"""Langkah C — LLM tunggal zero-shot (§3.5 skripsi): satu panggilan per baris log, tanpa alat, dekode, atau few-shot.

Model dan parameter dari configs/llm.yaml (openai/gpt-4.1-nano-2025-04-14, temperature 0, seed 42, penyedia openai tanpa
fallback, structured output ketat). Prompt di llm_prompt.py; masukan pengguna hanya raw_log_masked di dalam
<log>...</log>. Metode hanya menerima kolom masukan test_sample_500.jsonl (src/common/inputs.py), tidak pernah label.

Setiap panggilan, termasuk percobaan ulang, dicatat ke results/llm_single_calls.jsonl: prompt (pesan system + user),
respons mentah, token masuk/keluar, latensi, dan biaya. Penanganan kegagalan:
- jawaban model yang gagal di-parse/divalidasi (bukan JSON, tidak sesuai skema, confidence di luar 0-1, terpotong karena
  panjang, atau penolakan) -> dicoba ulang sekali; bila tetap gagal, label PARSE_ERROR (dihitung salah oleh evaluasi,
  keputusan penulis);
- kegagalan layanan (galat jaringan, HTTP 408/429/5xx, atau HTTP 200 yang berisi galat penyedia, badan bukan JSON, atau
  konten kosong) -> dicoba ulang dengan jeda 2, 4, ..., 64 detik; ini bukan kegagalan parse;
- kegagalan layanan yang menetap, atau HTTP 4xx lain (401/402/403: kunci, saldo, moderasi) -> run DIHENTIKAN tanpa
  menilai baris itu (keputusan asisten: galat API bukan kesalahan model). Prediksi yang sudah selesai disimpan di
  <out>/llm_single.partial.jsonl dan run dapat dilanjutkan dengan --resume.
Token, biaya, dan latensi per baris = jumlah semua panggilan baris itu (jeda antarpercobaan tidak dihitung).
Panggilan berurutan (satu per satu) agar latensi per baris tidak dipengaruhi antrean paralel.
Jalankan: make llm-single-pilot (30 baris: 5 per kelas) | make llm-single (500 baris)
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ..common.inputs import SAMPLE_PATH, method_rows
from ..common.runinfo import check_resume, git_state, ids_sha256, repo_path, run_info, sha256_file
from ..data.config import ROOT
from ..llm.openrouter import OpenRouterClient, api_key, build_payload, load_llm_config, summarize
from .llm_prompt import CLASS_LABELS, OUTPUT_SCHEMA, SYSTEM_PROMPT, prompt_sha256, user_message

RESULTS_DIR = ROOT / "results"
CALLS_PATH = RESULTS_DIR / "llm_single_calls.jsonl"
PARSE_ATTEMPTS = 2  # percobaan pertama + satu ulangan (keputusan penulis)
SERVICE_RETRIES = 6  # kegagalan layanan: jeda 2, 4, 8, 16, 32, 64 detik


class RunAborted(RuntimeError):
    """Run dihentikan karena kegagalan API yang bukan kesalahan model; dapat dilanjutkan dengan --resume."""


def parse_output(content) -> tuple[dict | None, str | None]:
    """(keluaran tervalidasi, None) atau (None, alasan gagal). Tidak pernah melempar galat."""
    if not isinstance(content, str) or not content:
        return None, f"konten bukan string tidak kosong: {type(content).__name__}"
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        return None, f"bukan JSON: {exc.msg}"
    if not isinstance(data, dict) or set(data) != {"label", "confidence", "evidence", "explanation"}:
        return None, "kunci tidak sesuai skema"
    if data["label"] not in CLASS_LABELS:
        return None, f"label tidak dikenal: {data['label']!r}"
    conf = data["confidence"]
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or math.isnan(conf) or not 0 <= conf <= 1:
        return None, f"confidence tidak valid: {conf!r}"
    if not isinstance(data["evidence"], list) or not all(isinstance(e, str) for e in data["evidence"]):
        return None, "evidence bukan daftar string"
    if not isinstance(data["explanation"], str):
        return None, "explanation bukan string"
    return data, None


def service_failure(summary: dict) -> str | None:
    """Alasan bila respons HTTP 200 sebenarnya kegagalan layanan (bukan jawaban model), selain itu None."""
    if summary["error"]:
        return f"galat penyedia: {json.dumps(summary['error'], ensure_ascii=True)[:300]}"
    if summary["choice_error"] or summary["finish_reason"] == "error":
        return f"galat generasi: {json.dumps(summary['choice_error'], ensure_ascii=True)[:300]}"
    if summary["non_json_body"]:
        return "badan respons bukan JSON"
    if summary["content"] in (None, "") and not summary["refusal"]:
        return "konten kosong tanpa penolakan"
    return None


class Runner:
    def __init__(self, client: OpenRouterClient, config: dict, run_id: str, calls_file, sleep=time.sleep):
        self.client, self.config, self.run_id, self.calls_file, self.sleep = client, config, run_id, calls_file, sleep
        self._spent = {}

    def _log(self, row_id: str, attempt: int, payload: dict, call: dict | None, summary: dict | None,
             outcome: str, detail: str | None) -> None:
        if summary:  # semua panggilan yang mengembalikan usage ikut dijumlahkan ke baris
            for key in ("prompt_tokens", "completion_tokens", "cost_usd", "latency_s"):
                self._spent[key] += summary[key] or 0
        record = {
            "run_id": self.run_id, "id": row_id, "attempt": attempt,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "prompt": payload["messages"], "request": {k: v for k, v in payload.items() if k != "messages"},
            "http_status": call["http_status"] if call else None,
            "response_raw": call["response"] if call else None,
            **{k: summary[k] if summary else None for k in (
                "prompt_tokens", "completion_tokens", "cached_tokens", "latency_s", "cost_usd", "served_model",
                "upstream_provider", "system_fingerprint", "finish_reason")},
            "outcome": outcome, "detail": detail,
        }
        self.calls_file.write(json.dumps(record, ensure_ascii=True) + "\n")
        self.calls_file.flush()

    def _call(self, row_id: str, attempt: int, payload: dict) -> tuple[dict, dict]:
        """Satu percobaan parse. Kegagalan layanan diulang dengan jeda; bila menetap atau HTTP 4xx lain -> RunAborted."""
        for retry in range(SERVICE_RETRIES + 1):
            try:
                call = self.client.chat(payload)
            except httpx.RequestError as exc:
                self._log(row_id, attempt, payload, None, None, "network_error", type(exc).__name__)
            else:
                summary = summarize(call)
                status = call["http_status"]
                if status == 200:
                    reason = service_failure(summary)
                    if reason is None:
                        return call, summary
                    self._log(row_id, attempt, payload, call, summary, "service_error", reason)
                elif status in (408, 429) or status >= 500:
                    self._log(row_id, attempt, payload, call, summary, "service_error", f"HTTP {status}")
                else:
                    detail = json.dumps(summary["error"], ensure_ascii=True)[:300]
                    self._log(row_id, attempt, payload, call, summary, "http_error", f"HTTP {status}: {detail}")
                    raise RunAborted(f"{row_id}: HTTP {status} ({detail}); run dihentikan, jalankan ulang perintah "
                                     f"yang sama dengan --resume")
            if retry < SERVICE_RETRIES:
                self.sleep(2 ** (retry + 1))
        raise RunAborted(f"{row_id}: kegagalan layanan menetap setelah {SERVICE_RETRIES} ulangan; jalankan ulang perintah "
                         f"yang sama dengan --resume")

    def classify(self, row: dict) -> dict:
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message(row["raw_log_masked"])}]
        payload = build_payload(self.config, messages, OUTPUT_SCHEMA, "klasifikasi_log")
        self._spent = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "latency_s": 0.0}
        truncated = 0
        for attempt in range(1, PARSE_ATTEMPTS + 1):
            call, summary = self._call(row["id"], attempt, payload)
            output, reason = parse_output(summary["content"])
            if summary["finish_reason"] == "length":  # terpotong di batas max_tokens (keputusan penulis 2026-10-08)
                truncated += 1
                output, reason = None, f"TRUNCATED: finish_reason length (max_tokens {payload.get('max_tokens')})"
            elif output is not None and summary["finish_reason"] not in (None, "stop"):
                output, reason = None, f"finish_reason {summary['finish_reason']}"
            if summary["refusal"]:
                output, reason = None, f"penolakan: {str(summary['refusal'])[:200]}"
            outcome = "ok" if output else ("TRUNCATED" if summary["finish_reason"] == "length" else "parse_error")
            self._log(row["id"], attempt, payload, call, summary, outcome, reason)
            if output is not None:
                return {"id": row["id"], **output, "status": "ok", "attempts": attempt, "truncated_calls": truncated,
                        **self._spent}
        return {"id": row["id"], "label": "PARSE_ERROR", "status": "PARSE_ERROR", "attempts": PARSE_ATTEMPTS,
                "truncated_calls": truncated, "detail": reason, **self._spent}


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def totals(predictions: list[dict]) -> dict:
    n = len(predictions) or 1
    return {
        "status": {s: sum(p["status"] == s for p in predictions) for s in ("ok", "PARSE_ERROR")},
        "retried_rows": sum(p["attempts"] > 1 for p in predictions),
        "prompt_tokens_mean": sum(p["prompt_tokens"] for p in predictions) / n,
        "completion_tokens_mean": sum(p["completion_tokens"] for p in predictions) / n,
        "cost_usd_total": sum(p["cost_usd"] for p in predictions),
        "cost_usd_per_1000_rows": 1000 * sum(p["cost_usd"] for p in predictions) / n,
        "latency_s_median": _percentile([p["latency_s"] for p in predictions], 0.5),
        "latency_s_p95": _percentile([p["latency_s"] for p in predictions], 0.95),
    }


def run(ids_path: Path | None = None, out_dir: Path = RESULTS_DIR, inputs_path: Path = SAMPLE_PATH,
        resume: bool = False, client: OpenRouterClient | None = None, calls_path: Path = CALLS_PATH,
        split: str | None = None, name: str = "llm_single") -> dict:
    """Jalankan (atau lanjutkan) satu run. Prediksi ditulis bertahap ke <name>.partial.jsonl; baru setelah semua baris
    selesai berkas itu menjadi <name>.jsonl beserta <name>.run.json. split: baris srbh_<split>.parquet (mis. val) sebagai
    pengganti test_sample_500; name: nama berkas keluaran (mis. llm_single_r1 untuk replikasi)."""
    config = load_llm_config()
    rows, inputs_path = method_rows(inputs_path, split)
    if ids_path is not None:
        wanted = json.loads(ids_path.read_text(encoding="utf-8"))["ids"]
        by_id = {r["id"]: r for r in rows}
        rows = [by_id[i] for i in wanted]
    out_dir.mkdir(parents=True, exist_ok=True)
    partial, info_path = out_dir / f"{name}.partial.jsonl", out_dir / f"{name}.partial.run.json"
    done: list[dict] = []
    if resume:
        if not partial.exists():
            raise FileNotFoundError(f"tidak ada run setengah jadi di {partial}")
        info = json.loads(info_path.read_text(encoding="utf-8"))
        done = [json.loads(line) for line in partial.read_text(encoding="utf-8").splitlines() if line.strip()]
        info.setdefault("resumed", []).append({"date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                               **git_state(), "rows_done": len(done)})
    else:
        if partial.exists():
            raise FileExistsError(f"{partial} sudah ada: jalankan ulang perintah yang sama dengan --resume")
        info = run_info(
            "llm_single", config["model"], run_name=name, model_version=config.get("model_version"),
            generation=config.get("generation"), provider_routing=config.get("provider_routing"),
            pricing_usd_per_1m_tokens=config.get("pricing_usd_per_1m_tokens"),
            prompt_sha256=prompt_sha256(), system_prompt=SYSTEM_PROMPT, output_schema=OUTPUT_SCHEMA,
            input_file=repo_path(inputs_path), input_sha256=sha256_file(inputs_path),
            ids_file=repo_path(ids_path), rows=len(rows), row_ids_sha256=ids_sha256([r["id"] for r in rows]),
            output_name=name, calls_file=repo_path(calls_path),
        )
    if info["prompt_sha256"] != prompt_sha256():
        raise RuntimeError("prompt berubah sejak run ini dimulai; mulai run baru")
    if resume:
        check_resume(info, {"input_file": repo_path(inputs_path), "ids_file": repo_path(ids_path), "rows": len(rows),
                            "row_ids_sha256": ids_sha256([r["id"] for r in rows]), "calls_file": repo_path(calls_path),
                            "output_name": name})
    info_path.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    finished = {p["id"] for p in done}
    with (client or OpenRouterClient(api_key())) as client, open(calls_path, "a", encoding="utf-8") as calls, \
            open(partial, "a", encoding="utf-8") as out:
        runner = Runner(client, config, info["run_id"], calls)
        todo = [r for r in rows if r["id"] not in finished]
        for n, row in enumerate(todo, len(finished) + 1):
            result = {**runner.classify(row), "run_id": info["run_id"]}
            out.write(json.dumps(result, ensure_ascii=True) + "\n")
            out.flush()
            done.append(result)
            print(f"[llm_single] {n}/{len(rows)} {row['id']} -> {result['label']} ({result['status']}, "
                  f"{result['latency_s']:.2f} s)", flush=True)
    order = {r["id"]: k for k, r in enumerate(rows)}
    done.sort(key=lambda p: order[p["id"]])
    info["totals"] = totals(done)
    (out_dir / f"{name}.jsonl").write_text("".join(json.dumps(p, ensure_ascii=True) + "\n" for p in done),
                                           encoding="utf-8")
    (out_dir / f"{name}.run.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    partial.unlink()
    info_path.unlink()
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM tunggal zero-shot")
    parser.add_argument("--ids", type=Path, help="berkas JSON {'ids': [...]} (mis. results/pilot/pilot_ids.json)")
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--resume", action="store_true", help="lanjutkan run yang terhenti (<name>.partial.jsonl)")
    parser.add_argument("--split", help="baris srbh_<split>.parquet (mis. val) sebagai pengganti test_sample_500")
    parser.add_argument("--name", default="llm_single", help="nama berkas keluaran (mis. llm_single_r1)")
    parser.add_argument("--calls", type=Path, default=CALLS_PATH, help="log panggilan (bawaan results/llm_single_calls.jsonl)")
    args = parser.parse_args(argv)
    try:
        info = run(args.ids.resolve() if args.ids else None, args.out_dir.resolve(), resume=args.resume,
                   calls_path=args.calls.resolve(), split=args.split, name=args.name)
    except RunAborted as exc:
        print(f"[llm_single] DIHENTIKAN: {exc}", file=sys.stderr)
        return 2
    t = info["totals"]
    median = "—" if t["latency_s_median"] is None else f"{t['latency_s_median']:.2f} s"
    print(f"[llm_single] selesai {info['rows']} baris, status {t['status']}, biaya ${t['cost_usd_total']:.6f} "
          f"(${t['cost_usd_per_1000_rows']:.4f} per 1.000 baris), latensi median {median}, run {info['run_id']} "
          f"(dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
