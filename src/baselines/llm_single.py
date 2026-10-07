"""Langkah C — LLM tunggal zero-shot (§3.5 skripsi): satu panggilan per baris log, tanpa alat, dekode, atau few-shot.

Model dan parameter dari configs/llm.yaml (openai/gpt-4.1-nano-2025-04-14, temperature 0, seed 42, penyedia openai tanpa
fallback, structured output ketat). Prompt di llm_prompt.py; masukan pengguna hanya raw_log_masked di dalam
<log>...</log>. Metode hanya menerima kolom masukan test_sample_500.jsonl (src/common/inputs.py), tidak pernah label.

Setiap panggilan, termasuk percobaan ulang, dicatat ke results/llm_single_calls.jsonl: prompt (pesan system + user),
respons mentah, token masuk/keluar, latensi, dan biaya. Penanganan kegagalan:
- respons HTTP 200 yang gagal di-parse/divalidasi (bukan JSON, tidak sesuai skema, confidence di luar 0-1, terpotong)
  -> dicoba ulang sekali; bila tetap gagal, label PARSE_ERROR (dihitung salah oleh evaluasi);
- galat jaringan, HTTP 408/429/5xx -> dicoba ulang dengan jeda bertambah (galat layanan, bukan kegagalan parse); bila
  tetap gagal, atau HTTP 4xx lain, label API_ERROR (juga dihitung salah).
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

from ..common.inputs import SAMPLE_PATH, load_inputs
from ..common.runinfo import run_info, sha256_file
from ..data.config import ROOT
from ..llm.openrouter import OpenRouterClient, api_key, build_payload, load_llm_config, summarize
from .llm_prompt import CLASS_LABELS, OUTPUT_SCHEMA, SYSTEM_PROMPT, prompt_sha256, user_message

RESULTS_DIR = ROOT / "results"
CALLS_PATH = RESULTS_DIR / "llm_single_calls.jsonl"
PARSE_ATTEMPTS = 2  # percobaan pertama + satu ulangan (keputusan penulis)
SERVICE_RETRIES = 6  # galat jaringan/layanan: jeda 2, 4, 8, 16, 32, 64 detik
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


def parse_output(content: str | None) -> tuple[dict | None, str | None]:
    """(keluaran tervalidasi, None) atau (None, alasan gagal)."""
    if not content:
        return None, "konten kosong"
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        return None, f"bukan JSON: {exc.msg}"
    if not isinstance(data, dict) or set(data) != {"label", "confidence", "evidence", "explanation"}:
        return None, "kunci tidak sesuai skema"
    if data["label"] not in CLASS_LABELS:
        return None, f"label tidak dikenal: {data['label']!r}"
    conf = data["confidence"]
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1 or math.isnan(conf):
        return None, f"confidence tidak valid: {conf!r}"
    if not isinstance(data["evidence"], list) or not all(isinstance(e, str) for e in data["evidence"]):
        return None, "evidence bukan daftar string"
    if not isinstance(data["explanation"], str):
        return None, "explanation bukan string"
    return data, None


class Runner:
    def __init__(self, client: OpenRouterClient, config: dict, run_id: str, calls_file, sleep=time.sleep):
        self.client, self.config, self.run_id, self.calls_file, self.sleep = client, config, run_id, calls_file, sleep

    def _log(self, row_id: str, attempt: int, payload: dict, call: dict | None, summary: dict | None,
             outcome: str, detail: str | None) -> None:
        record = {
            "run_id": self.run_id, "id": row_id, "attempt": attempt,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "prompt": payload["messages"], "request": {k: v for k, v in payload.items() if k != "messages"},
            "http_status": call["http_status"] if call else None,
            "response_raw": call["response"] if call else None,
            "prompt_tokens": summary["prompt_tokens"] if summary else None,
            "completion_tokens": summary["completion_tokens"] if summary else None,
            "cached_tokens": summary["cached_tokens"] if summary else None,
            "latency_s": summary["latency_s"] if summary else None,
            "cost_usd": summary["cost_usd"] if summary else None,
            "served_model": summary["served_model"] if summary else None,
            "upstream_provider": summary["upstream_provider"] if summary else None,
            "system_fingerprint": summary["system_fingerprint"] if summary else None,
            "finish_reason": summary["finish_reason"] if summary else None,
            "outcome": outcome, "detail": detail,
        }
        self.calls_file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.calls_file.flush()

    def _call(self, row_id: str, attempt: int, payload: dict) -> tuple[dict, dict] | None:
        """Satu percobaan parse; galat layanan diulang dengan jeda. (respons, ringkasan), atau None bila tetap gagal."""
        for retry in range(SERVICE_RETRIES + 1):
            try:
                call = self.client.chat(payload)
            except httpx.TransportError as exc:
                self._log(row_id, attempt, payload, None, None, "network_error", type(exc).__name__)
            else:
                summary = summarize(call)
                status = call["http_status"]
                if status == 200 and not summary["error"]:
                    return call, summary
                outcome = "service_error" if status in RETRYABLE_STATUS or status == 200 else "http_error"
                self._log(row_id, attempt, payload, call, summary, outcome, json.dumps(summary["error"], ensure_ascii=False))
                if outcome == "http_error":
                    return None
            if retry < SERVICE_RETRIES:
                self.sleep(2 ** (retry + 1))
        return None

    def classify(self, row: dict) -> dict:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_message(row["raw_log_masked"])}]
        payload = build_payload(self.config, messages, OUTPUT_SCHEMA, "klasifikasi_log")
        totals = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "latency_s": 0.0}
        for attempt in range(1, PARSE_ATTEMPTS + 1):
            result = self._call(row["id"], attempt, payload)
            if result is None:
                return {"id": row["id"], "label": "API_ERROR", "status": "API_ERROR", "attempts": attempt, **totals}
            call, summary = result
            for key in totals:
                totals[key] += summary[key] or 0
            output, reason = parse_output(summary["content"])
            if summary["finish_reason"] not in (None, "stop") and output is not None:
                output, reason = None, f"finish_reason {summary['finish_reason']}"
            self._log(row["id"], attempt, payload, call, summary, "ok" if output else "parse_error", reason)
            if output is not None:
                return {"id": row["id"], **output, "status": "ok", "attempts": attempt, **totals}
        return {"id": row["id"], "label": "PARSE_ERROR", "status": "PARSE_ERROR", "attempts": PARSE_ATTEMPTS, **totals}


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def run(ids_path: Path | None = None, out_dir: Path = RESULTS_DIR, inputs_path: Path = SAMPLE_PATH) -> dict:
    config = load_llm_config()
    rows = load_inputs(inputs_path)
    if ids_path is not None:
        wanted = json.loads(ids_path.read_text(encoding="utf-8"))["ids"]
        by_id = {r["id"]: r for r in rows}
        rows = [by_id[i] for i in wanted]
    info = run_info(
        "llm_single", config["model"], model_version=config.get("model_version"),
        generation=config.get("generation"), provider_routing=config.get("provider_routing"),
        pricing_usd_per_1m_tokens=config.get("pricing_usd_per_1m_tokens"),
        prompt_sha256=prompt_sha256(), system_prompt=SYSTEM_PROMPT, output_schema=OUTPUT_SCHEMA,
        input_file=str(inputs_path.relative_to(ROOT)), input_sha256=sha256_file(inputs_path),
        ids_file=str(ids_path.relative_to(ROOT)) if ids_path else None, rows=len(rows),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    predictions = []
    with OpenRouterClient(api_key()) as client, open(CALLS_PATH, "a", encoding="utf-8") as calls:
        runner = Runner(client, config, info["run_id"], calls)
        for n, row in enumerate(rows, 1):
            result = {**runner.classify(row), "run_id": info["run_id"]}
            predictions.append(result)
            print(f"[llm_single] {n}/{len(rows)} {row['id']} -> {result['label']} ({result['status']}, "
                  f"{result['latency_s']:.2f} s)", flush=True)
    with open(out_dir / "llm_single.jsonl", "w", encoding="utf-8") as f:
        for result in predictions:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    ok = [p for p in predictions if p["status"] == "ok"]
    info["totals"] = {
        "status": {s: sum(p["status"] == s for p in predictions) for s in ("ok", "PARSE_ERROR", "API_ERROR")},
        "retried_rows": sum(p["attempts"] > 1 for p in predictions),
        "prompt_tokens_mean": sum(p["prompt_tokens"] for p in predictions) / len(predictions),
        "completion_tokens_mean": sum(p["completion_tokens"] for p in predictions) / len(predictions),
        "cost_usd_total": sum(p["cost_usd"] for p in predictions),
        "cost_usd_per_1000_rows": 1000 * sum(p["cost_usd"] for p in predictions) / len(predictions),
        "latency_s_median": _percentile([p["latency_s"] for p in ok], 0.5),
        "latency_s_p95": _percentile([p["latency_s"] for p in ok], 0.95),
    }
    (out_dir / "llm_single.run.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LLM tunggal zero-shot")
    parser.add_argument("--ids", type=Path, help="berkas JSON {'ids': [...]} (mis. results/pilot/pilot_ids.json)")
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)
    info = run(args.ids.resolve() if args.ids else None, args.out_dir.resolve())
    t = info["totals"]
    print(f"[llm_single] selesai {info['rows']} baris, status {t['status']}, biaya ${t['cost_usd_total']:.6f} "
          f"(${t['cost_usd_per_1000_rows']:.4f} per 1.000 baris), latensi median {t['latency_s_median']:.2f} s, "
          f"run {info['run_id']} (dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
