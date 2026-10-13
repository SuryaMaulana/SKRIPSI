"""Ablasi revisi jurnal — LLM tunggal + loop verifikasi deterministik (manuskrip §2.5; keputusan penulis 2026-10-13).

Tujuan: memisahkan sumbangan loop verifikasi dari sumbangan orkestrasi deep agent. Spesifikasi:
- Panggilan pertama identik dengan LLM tunggal resmi (llm_single): system prompt llm_prompt.SYSTEM_PROMPT (hash sama),
  pesan pengguna <log>raw_log_masked</log>, parameter generasi, routing, dan skema keluaran sama.
- Verifikasi identik dengan sub-agen Verifikasi deep agent: schema_check (llm_single.parse_output atas keluaran
  klasifikasi) lalu evidence_exists (substring literal pada raw_log_masked mentah atau hasil decode,
  src/common/evidence.py) untuk setiap item; putusan dari src/agent/graph.deterministic_verdict.
- Bila ditolak, model dipanggil lagi dengan alasan penolakan memakai bagian MASUKAN prompt Klasifikasi TANPA keluaran
  alat: system prompt = prompt LLM tunggal + MASUKAN_ABLASI (bagian MASUKAN deep agent tanpa <parsed>, <decoded>,
  <pattern_hits>, <scanner_indicators>; kalimat evidence penulis tetap sama persis), pesan pengguna = <log>...</log>
  ditambah <umpan_balik_verifikasi> berisi alasan penolakan terakhir, dirakit seperti prompts.classifier_input.
- Paling banyak MAX_VERIFICATION_ROUNDS (2) putaran verifikasi, sama dengan deep agent; setelah itu klasifikasi valid
  terakhir dipakai dengan status verification_failed. Tidak ada orkestrator, sub-agen, atau alat.
- Kebijakan ulang parse/TRUNCATED/kegagalan layanan, log panggilan, dan --resume sama dengan LLM tunggal (Runner).
  Log panggilan memuat putaran_verifikasi (berbasis 0, seperti deep agent); bila run berhenti di tengah baris,
  rekaman jenis=galat_api menandai panggilan baris itu sebagai dibatalkan (baris diulang penuh saat --resume).
Status per baris sama dengan deep agent: ok, verification_failed, PARSE_ERROR (tidak ada klasifikasi valid). Latensi
per baris = jumlah latensi panggilan (konvensi LLM tunggal; jeda ulang tidak dihitung); waktu dinding di wall_s.
Jalankan: make run-cv R=1|2|3 atau make llm_single_verified (3 run berurutan).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ..agent.context import MAX_VERIFICATION_ROUNDS
from ..agent.graph import deterministic_verdict
from ..agent.prompts import MASUKAN_SECTION, _section
from ..common.evidence import evidence_exists
from ..common.inputs import SAMPLE_PATH, method_rows
from ..common.runinfo import check_resume, git_state, ids_sha256, repo_path, run_info, sha256_file
from ..llm.klasifikasi import SCHEMA_SECTION, sha256
from ..llm.openrouter import OpenRouterClient, api_key, build_payload, is_truncated, load_llm_config
from .llm_prompt import OUTPUT_SCHEMA, SYSTEM_PROMPT, prompt_sha256, user_message
from .llm_single import PARSE_ATTEMPTS, RESULTS_DIR, Runner, RunAborted, _percentile, parse_output

METHOD = "llm_single_verified"
CALLS_PATH = RESULTS_DIR / f"{METHOD}_calls.jsonl"
STATUSES = ("ok", "verification_failed", "PARSE_ERROR")
TOOL_TAGS = ("parsed", "decoded", "pattern_hits", "scanner_indicators")

# Bagian MASUKAN deep agent tanpa keluaran alat: baris pertama tanpa tag alat, kalimat evidence penulis (K3) apa adanya.
_E_INPUT_LINE, EVIDENCE_SENTENCE = MASUKAN_SECTION.splitlines()[1:3]
assert EVIDENCE_SENTENCE.startswith("Evidence ditulis persis seperti di baris log")
MASUKAN_ABLASI = "\n".join([
    "MASUKAN",
    re.sub(r" <(" + "|".join(TOOL_TAGS) + r")>.*?</\1>", "", _E_INPUT_LINE),
    EVIDENCE_SENTENCE,
])
assert not any(f"<{tag}>" in MASUKAN_ABLASI for tag in TOOL_TAGS) and "<umpan_balik_verifikasi>" in MASUKAN_ABLASI
assert SYSTEM_PROMPT.count(SCHEMA_SECTION) == 1
RETRY_PROMPT = SYSTEM_PROMPT.replace(SCHEMA_SECTION, MASUKAN_ABLASI + "\n\n" + SCHEMA_SECTION)


def first_messages(raw_log_masked: str) -> list[dict]:
    """Pesan panggilan pertama: sama persis dengan LLM tunggal resmi."""
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_message(raw_log_masked)}]


def retry_messages(raw_log_masked: str, reasons: list[str]) -> list[dict]:
    """Pesan panggilan ulang: MASUKAN tanpa keluaran alat, dengan alasan penolakan terakhir (seperti classifier_input)."""
    reasons = [r.encode("utf-8", "replace").decode("utf-8") for r in reasons]  # surrogate tunggal dari teks model
    user = "\n".join([f"<log>{raw_log_masked}</log>", _section("umpan_balik_verifikasi", reasons)])
    return [{"role": "system", "content": RETRY_PROMPT}, {"role": "user", "content": user}]


def verify(classification: dict, raw_log_masked: str) -> dict:
    """Putusan Verifikasi deep agent untuk satu klasifikasi: schema_check, lalu evidence_exists per item bila skema valid."""
    if "_parse_error" in classification:
        schema = {"valid": False, "alasan": classification["_parse_error"]}
    else:
        output, reason = parse_output(json.dumps(classification))
        schema = {"valid": output is not None, "alasan": reason}
    missing = [item for item in classification["evidence"] if not evidence_exists(item, raw_log_masked)] \
        if schema["valid"] else []
    return deterministic_verdict(schema, missing)


class VerifiedRunner(Runner):
    """Runner LLM tunggal dengan loop verifikasi. Setiap rekaman log panggilan memuat putaran_verifikasi."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._round = 1

    def _log(self, row_id: str, attempt: int, payload: dict, call: dict | None, summary: dict | None,
             outcome: str, detail: str | None) -> None:
        if summary:
            for key in ("prompt_tokens", "completion_tokens", "cost_usd", "latency_s"):
                self._spent[key] += summary[key] or 0
        record = {
            "run_id": self.run_id, "id": row_id, "attempt": attempt,
            "putaran_verifikasi": self._round - 1,  # seperti log deep agent: putaran verifikasi yang sudah selesai
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

    def _classify(self, row_id: str, messages: list[dict]) -> tuple[dict | None, str | None, int, list[int]]:
        """Satu langkah klasifikasi dengan kebijakan percobaan LLM tunggal: (keluaran | None, alasan, percobaan, percobaan
        yang terpotong). Alasan TRUNCATED memakai teks deep agent ("TRUNCATED: finish_reason length"), karena alasan itu
        masuk ke umpan balik verifikasi; rincian token tetap di kolom detail log panggilan (format LLM tunggal)."""
        payload = build_payload(self.config, messages, OUTPUT_SCHEMA, "klasifikasi_log")
        truncated, reason = [], "tidak ada percobaan"
        for attempt in range(1, PARSE_ATTEMPTS + 1):
            call, summary = self._call(row_id, attempt, payload)
            output, reason = parse_output(summary["content"])
            detail = reason
            cut = is_truncated(summary["finish_reason"], summary.get("native_finish_reason"), summary["completion_tokens"],
                               payload.get("max_tokens"))
            if cut:
                truncated.append(attempt)
                output, reason = None, "TRUNCATED: finish_reason length"
                detail = (f"TRUNCATED: finish_reason {summary['finish_reason']}, "
                          f"{summary['completion_tokens']} token (max_tokens {payload.get('max_tokens')})")
            elif output is not None and summary["finish_reason"] not in (None, "stop"):
                output, reason = None, f"finish_reason {summary['finish_reason']}"
                detail = reason
            if summary["refusal"]:
                output, reason = None, f"penolakan: {str(summary['refusal'])[:200]}"
                detail = reason
            outcome = "ok" if output else ("TRUNCATED" if cut else "parse_error")
            self._log(row_id, attempt, payload, call, summary, outcome, detail)
            if output is not None:
                return output, None, attempt, truncated
        return None, reason, PARSE_ATTEMPTS, truncated

    def classify(self, row: dict) -> dict:
        raw = row["raw_log_masked"]
        self._spent = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "latency_s": 0.0}
        start = time.perf_counter()
        classifications, verdicts, truncations, calls = [], [], [], 0
        messages = first_messages(raw)
        for round_ in range(1, MAX_VERIFICATION_ROUNDS + 1):
            self._round = round_
            output, reason, attempts, truncated = self._classify(row["id"], messages)
            calls += attempts
            truncations += [{"subagen": "klasifikasi", "percobaan": a, "putaran": round_ - 1} for a in truncated]
            classifications.append(output if output is not None else {"_parse_error": reason})
            verdict = {**verify(classifications[-1], raw), "putaran": round_, "klasifikasi_ke": len(classifications)}
            verdicts.append(verdict)
            if verdict["lolos"]:
                break
            messages = retry_messages(raw, verdict["alasan"])
        return assemble(row["id"], classifications, verdicts, calls, truncations,
                        {**self._spent, "wall_s": time.perf_counter() - start})


def assemble(row_id: str, classifications: list[dict], verdicts: list[dict], calls: int, truncations: list[dict],
             spent: dict) -> dict:
    """Baris keluaran: aturan label dan status sama dengan deep agent (run.assemble)."""
    valid = [k for k, c in enumerate(classifications, 1) if "_parse_error" not in c]
    base = {"id": row_id, "klasifikasi_dipanggil": len(classifications),
            "riwayat_label": [c.get("label", "PARSE_ERROR") for c in classifications],
            "riwayat_klasifikasi": classifications,
            "verifikasi": {"putaran": len(verdicts), "penolakan": sum(not v["lolos"] for v in verdicts),
                           "verification_failed": False,
                           "putusan": [{k: v.get(k) for k in ("putaran", "klasifikasi_ke", "lolos", "skema_valid",
                                                               "evidence_hilang", "alasan")} for v in verdicts]},
            "llm_calls": calls, "attempts": calls, "truncated_calls": len(truncations), "truncations": truncations,
            **spent}
    if not valid:
        return {**base, "label": "PARSE_ERROR", "status": "PARSE_ERROR",
                "detail": classifications[-1]["_parse_error"] if classifications else "tidak ada klasifikasi"}
    chosen = valid[-1]
    chosen_verdicts = [v for v in verdicts if v["klasifikasi_ke"] == chosen]
    status = "ok" if chosen_verdicts[-1]["lolos"] else "verification_failed"
    base["verifikasi"]["verification_failed"] = status == "verification_failed"
    return {**base, **classifications[chosen - 1], "status": status, "klasifikasi_dipakai": chosen}


def totals(predictions: list[dict]) -> dict:
    n = len(predictions) or 1
    return {
        "status": {s: sum(p["status"] == s for p in predictions) for s in STATUSES},
        "rows_with_rejection": sum(p["verifikasi"]["penolakan"] > 0 for p in predictions),
        "verification_rounds_mean": sum(p["verifikasi"]["putaran"] for p in predictions) / n,
        "llm_calls_mean": sum(p["llm_calls"] for p in predictions) / n,
        "truncated_calls": sum(p["truncated_calls"] for p in predictions),
        "prompt_tokens_mean": sum(p["prompt_tokens"] for p in predictions) / n,
        "completion_tokens_mean": sum(p["completion_tokens"] for p in predictions) / n,
        "cost_usd_total": sum(p["cost_usd"] for p in predictions),
        "cost_usd_per_1000_rows": 1000 * sum(p["cost_usd"] for p in predictions) / n,
        "latency_s_median": _percentile([p["latency_s"] for p in predictions], 0.5),
        "latency_s_p95": _percentile([p["latency_s"] for p in predictions], 0.95),
    }


def run(ids_path: Path | None = None, out_dir: Path = RESULTS_DIR, inputs_path: Path = SAMPLE_PATH,
        resume: bool = False, client: OpenRouterClient | None = None, calls_path: Path = CALLS_PATH,
        split: str | None = None, name: str = METHOD) -> dict:
    """Jalankan (atau lanjutkan) satu run; berkas keluaran dan --resume seperti llm_single.run."""
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
            METHOD, config["model"], run_name=name, model_version=config.get("model_version"),
            generation=config.get("generation"), provider_routing=config.get("provider_routing"),
            pricing_usd_per_1m_tokens=config.get("pricing_usd_per_1m_tokens"),
            prompt_sha256=prompt_sha256(), system_prompt=SYSTEM_PROMPT,
            retry_prompt_sha256=sha256(RETRY_PROMPT), retry_system_prompt=RETRY_PROMPT,
            max_verification_rounds=MAX_VERIFICATION_ROUNDS,
            verifier="schema_check (llm_single.parse_output) + evidence_exists (src/common/evidence.py), "
                     "src/agent/graph.deterministic_verdict",
            output_schema=OUTPUT_SCHEMA,
            input_file=repo_path(inputs_path), input_sha256=sha256_file(inputs_path),
            ids_file=repo_path(ids_path), rows=len(rows), row_ids_sha256=ids_sha256([r["id"] for r in rows]),
            output_name=name, calls_file=repo_path(calls_path),
        )
    if info["prompt_sha256"] != prompt_sha256() or info["retry_prompt_sha256"] != sha256(RETRY_PROMPT):
        raise RuntimeError("prompt berubah sejak run ini dimulai; mulai run baru")
    if info.get("max_verification_rounds") != MAX_VERIFICATION_ROUNDS:
        raise RuntimeError("batas putaran verifikasi berubah sejak run ini dimulai; mulai run baru")
    if resume:
        check_resume(info, {"input_file": repo_path(inputs_path), "ids_file": repo_path(ids_path), "rows": len(rows),
                            "row_ids_sha256": ids_sha256([r["id"] for r in rows]), "calls_file": repo_path(calls_path),
                            "output_name": name, "model": config["model"], "generation": config.get("generation"),
                            "provider_routing": config.get("provider_routing")})
    info_path.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    finished = {p["id"] for p in done}
    with (client or OpenRouterClient(api_key())) as client, open(calls_path, "a", encoding="utf-8") as calls, \
            open(partial, "a", encoding="utf-8") as out:
        runner = VerifiedRunner(client, config, info["run_id"], calls)
        todo = [r for r in rows if r["id"] not in finished]
        for n, row in enumerate(todo, len(finished) + 1):
            try:
                result = {**runner.classify(row), "run_id": info["run_id"]}
            except BaseException as exc:  # baris diulang penuh setelah --resume; panggilannya ditandai dibatalkan
                calls.write(json.dumps({"run_id": info["run_id"], "id": row["id"], "jenis": "galat_api",
                                        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                                        "galat": f"{type(exc).__name__}: {str(exc)[:300]}"}, ensure_ascii=True) + "\n")
                calls.flush()
                raise
            out.write(json.dumps(result, ensure_ascii=True) + "\n")
            out.flush()
            done.append(result)
            print(f"[{METHOD}] {n}/{len(rows)} {row['id']} -> {result['label']} ({result['status']}, "
                  f"putaran {result['verifikasi']['putaran']}, {result['latency_s']:.2f} s)", flush=True)
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
    parser = argparse.ArgumentParser(description="Ablasi: LLM tunggal + loop verifikasi deterministik")
    parser.add_argument("--ids", type=Path, help="berkas JSON {'ids': [...]}")
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--resume", action="store_true", help="lanjutkan run yang terhenti (<name>.partial.jsonl)")
    parser.add_argument("--split", help="baris srbh_<split>.parquet (mis. val) sebagai pengganti test_sample_500")
    parser.add_argument("--name", default=METHOD, help="nama berkas keluaran (mis. llm_single_verified_r1)")
    parser.add_argument("--calls", type=Path, default=CALLS_PATH, help="log panggilan")
    args = parser.parse_args(argv)
    try:
        info = run(args.ids.resolve() if args.ids else None, args.out_dir.resolve(), resume=args.resume,
                   calls_path=args.calls.resolve(), split=args.split, name=args.name)
    except RunAborted as exc:
        print(f"[{METHOD}] DIHENTIKAN: {exc}", file=sys.stderr)
        return 2
    t = info["totals"]
    median = "—" if t["latency_s_median"] is None else f"{t['latency_s_median']:.2f} s"
    print(f"[{METHOD}] selesai {info['rows']} baris, status {t['status']}, putaran rerata "
          f"{t['verification_rounds_mean']:.2f}, biaya ${t['cost_usd_total']:.6f} (${t['cost_usd_per_1000_rows']:.4f} per "
          f"1.000 baris), latensi median {median}, run {info['run_id']} (dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
