"""Ablasi (tanggapan reviewer): LLM tunggal + konteks alat deterministik, TANPA orkestrasi dan TANPA verifier loop.

Satu panggilan LLM per baris, model dan parameter sama dengan llm_single (configs/llm.yaml: openai/gpt-4.1-nano,
temperature 0, seed 42, structured output ketat). Bedanya hanya prompt: alih-alih <log>...</log> saja, pesan diberi
keluaran alat deterministik yang sama seperti yang diterima sub-agen Klasifikasi deep agent — kolom hasil urai, payload
terdekode (URL + entity HTML), pola OWASP CRS yang cocok, dan indikator pemindai. Keluaran alat dihasilkan oleh ALAT YANG
SAMA PERSIS seperti di deep agent (src/agent/tools.py), yang membaca HANYA baris log (bukan label/template_key).

System prompt = CLASSIFIER_PROMPT (prompt LLM tunggal + bagian MASUKAN, src/agent/prompts.py); pesan pengguna =
classifier_input(ctx), format tag identik dengan sub-agen Klasifikasi. Tidak ada planner, sub-agen, task, maupun putaran
verifikasi: hanya satu panggilan klasifikasi.

Perbedaan dengan deep agent yang disengaja agar deterministik: di deep agent, bagian mana yang di-decode dipilih LLM
sub-agen Payload (tidak deterministik), sedangkan di sini keempat bagian (path, query, referer, user_agent) selalu
di-decode. Ini memberi konteks alat maksimal dan tetap, sehingga memisahkan sumbangan "konteks alat" dari "orkestrasi"
dalam dekomposisi selisih akurasi.

Penanganan kegagalan, pencatatan panggilan per baris, totals, dan --resume sama dengan llm_single.
Jalankan: make llm-single-toolctx (500 baris) | --name llm_single_toolctx_r1 untuk replikasi.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ..agent import tools as agent_tools
from ..agent.context import RowContext, set_current
from ..agent.prompts import CLASSIFIER_PROMPT, classifier_input
from ..common.inputs import SAMPLE_PATH, method_rows
from ..common.runinfo import check_resume, git_state, ids_sha256, repo_path, run_info, sha256_file
from ..data.config import ROOT
from ..llm.openrouter import OpenRouterClient, api_key, build_payload, is_truncated, load_llm_config
from .llm_prompt import OUTPUT_SCHEMA
from .llm_single import PARSE_ATTEMPTS, RESULTS_DIR, RunAborted, Runner, parse_output, totals

CALLS_PATH = RESULTS_DIR / "llm_single_toolctx_calls.jsonl"
DECODE_SECTIONS = ("path", "query", "referer", "user_agent")  # keempat bagian selalu di-decode (deterministik)


def prompt_sha256() -> str:
    """SHA-256 prompt system ablation (CLASSIFIER_PROMPT). Guard: prompt tak boleh berubah selama satu run."""
    return hashlib.sha256(CLASSIFIER_PROMPT.encode("utf-8")).hexdigest()


def _run_tool(t, **kwargs):
    """Jalankan satu alat deep agent (StructuredTool) demi efek sampingnya: menulis hasil ke context.current()."""
    fn = getattr(t, "func", None)
    return fn(**kwargs) if callable(fn) else t.invoke(kwargs)


def build_tool_context(run_id: str, row: dict) -> RowContext:
    """Rakit konteks baris dengan menjalankan alat deterministik yang sama seperti deep agent (urut, satu baris).

    Hanya baris log yang dibaca; keempat bagian di-decode agar konteks tetap dan tak bergantung pilihan LLM."""
    ctx = RowContext(run_id=run_id, row_id=row["id"], raw_log_masked=row["raw_log_masked"])
    set_current(ctx)
    try:
        _run_tool(agent_tools.parse_log_line)
        _run_tool(agent_tools.pattern_match)
        _run_tool(agent_tools.scanner_indicators)
        for bagian in DECODE_SECTIONS:
            _run_tool(agent_tools.url_decode_recursive, bagian=bagian)
            _run_tool(agent_tools.html_decode, bagian=bagian)
    finally:
        set_current(None)
    return ctx


class ToolCtxRunner(Runner):
    """Seperti llm_single.Runner, tetapi prompt diberi konteks alat; tetap satu panggilan tanpa verifier loop."""

    def classify(self, row: dict) -> dict:
        ctx = build_tool_context(self.run_id, row)
        messages = [{"role": "system", "content": CLASSIFIER_PROMPT},
                    {"role": "user", "content": classifier_input(ctx)}]
        payload = build_payload(self.config, messages, OUTPUT_SCHEMA, "klasifikasi_log")
        self._spent = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "latency_s": 0.0}
        truncated = 0
        reason = None
        for attempt in range(1, PARSE_ATTEMPTS + 1):
            call, summary = self._call(row["id"], attempt, payload)
            output, reason = parse_output(summary["content"])
            cut = is_truncated(summary["finish_reason"], summary.get("native_finish_reason"),
                               summary["completion_tokens"], payload.get("max_tokens"))
            if cut:  # terpotong di batas max_tokens (keputusan penulis 2026-10-08)
                truncated += 1
                output, reason = None, (f"TRUNCATED: finish_reason {summary['finish_reason']}, "
                                        f"{summary['completion_tokens']} token (max_tokens {payload.get('max_tokens')})")
            elif output is not None and summary["finish_reason"] not in (None, "stop"):
                output, reason = None, f"finish_reason {summary['finish_reason']}"
            if summary["refusal"]:
                output, reason = None, f"penolakan: {str(summary['refusal'])[:200]}"
            outcome = "ok" if output else ("TRUNCATED" if cut else "parse_error")
            self._log(row["id"], attempt, payload, call, summary, outcome, reason)
            if output is not None:
                return {"id": row["id"], **output, "status": "ok", "attempts": attempt, "truncated_calls": truncated,
                        **self._spent}
        return {"id": row["id"], "label": "PARSE_ERROR", "status": "PARSE_ERROR", "attempts": PARSE_ATTEMPTS,
                "truncated_calls": truncated, "detail": reason, **self._spent}


def run(ids_path: Path | None = None, out_dir: Path = RESULTS_DIR, inputs_path: Path = SAMPLE_PATH,
        resume: bool = False, client: OpenRouterClient | None = None, calls_path: Path = CALLS_PATH,
        split: str | None = None, name: str = "llm_single_toolctx") -> dict:
    """Jalankan (atau lanjutkan) satu run ablation. Sama alur dengan llm_single.run, prompt dengan konteks alat."""
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
            "llm_single_toolctx", config["model"], run_name=name, model_version=config.get("model_version"),
            generation=config.get("generation"), provider_routing=config.get("provider_routing"),
            pricing_usd_per_1m_tokens=config.get("pricing_usd_per_1m_tokens"),
            prompt_sha256=prompt_sha256(), system_prompt=CLASSIFIER_PROMPT, output_schema=OUTPUT_SCHEMA,
            decode_sections=list(DECODE_SECTIONS),
            input_file=repo_path(inputs_path), input_sha256=sha256_file(inputs_path),
            ids_file=repo_path(ids_path), rows=len(rows), row_ids_sha256=ids_sha256([r["id"] for r in rows]),
            output_name=name, calls_file=repo_path(calls_path),
        )
    if info["prompt_sha256"] != prompt_sha256():
        raise RuntimeError("prompt berubah sejak run ini dimulai; mulai run baru")
    if resume:
        check_resume(info, {"input_file": repo_path(inputs_path), "ids_file": repo_path(ids_path), "rows": len(rows),
                            "row_ids_sha256": ids_sha256([r["id"] for r in rows]), "calls_file": repo_path(calls_path),
                            "output_name": name, "model": config["model"], "generation": config.get("generation"),
                            "provider_routing": config.get("provider_routing")})
    info_path.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    finished = {p["id"] for p in done}
    with (client or OpenRouterClient(api_key())) as client, open(calls_path, "a", encoding="utf-8") as calls, \
            open(partial, "a", encoding="utf-8") as out:
        runner = ToolCtxRunner(client, config, info["run_id"], calls)
        todo = [r for r in rows if r["id"] not in finished]
        for n, row in enumerate(todo, len(finished) + 1):
            result = {**runner.classify(row), "run_id": info["run_id"]}
            out.write(json.dumps(result, ensure_ascii=True) + "\n")
            out.flush()
            done.append(result)
            print(f"[llm_single_toolctx] {n}/{len(rows)} {row['id']} -> {result['label']} ({result['status']}, "
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
    parser = argparse.ArgumentParser(description="LLM tunggal + konteks alat deterministik (ablation, tanpa orkestrasi)")
    parser.add_argument("--ids", type=Path, help="berkas JSON {'ids': [...]} (mis. results/archive/pilot/pilot_ids.json)")
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--resume", action="store_true", help="lanjutkan run yang terhenti (<name>.partial.jsonl)")
    parser.add_argument("--split", help="baris srbh_<split>.parquet (mis. val) sebagai pengganti test_sample_500")
    parser.add_argument("--name", default="llm_single_toolctx", help="nama berkas keluaran (mis. llm_single_toolctx_r1)")
    parser.add_argument("--calls", type=Path, default=CALLS_PATH, help="log panggilan (bawaan results/llm_single_toolctx_calls.jsonl)")
    args = parser.parse_args(argv)
    try:
        info = run(args.ids.resolve() if args.ids else None, args.out_dir.resolve(), resume=args.resume,
                   calls_path=args.calls.resolve(), split=args.split, name=args.name)
    except RunAborted as exc:
        print(f"[llm_single_toolctx] DIHENTIKAN: {exc}", file=sys.stderr)
        return 2
    t = info["totals"]
    median = "—" if t["latency_s_median"] is None else f"{t['latency_s_median']:.2f} s"
    print(f"[llm_single_toolctx] selesai {info['rows']} baris, status {t['status']}, biaya ${t['cost_usd_total']:.6f} "
          f"(${t['cost_usd_per_1000_rows']:.4f} per 1.000 baris), latensi median {median}, run {info['run_id']} "
          f"(dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
