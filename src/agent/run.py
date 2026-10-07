"""Langkah E — menjalankan deep agent per baris test_sample_500 (pilot 30 baris dulu; keputusan penulis).

Masukan agen hanya raw_log_masked (sama dengan LLM tunggal); kolom lain diturunkan sendiri oleh alat Parser. Setiap
panggilan LLM dan setiap pemanggilan alat dicatat ke results/agent_calls.jsonl lewat callback LangChain: id baris,
sub-agen, token, latensi, biaya (usage.cost OpenRouter), dan putaran verifikasi saat itu. System prompt dan definisi alat
yang dikirim ke model dicatat sekali per isi berbeda (jenis "prompt_sistem"/"definisi_alat"), lalu dirujuk lewat sha256.

Label akhir = keluaran sub-agen Klasifikasi yang valid paling akhir (bukan teks bebas orkestrator). Status per baris:
- ok: klasifikasi itu lolos verifikasi;
- verification_failed: klasifikasi itu ditolak verifikasi (batas putaran tercapai atau orkestrator berhenti); label tetap
  dipakai (keputusan penulis: "pakai label terakhir dan tandai verification_failed");
- verification_skipped: klasifikasi itu tidak pernah diverifikasi; label tetap dipakai;
- PARSE_ERROR: tidak ada klasifikasi yang valid (gagal parse dua kali, atau orkestrator tidak memanggil klasifikasi
  sebelum selesai/batas rekursi) -> dihitung salah oleh evaluasi.
Galat API yang menetap (lihat graph.py: kebijakan ulang sama dengan LLM tunggal) menghentikan run tanpa menilai baris
itu; lanjutkan dengan --resume.
Jalankan: make agent-pilot | make agent
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import openai
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import HumanMessage, ToolMessage
from langgraph.errors import GraphRecursionError

from ..baselines.llm_single import RunAborted, totals
from ..common.inputs import SAMPLE_PATH, method_rows
from ..common.runinfo import git_state, run_info, sha256_file
from ..data.config import ROOT
from ..llm.klasifikasi import sha256
from ..llm.openrouter import load_llm_config
from . import context
from .context import MAX_VERIFICATION_ROUNDS, CallLogger, RowContext
from .graph import (
    CLASSIFIER_ATTEMPTS,
    EXCLUDED_TOOLS,
    LIMIT_MARKER,
    MAX_CLASSIFICATIONS,
    MAX_REMINDERS,
    RECURSION_LIMIT,
    REQUEST_TIMEOUT_S,
    SUBAGENT_MODEL_CALLS,
    ServiceFailure,
    build_agent,
)
from .prompts import CLASSIFIER_PROMPT, ORCHESTRATOR_PROMPT, PARSER_PROMPT, PAYLOAD_PROMPT

RESULTS_DIR = ROOT / "results"
CALLS_PATH = RESULTS_DIR / "agent_calls.jsonl"
KB_PATH = ROOT / "configs" / "owasp_kb.yaml"
TEXT_LIMIT = 4000  # potongan masukan/keluaran alat yang disimpan di log panggilan
STATUSES = ("ok", "verification_failed", "verification_skipped", "PARSE_ERROR")
SUBAGENTS = ("parser", "analisis_payload", "klasifikasi", "verifikasi")
_KEYLIKE = re.compile(r"sk-[A-Za-z0-9_\-]{6,}")


TRACING_VARS = ("LANGSMITH_TRACING", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING", "LANGCHAIN_TRACING_V2")


def disable_remote_tracing() -> None:
    """Semua catatan tetap lokal (results/agent_calls.jsonl): tracing LangSmith dimatikan agar isi log tidak terkirim
    ke layanan luar, apa pun isi environment."""
    for name in TRACING_VARS:
        os.environ[name] = "false"


def safe_error(exc: BaseException) -> str:
    """Ringkasan galat tanpa nilai yang menyerupai kunci API."""
    if isinstance(exc, (openai.AuthenticationError, openai.PermissionDeniedError)):
        return f"{type(exc).__name__} (HTTP {exc.status_code})"
    return _KEYLIKE.sub("sk-***", f"{type(exc).__name__}: {str(exc)[:300]}")


def _agent_name(tags: list[str] | None, metadata: dict | None) -> str:
    for tag in tags or []:
        if tag.startswith("subagen:"):
            return tag.split(":", 1)[1]
    return (metadata or {}).get("lc_agent_name") or "orkestrator"


def _message(m) -> dict:
    out = {"role": m.type, "content": m.content}
    if getattr(m, "tool_calls", None):
        out["tool_calls"] = m.tool_calls
    if getattr(m, "tool_call_id", None):
        out["tool_call_id"] = m.tool_call_id
    return out


def _clip(value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= TEXT_LIMIT else text[:TEXT_LIMIT] + f"...[+{len(text) - TEXT_LIMIT} karakter]"


class CallRecorder(BaseCallbackHandler):
    """Mencatat setiap panggilan LLM dan alat (termasuk alat bawaan deepagents) ke results/agent_calls.jsonl."""

    raise_error = True

    def __init__(self, logger: CallLogger):
        self.logger = logger
        self._llm: dict = {}
        self._tool: dict = {}
        self._seen: set[str] = set()
        self.sent: dict[str, dict] = {}  # sha256 -> {"jenis", "isi"}: prompt sistem/definisi alat yang benar-benar terkirim
        self._lock = threading.Lock()

    def _once(self, kind: str, value) -> str:
        """Catat isi besar (system prompt, definisi alat) sekali saja; kembalikan sha256-nya."""
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._lock:
            new = digest not in self._seen
            self._seen.add(digest)
            self.sent.setdefault(digest, {"jenis": kind, "isi": value})
        if new:
            self.logger.write({"run_id": context.current().run_id, "jenis": kind, "sha256": digest, "isi": value})
        return digest

    def on_chat_model_start(self, serialized, messages, *, run_id, tags=None, metadata=None, **kwargs):
        prompt = [{"role": "system", "sha256": self._once("prompt_sistem", m.content)} if m.type == "system"
                  else _message(m) for m in messages[0]]
        params = {k: v for k, v in (kwargs.get("invocation_params") or {}).items() if k not in ("api_key", "tools")}
        tools = (kwargs.get("invocation_params") or {}).get("tools")
        if tools:
            params["tools"] = {"nama": [(t.get("function") or {}).get("name") for t in tools],
                               "sha256": self._once("definisi_alat", tools)}
        self._llm[run_id] = (time.perf_counter(), _agent_name(tags, metadata), prompt, params)

    def on_llm_end(self, response, *, run_id, **kwargs):
        start, agent, prompt, params = self._llm.pop(run_id, (time.perf_counter(), "?", [], {}))
        latency = time.perf_counter() - start
        generation = response.generations[0][0]
        message = getattr(generation, "message", None)
        meta = (message.response_metadata or {}) if message is not None else {}
        output = response.llm_output or {}
        usage = output.get("token_usage") or meta.get("token_usage") or {}
        ctx = context.current()
        with ctx.lock:
            ctx.llm_calls += 1
            ctx.prompt_tokens += usage.get("prompt_tokens") or 0
            ctx.completion_tokens += usage.get("completion_tokens") or 0
            ctx.cost_usd += usage.get("cost") or 0.0
            ctx.llm_latency_s += latency
            round_ = ctx.verification_round
        self.logger.write({
            "run_id": ctx.run_id, "id": ctx.row_id, "jenis": "llm", "subagen": agent, "putaran_verifikasi": round_,
            "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
            "cached_tokens": (usage.get("prompt_tokens_details") or {}).get("cached_tokens"),
            "cost_usd": usage.get("cost"), "latency_s": round(latency, 3), "finish_reason": meta.get("finish_reason"),
            "served_model": output.get("model_name"), "upstream_provider": output.get("upstream_provider"),
            "system_fingerprint": output.get("system_fingerprint"), "parameter": params, "prompt": prompt,
            "respons": _message(message) if message is not None else generation.text,
        })

    def on_llm_error(self, error, *, run_id, **kwargs):
        start, agent, prompt, params = self._llm.pop(run_id, (time.perf_counter(), "?", [], {}))
        ctx = context.current()
        self.logger.write({"run_id": ctx.run_id, "id": ctx.row_id, "jenis": "llm_galat", "subagen": agent,
                           "putaran_verifikasi": ctx.verification_round, "latency_s": round(time.perf_counter() - start, 3),
                           "galat": safe_error(error), "parameter": params, "prompt": prompt})

    def on_tool_start(self, serialized, input_str, *, run_id, tags=None, metadata=None, inputs=None, **kwargs):
        name = (serialized or {}).get("name") or kwargs.get("name") or "?"
        self._tool[run_id] = (time.perf_counter(), _agent_name(tags, metadata), name,
                              inputs if inputs is not None else input_str)

    def on_tool_end(self, output, *, run_id, **kwargs):
        self._finish_tool(run_id, output=output)

    def on_tool_error(self, error, *, run_id, **kwargs):
        self._finish_tool(run_id, error=safe_error(error))

    def _finish_tool(self, run_id, output=None, error=None):
        start, agent, name, given = self._tool.pop(run_id, (time.perf_counter(), "?", "?", None))
        ctx = context.current()
        with ctx.lock:
            ctx.tool_calls += 1
            ctx.tool_names.append(f"task:{given.get('subagent_type')}" if name == "task" and isinstance(given, dict)
                                  else name)
            round_ = ctx.verification_round
        update = getattr(output, "update", None)
        if isinstance(update, dict):  # Command dari alat task/write_todos: ambil pesan alatnya
            messages = update.get("messages") or []
            output = messages[-1] if messages else update
        text = getattr(output, "content", output)
        self.logger.write({
            "run_id": ctx.run_id, "id": ctx.row_id, "jenis": "alat", "subagen": agent, "alat": name,
            "putaran_verifikasi": round_, "latency_s": round(time.perf_counter() - start, 3),
            "masukan": _clip(given), "keluaran": None if text is None else _clip(text), "galat": error,
        })


def assemble(ctx: RowContext, run_id: str, wall_s: float, final_message: str | None, limit_hits: int = 0,
             error: str | None = None) -> dict:
    """Baris keluaran: label dari klasifikasi valid paling akhir beserta status verifikasinya."""
    valid = [k for k, c in enumerate(ctx.classifications, 1) if "_parse_error" not in c]
    verification = {"putaran": ctx.verification_round, "penolakan": ctx.rejections(), "verification_failed": False,
                    "verification_skipped": False,
                    "putusan": [{k: v.get(k) for k in ("putaran", "klasifikasi_ke", "lolos", "skema_valid", "evidence_hilang",
                                                       "alasan")} for v in ctx.verdicts]}
    delegated = {name: f"task:{name}" in ctx.tool_names for name in SUBAGENTS}
    base = {"id": ctx.row_id, "run_id": run_id, "prompt_tokens": ctx.prompt_tokens,
            "completion_tokens": ctx.completion_tokens, "cost_usd": ctx.cost_usd, "latency_s": wall_s,
            "llm_latency_s": ctx.llm_latency_s, "llm_calls": ctx.llm_calls, "tool_calls": ctx.tool_calls,
            "klasifikasi_dipanggil": len(ctx.classifications),
            "riwayat_label": [c.get("label", "PARSE_ERROR") for c in ctx.classifications], "verifikasi": verification,
            "delegasi": {**delegated, "keempat_subagen": all(delegated.values())},
            "alat_dipanggil": dict(Counter(ctx.tool_names)),
            "ditahan_guard": ctx.guard_blocks, "pengingat_prosedur": ctx.reminders, "batas_panggilan_subagen": limit_hits,
            "attempts": ctx.attempt}
    if error:
        base["detail"] = error
    if not valid:
        reason = error or (ctx.classifications[-1]["_parse_error"] if ctx.classifications
                           else "orkestrator selesai tanpa memanggil klasifikasi")
        return {**base, "label": "PARSE_ERROR", "status": "PARSE_ERROR", "detail": reason}
    chosen = valid[-1]
    verdicts = [v for v in ctx.verdicts if v["klasifikasi_ke"] == chosen]
    if not verdicts:
        status = "verification_skipped"
    elif verdicts[-1]["lolos"]:
        status = "ok"
    else:
        status = "verification_failed"
    verification["verification_failed"] = status == "verification_failed"
    verification["verification_skipped"] = status == "verification_skipped"
    return {**base, **ctx.classifications[chosen - 1], "status": status, "klasifikasi_dipakai": chosen,
            "pesan_akhir_orkestrator": (final_message or "")[:2000]}


def classify_row(agent, recorder: CallRecorder, run_id: str, row: dict) -> dict:
    ctx = RowContext(run_id, row["id"], row["raw_log_masked"])
    context.set_current(ctx)
    start = time.perf_counter()
    try:
        state = agent.invoke(
            {"messages": [HumanMessage(f"Klasifikasikan baris log berikut.\n<log>{row['raw_log_masked']}</log>")]},
            config={"callbacks": [recorder], "recursion_limit": RECURSION_LIMIT})
    except GraphRecursionError:
        return assemble(ctx, run_id, time.perf_counter() - start, None,
                        error=f"batas rekursi orkestrator ({RECURSION_LIMIT} langkah) tercapai")
    except (openai.APIError, ServiceFailure) as exc:
        recorder.logger.write({"run_id": run_id, "id": row["id"], "jenis": "galat_api", "galat": safe_error(exc)})
        raise RunAborted(f"{row['id']}: {safe_error(exc)}; run dihentikan, lanjutkan dengan --resume") from None
    messages = state.get("messages") or []
    limit_hits = sum(isinstance(m, ToolMessage) and str(m.content).startswith(LIMIT_MARKER) for m in messages)
    final = messages[-1].content if messages else None
    return assemble(ctx, run_id, time.perf_counter() - start, final if isinstance(final, str) else json.dumps(final),
                    limit_hits=limit_hits)


def summarize_rows(done: list[dict]) -> dict:
    n = max(len(done), 1)
    return {**totals([{**p, "status": "PARSE_ERROR" if p["status"] == "PARSE_ERROR" else "ok"} for p in done]),
            "status_detail": {s: sum(p["status"] == s for p in done) for s in STATUSES},
            "verification_rejections": sum(p["verifikasi"]["penolakan"] for p in done),
            "rows_with_rejection": sum(p["verifikasi"]["penolakan"] > 0 for p in done),
            "guard_blocks": sum(len(p["ditahan_guard"]) for p in done),
            "procedure_reminders": sum(len(p["pengingat_prosedur"]) for p in done),
            "subagent_limit_hits": sum(p["batas_panggilan_subagen"] for p in done),
            "delegated_all_four": sum(p["delegasi"]["keempat_subagen"] for p in done),
            "recursion_limit_rows": sum("batas rekursi" in (p.get("detail") or "") for p in done),
            "llm_calls_mean": sum(p["llm_calls"] for p in done) / n,
            "tool_calls_mean": sum(p["tool_calls"] for p in done) / n}


def run(ids_path: Path | None = None, out_dir: Path = RESULTS_DIR, inputs_path: Path = SAMPLE_PATH,
        resume: bool = False, calls_path: Path = CALLS_PATH, agent=None, split: str | None = None,
        name: str = "agent") -> dict:
    """split: baris srbh_<split>.parquet (mis. val) sebagai pengganti test_sample_500; name: nama berkas keluaran
    (mis. agent_r1 untuk replikasi)."""
    disable_remote_tracing()
    config = load_llm_config()
    rows, inputs_path = method_rows(inputs_path, split)
    if ids_path is not None:
        by_id = {r["id"]: r for r in rows}
        rows = [by_id[i] for i in json.loads(ids_path.read_text(encoding="utf-8"))["ids"]]
    out_dir.mkdir(parents=True, exist_ok=True)
    partial, info_path = out_dir / f"{name}.partial.jsonl", out_dir / f"{name}.partial.run.json"
    prompts = {"orkestrator": ORCHESTRATOR_PROMPT, "parser": PARSER_PROMPT, "analisis_payload": PAYLOAD_PROMPT,
               "klasifikasi": CLASSIFIER_PROMPT}
    prompt_hashes = {k: sha256(v) for k, v in prompts.items()}
    done: list[dict] = []
    if resume:
        if not partial.exists():
            raise FileNotFoundError(f"tidak ada run setengah jadi di {partial}")
        info = json.loads(info_path.read_text(encoding="utf-8"))
        done = [json.loads(x) for x in partial.read_text(encoding="utf-8").splitlines() if x.strip()]
        info.setdefault("resumed", []).append({"date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                               **git_state(), "rows_done": len(done)})
    else:
        if partial.exists():
            raise FileExistsError(f"{partial} sudah ada: lanjutkan dengan --resume atau hapus dulu")
        info = run_info(
            "agent", config["model"], model_version=config.get("model_version"), generation=config.get("generation"),
            provider_routing=config.get("provider_routing"),
            pricing_usd_per_1m_tokens=config.get("pricing_usd_per_1m_tokens"), prompt_sha256=prompt_hashes,
            prompts=prompts,
            limits={"max_verification_rounds": MAX_VERIFICATION_ROUNDS, "classifier_parse_attempts": CLASSIFIER_ATTEMPTS,
                    "max_classifications": MAX_CLASSIFICATIONS, "orchestrator_recursion_limit": RECURSION_LIMIT,
                    "subagent_model_calls": SUBAGENT_MODEL_CALLS, "procedure_reminders": MAX_REMINDERS,
                    "request_timeout_s": REQUEST_TIMEOUT_S},
            excluded_tools=sorted(EXCLUDED_TOOLS), verifier="deterministik tanpa LLM (schema_check + evidence_exists)",
            pattern_match="mesin emulasi CRS 4.30.0 yang sama dengan regex_full (configs/regex_full.yaml), tanpa "
                          "pemetaan kelas",
            knowledge_base=str(KB_PATH.relative_to(ROOT)), knowledge_base_sha256=sha256_file(KB_PATH),
            remote_tracing="dimatikan (LangSmith); catatan hanya lokal",
            input_file=str(inputs_path.relative_to(ROOT)), input_sha256=sha256_file(inputs_path),
            ids_file=str(ids_path.relative_to(ROOT)) if ids_path else None, rows=len(rows), output_name=name,
            calls_file=str(calls_path.relative_to(ROOT)) if calls_path.is_relative_to(ROOT) else str(calls_path))
    if info["prompt_sha256"] != prompt_hashes:
        raise RuntimeError("prompt berubah sejak run ini dimulai; mulai run baru")
    info_path.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    agent = agent or build_agent(config)
    logger = CallLogger(calls_path)
    recorder = CallRecorder(logger)
    finished = {p["id"] for p in done}
    try:
        with open(partial, "a", encoding="utf-8") as out:
            for n, row in enumerate([r for r in rows if r["id"] not in finished], len(finished) + 1):
                result = classify_row(agent, recorder, info["run_id"], row)
                out.write(json.dumps(result, ensure_ascii=True) + "\n")
                out.flush()
                done.append(result)
                v = result["verifikasi"]
                print(f"[agent] {n}/{len(rows)} {row['id']} -> {result['label']} ({result['status']}, putaran "
                      f"{v['putaran']}, tolak {v['penolakan']}, LLM {result['llm_calls']}, alat {result['tool_calls']}, "
                      f"{result['latency_s']:.1f} s, ${result['cost_usd']:.5f})", flush=True)
    finally:
        logger.close()
        context.set_current(None)
    order = {r["id"]: k for k, r in enumerate(rows)}
    done.sort(key=lambda p: order[p["id"]])
    info["totals"] = summarize_rows(done)
    info.setdefault("prompt_terkirim", {}).update(recorder.sent)  # prompt sistem + definisi alat yang benar-benar dikirim
    (out_dir / f"{name}.jsonl").write_text("".join(json.dumps(p, ensure_ascii=True) + "\n" for p in done), encoding="utf-8")
    (out_dir / f"{name}.run.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    partial.unlink()
    info_path.unlink()
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deep agent (langkah E)")
    parser.add_argument("--ids", type=Path, help="berkas JSON {'ids': [...]} (mis. results/pilot/pilot_ids.json)")
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--resume", action="store_true", help="lanjutkan run yang terhenti (<name>.partial.jsonl)")
    parser.add_argument("--split", help="baris srbh_<split>.parquet (mis. val) sebagai pengganti test_sample_500")
    parser.add_argument("--name", default="agent", help="nama berkas keluaran (mis. agent_r1)")
    parser.add_argument("--calls", type=Path, default=CALLS_PATH, help="log panggilan (bawaan results/agent_calls.jsonl)")
    args = parser.parse_args(argv)
    try:
        info = run(args.ids.resolve() if args.ids else None, args.out_dir.resolve(), resume=args.resume,
                   calls_path=args.calls.resolve(), split=args.split, name=args.name)
    except RunAborted as exc:
        print(f"[agent] DIHENTIKAN: {exc}", file=sys.stderr)
        return 2
    t = info["totals"]
    print(f"[agent] selesai {info['rows']} baris, status {t['status_detail']}, penolakan verifikasi "
          f"{t['verification_rejections']} (di {t['rows_with_rejection']} baris), biaya ${t['cost_usd_total']:.5f}, "
          f"latensi median {t['latency_s_median']:.1f} s, run {info['run_id']} (dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
