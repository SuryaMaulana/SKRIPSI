"""Rakitan deep agent: orkestrator create_deep_agent (deepagents) + empat sub-agen (BAB III).

- Model dan parameter sama dengan LLM tunggal (configs/llm.yaml): openai/gpt-4.1-nano-2025-04-14 lewat OpenRouter,
  temperature 0, seed 42, penyedia openai tanpa fallback. Setiap sub-agen memakai instans model sendiri bertag
  "subagen:<nama>" agar setiap panggilan bisa diatribusikan di results/agent_calls.jsonl.
- Kegagalan layanan diperlakukan sama dengan LLM tunggal: HTTP 408/429/5xx, galat jaringan/timeout, dan respons HTTP 200
  yang sebenarnya galat (galat penyedia, galat generasi, konten kosong tanpa panggilan alat) diulang 6 kali dengan jeda
  2, 4, ..., 64 detik; bila menetap, atau HTTP 4xx lain, run dihentikan dan dilanjutkan dengan --resume.
- Orkestrator hanya memegang write_todos (TodoListMiddleware) dan task (memanggil sub-agen). Alat berkas virtual deepagents
  (ls, read_file, write_file, edit_file, delete, glob, grep), execute, dan sub-agen general-purpose dimatikan lewat
  HarnessProfile untuk orkestrator dan sub-agen (keputusan penulis K1 setelah pilot v1, 2026-10-08).
- parser dan analisis_payload: sub-agen deklaratif deepagents dengan alat deterministik (tools.py).
- klasifikasi: sub-agen terkompilasi tanpa alat. Masukannya bagian MASUKAN Lampiran A yang dirakit dari keluaran alat;
  keluarannya JSON skema ketat yang sama dengan LLM tunggal. Gagal parse -> diulang sekali -> PARSE_ERROR.
- verifikasi: node deterministik TANPA panggilan LLM (keputusan penulis K2): menjalankan schema_check dan evidence_exists
  (tercatat sebagai pemanggilan alat sub-agen verifikasi); lolos hanya bila skema valid dan semua evidence ditemukan.
- VerificationRoundGuard menegakkan paling banyak MAX_VERIFICATION_ROUNDS putaran klasifikasi -> verifikasi.
- ProcedureGuard menegakkan aturan "jika verifikasi gagal kembali ke Klasifikasi" (keputusan penulis): bila orkestrator
  hendak berhenti padahal belum ada klasifikasi, klasifikasi terakhir belum diverifikasi, atau verifikasi menolak dan
  putaran belum habis, orkestrator diberi pengingat dan kembali ke model. Pemanggilan sub-agen tetap keputusan orkestrator.
- Pengaman putaran tak berujung (bukan pertimbangan biaya): orkestrator RECURSION_LIMIT langkah graf, tiap pemanggilan
  sub-agen parser/analisis_payload paling banyak SUBAGENT_MODEL_CALLS panggilan model. Seberapa sering batas ini tercapai
  dicatat per baris.
"""

from __future__ import annotations

import json
import time
from typing import Any

import openai
from deepagents import (
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    create_deep_agent,
    register_harness_profile,
)
from langchain.agents.middleware import (
    AgentMiddleware,
    ModelCallLimitMiddleware,
    ModelRetryMiddleware,
    TodoListMiddleware,
    hook_config,
)
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda
from langchain_openai import ChatOpenAI

from ..baselines.llm_single import SERVICE_RETRIES, parse_output, service_failure
from ..llm.klasifikasi import OUTPUT_SCHEMA
from ..llm.openrouter import BASE_URL, api_key, summarize
from . import context
from .context import MAX_VERIFICATION_ROUNDS
from .prompts import (
    CLASSIFIER_PROMPT,
    ORCHESTRATOR_PROMPT,
    PARSER_PROMPT,
    PAYLOAD_PROMPT,
    classifier_input,
)
from .tools import PARSER_TOOLS, PAYLOAD_TOOLS, evidence_exists, schema_check

CLASSIFIER_ATTEMPTS = 2  # sama dengan LLM tunggal: satu percobaan + satu ulangan bila gagal parse
MAX_CLASSIFICATIONS = 4  # pengaman putaran tak berujung di luar batas verifikasi
RECURSION_LIMIT = 80  # langkah graf orkestrator per baris
SUBAGENT_MODEL_CALLS = 15  # panggilan model per pemanggilan sub-agen parser/analisis_payload
LIMIT_MARKER = "Model call limits exceeded"  # awal pesan ModelCallLimitMiddleware saat batas tercapai
REQUEST_TIMEOUT_S = 120.0  # sama dengan klien LLM tunggal (src/llm/openrouter.py)
FILESYSTEM_TOOLS = frozenset({"ls", "read_file", "write_file", "edit_file", "delete", "glob", "grep"})  # bawaan deepagents
EXCLUDED_TOOLS = FILESYSTEM_TOOLS | {"execute"}  # keputusan penulis K1
MAX_REMINDERS = 4  # pengingat prosedur per baris (cukup untuk: klasifikasi, verifikasi, klasifikasi ulang, verifikasi ulang)


class ServiceFailure(RuntimeError):
    """Respons HTTP 200 yang sebenarnya kegagalan layanan, bukan jawaban model (lihat llm_single.service_failure)."""


def is_service_error(exc: BaseException) -> bool:
    """Kegagalan yang diulang dengan jeda (sama dengan LLM tunggal); selain ini run langsung dihentikan."""
    if isinstance(exc, (ServiceFailure, openai.APIConnectionError, openai.APIResponseValidationError)):
        return True
    return isinstance(exc, openai.APIStatusError) and (exc.status_code in (408, 429) or exc.status_code >= 500)


class OpenRouterChat(ChatOpenAI):
    """ChatOpenAI yang memeriksa respons HTTP 200 dengan aturan kegagalan layanan LLM tunggal, dan menyimpan penyedia
    hulu (field provider OpenRouter) di llm_output."""

    def _create_chat_result(self, response, generation_info=None):
        body = response if isinstance(response, dict) else response.model_dump()
        summary = summarize({"http_status": 200, "latency_s": 0.0, "response": body})
        message = ((body.get("choices") or [{}])[0] or {}).get("message") or {}
        if message.get("tool_calls") and summary["content"] in (None, ""):
            summary["content"] = "(panggilan alat)"  # konten kosong wajar bila model memanggil alat
        reason = service_failure(summary)
        if reason:
            raise ServiceFailure(reason)
        result = super()._create_chat_result(response, generation_info)
        result.llm_output = {**(result.llm_output or {}), "upstream_provider": body.get("provider")}
        return result


def make_model(config: dict, subagent: str, key: str) -> OpenRouterChat:
    generation = config.get("generation") or {}
    return OpenRouterChat(
        model=config["model"], base_url=BASE_URL, api_key=key, temperature=generation.get("temperature", 0),
        seed=generation.get("seed"), use_responses_api=False, max_retries=0, timeout=REQUEST_TIMEOUT_S,
        extra_body={"provider": dict(config["provider_routing"])}, tags=[f"subagen:{subagent}"],
    )


def retry_middleware() -> ModelRetryMiddleware:
    return ModelRetryMiddleware(max_retries=SERVICE_RETRIES, retry_on=is_service_error, on_failure="error",
                                backoff_factor=2.0, initial_delay=2.0, max_delay=64.0, jitter=False)


def limit_middleware() -> ModelCallLimitMiddleware:
    return ModelCallLimitMiddleware(run_limit=SUBAGENT_MODEL_CALLS, exit_behavior="end")


def as_subagent(config: RunnableConfig | None, name: str) -> RunnableConfig:
    """Config untuk graf/model di dalam sub-agen terkompilasi: metadata lc_agent_name dan tag subagen:<nama> agar setiap
    panggilan model dan alat di dalamnya tercatat atas nama sub-agen itu (bukan orkestrator)."""
    config = dict(config or {})
    config["metadata"] = {**(config.get("metadata") or {}), "lc_agent_name": name}
    config["tags"] = [t for t in (config.get("tags") or []) if not t.startswith("subagen:")] + [f"subagen:{name}"]
    return config


def invoke_with_retries(model, messages, config, sleep=time.sleep):
    """Satu panggilan model dengan kebijakan ulang kegagalan layanan yang sama dengan LLM tunggal."""
    for retry in range(SERVICE_RETRIES + 1):
        try:
            return model.invoke(messages, config)
        except Exception as exc:
            if not is_service_error(exc) or retry == SERVICE_RETRIES:
                raise
            sleep(2 ** (retry + 1))
    raise AssertionError("tidak tercapai")


def _register_profile() -> None:
    register_harness_profile("openai", HarnessProfile(
        excluded_tools=EXCLUDED_TOOLS,
        general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
    ))


def build_classifier(model, sleep=time.sleep) -> RunnableLambda:
    structured = model.bind(response_format={"type": "json_schema", "json_schema": {
        "name": "klasifikasi_log", "strict": True, "schema": OUTPUT_SCHEMA}})

    def run(state: dict, config: RunnableConfig) -> dict:
        ctx = context.current()
        messages = [SystemMessage(CLASSIFIER_PROMPT), HumanMessage(classifier_input(ctx))]
        output, reason = None, "tidak ada percobaan"
        for _ in range(CLASSIFIER_ATTEMPTS):
            reply = invoke_with_retries(structured, messages, as_subagent(config, "klasifikasi"), sleep)
            output, reason = parse_output(reply.content)
            finish = (reply.response_metadata or {}).get("finish_reason")
            if output is not None and finish not in (None, "stop"):
                output, reason = None, f"finish_reason {finish}"
            refusal = (reply.additional_kwargs or {}).get("refusal")
            if refusal:
                output, reason = None, f"penolakan: {str(refusal)[:200]}"
            if output is not None:
                break
        with ctx.lock:
            ctx.classifications.append(output if output is not None else {"_parse_error": reason})
        content = json.dumps(output if output is not None else {"galat": f"PARSE_ERROR: {reason}"}, ensure_ascii=False)
        return {"messages": [AIMessage(content=content)]}

    return RunnableLambda(run, name="klasifikasi")


def deterministic_verdict(schema: dict, missing: list[str]) -> dict:
    """Putusan Verifikasi dari hasil schema_check dan evidence_exists saja (K2)."""
    reasons = []
    if not schema["valid"]:
        reasons.append(f"schema_check gagal: {schema.get('alasan')}")
    if missing:
        reasons.append("evidence tidak ditemukan di baris log: " + "; ".join(e[:120] for e in missing))
    return {"lolos": bool(schema["valid"]) and not missing, "alasan": reasons, "skema_valid": bool(schema["valid"]),
            "evidence_hilang": missing}


def build_verifier() -> RunnableLambda:
    """Sub-agen Verifikasi deterministik (tanpa LLM): schema_check atas klasifikasi terakhir, lalu evidence_exists untuk
    setiap item evidence. Alat dipanggil sebagai alat LangChain agar tercatat di agent_calls.jsonl atas nama verifikasi."""

    def run(state: dict, config: RunnableConfig) -> dict:
        ctx = context.current()
        cfg = as_subagent(config, "verifikasi")
        schema = json.loads(schema_check.invoke({}, cfg))
        missing = []
        if schema["valid"]:
            for item in ctx.latest_classification()["evidence"]:
                if not json.loads(evidence_exists.invoke({"item": item}, cfg))["ada"]:
                    missing.append(item)
        verdict = deterministic_verdict(schema, missing)
        with ctx.lock:
            verdict["putaran"] = len(ctx.verdicts) + 1
            verdict["klasifikasi_ke"] = len(ctx.classifications)
            ctx.verdicts.append(verdict)
        return {"messages": [AIMessage(content=json.dumps({k: verdict[k] for k in ("lolos", "alasan", "putaran")},
                                                          ensure_ascii=False))]}

    return RunnableLambda(run, name="verifikasi")


class VerificationRoundGuard(AgentMiddleware):
    """Menahan pemanggilan sub-agen yang melanggar batas putaran (keputusan penulis: maksimum 2 putaran)."""

    def wrap_tool_call(self, request, handler):
        call = request.tool_call
        if call.get("name") == "task":
            args = call.get("args") or {}
            blocked = self.blocked(args)
            if blocked:
                ctx = context.current()
                with ctx.lock:
                    ctx.guard_blocks.append({"subagen": args.get("subagent_type"), "alasan": blocked,
                                             "putaran": ctx.verification_round})
                return ToolMessage(content=blocked, tool_call_id=call["id"], name="task")
        return handler(request)

    @staticmethod
    def blocked(args: dict[str, Any]) -> str | None:
        ctx = context.current()
        target = args.get("subagent_type")
        if target == "klasifikasi":
            if ctx.verdicts and not ctx.verdicts[-1]["lolos"] and ctx.verification_round >= MAX_VERIFICATION_ROUNDS:
                return (f"Batas {MAX_VERIFICATION_ROUNDS} putaran verifikasi tercapai. Jangan memanggil klasifikasi lagi; "
                        "akhiri dengan menyalin JSON klasifikasi terakhir.")
            if ctx.verdicts and ctx.verdicts[-1]["lolos"] and not ctx.unverified():
                return "Klasifikasi terakhir sudah lolos verifikasi. Akhiri dengan menyalin JSON klasifikasi itu."
            if len(ctx.classifications) >= MAX_CLASSIFICATIONS:
                return "Batas pemanggilan klasifikasi tercapai. Akhiri dengan JSON klasifikasi terakhir."
        if target == "verifikasi":
            if not ctx.classifications:
                return "Belum ada keluaran klasifikasi untuk diverifikasi. Panggil klasifikasi lebih dulu."
            if not ctx.unverified():
                if not ctx.verdicts[-1]["lolos"] and ctx.verification_round < MAX_VERIFICATION_ROUNDS:
                    return ("Klasifikasi terakhir sudah diverifikasi dan DITOLAK. Panggil klasifikasi lagi (alasan penolakan "
                            "diteruskan otomatis), lalu verifikasi.")
                return "Klasifikasi terakhir sudah diverifikasi. Ikuti putusan verifikasi sebelumnya."
            if ctx.verification_round >= MAX_VERIFICATION_ROUNDS:
                return f"Batas {MAX_VERIFICATION_ROUNDS} putaran verifikasi tercapai. Akhiri dengan JSON klasifikasi terakhir."
        return None


def procedure_reminder(ctx: context.RowContext) -> str | None:
    """Langkah prosedur yang belum dijalankan saat orkestrator hendak berhenti, atau None bila boleh berhenti."""
    if not ctx.classifications:
        return ("Belum ada keluaran klasifikasi. Panggil sub-agen klasifikasi (setelah parser dan analisis_payload bila "
                "belum) sebelum mengakhiri.")
    if ctx.verification_round >= MAX_VERIFICATION_ROUNDS:
        return None
    if ctx.unverified():
        return "Klasifikasi terakhir belum diverifikasi. Panggil sub-agen verifikasi sebelum mengakhiri."
    if not ctx.verdicts[-1]["lolos"]:
        return ("Verifikasi menolak klasifikasi terakhir dan batas putaran belum tercapai. Panggil sub-agen klasifikasi "
                "lagi (alasan penolakan diteruskan otomatis), lalu verifikasi.")
    return None


class ProcedureGuard(AgentMiddleware):
    """Saat orkestrator menjawab tanpa memanggil alat (hendak berhenti) padahal prosedur belum selesai, tambahkan
    pengingat dan kembalikan ke model. Paling banyak MAX_REMINDERS pengingat per baris."""

    @hook_config(can_jump_to=["model"])
    def after_model(self, state, runtime):
        messages = state.get("messages") or []
        last = messages[-1] if messages else None
        if not isinstance(last, AIMessage) or last.tool_calls:
            return None
        ctx = context.current()
        reminder = procedure_reminder(ctx)
        if reminder is None or len(ctx.reminders) >= MAX_REMINDERS:
            return None
        with ctx.lock:
            ctx.reminders.append(reminder)
        return {"messages": [HumanMessage(f"PENGINGAT PROSEDUR: {reminder}")], "jump_to": "model"}


def build_agent(config: dict):
    """Graf deep agent siap dipanggil per baris: invoke({"messages": [HumanMessage(...)]})."""
    _register_profile()
    key = api_key()
    subagents = [
        {"name": "parser", "description": "Menguraikan baris log menjadi kolom dan menandai kolom yang rusak.",
         "system_prompt": PARSER_PROMPT, "tools": PARSER_TOOLS, "model": make_model(config, "parser", key),
         "middleware": [retry_middleware(), limit_middleware()]},
        {"name": "analisis_payload",
         "description": "Mendekode payload dan mencari indikator serangan atau pemindaian pada path, query, user "
                        "agent, dan referer dengan pencocok pola CRS, indikator pemindai, dan basis pengetahuan OWASP.",
         "system_prompt": PAYLOAD_PROMPT, "tools": PAYLOAD_TOOLS, "model": make_model(config, "analisis_payload", key),
         "middleware": [retry_middleware(), limit_middleware()]},
        {"name": "klasifikasi", "description": "Menetapkan satu dari enam kelas berdasarkan bukti yang dikumpulkan alat; "
                                               "keluaran JSON {label, confidence, evidence, explanation}.",
         "runnable": build_classifier(make_model(config, "klasifikasi", key))},
        {"name": "verifikasi", "description": "Memeriksa skema keluaran klasifikasi terakhir dan keberadaan literal setiap "
                                              "evidence di baris log; menjawab lolos atau tolak beserta alasan.",
         "runnable": build_verifier()},
    ]
    return create_deep_agent(
        model=make_model(config, "orkestrator", key), tools=[], system_prompt=ORCHESTRATOR_PROMPT, subagents=subagents,
        middleware=[TodoListMiddleware(), VerificationRoundGuard(), ProcedureGuard(), retry_middleware()], name="orkestrator",
    )
