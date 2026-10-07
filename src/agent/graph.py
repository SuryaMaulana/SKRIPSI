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
- Batas token keluaran generation.max_tokens (configs/llm.yaml, 4.096) untuk semua panggilan LLM, sama dengan C (keputusan
  penulis 2026-10-08: pengaman kegagalan). Panggilan yang terpotong (openrouter.is_truncated: finish_reason length, alasan
  asli penyedia, atau token keluaran >= max_tokens) dicatat TRUNCATED dan diulang sekali; bila terpotong lagi: pada
  Klasifikasi menjadi klasifikasi PARSE_ERROR (seperti C); pada orkestrator/parser/analisis_payload baris dihentikan
  (TruncatedOutput) dengan label klasifikasi valid terakhir bila ada, selain itu PARSE_ERROR.
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
from ..llm.openrouter import BASE_URL, api_key, is_truncated, summarize
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


class TruncatedOutput(RuntimeError):
    """Keluaran LLM terpotong di max_tokens dua kali berturut-turut pada panggilan yang sama (baris -> PARSE_ERROR)."""


class ServiceFailure(RuntimeError):
    """Respons HTTP 200 yang sebenarnya kegagalan layanan, bukan jawaban model (lihat llm_single.service_failure)."""


def is_service_error(exc: BaseException) -> bool:
    """Kegagalan yang diulang dengan jeda (sama dengan LLM tunggal); selain ini run langsung dihentikan."""
    if isinstance(exc, (ServiceFailure, openai.APIConnectionError, openai.APIResponseValidationError)):
        return True
    return isinstance(exc, openai.APIStatusError) and (exc.status_code in (408, 429) or exc.status_code >= 500)


class OpenRouterChat(ChatOpenAI):
    """ChatOpenAI yang memeriksa respons HTTP 200 dengan aturan kegagalan layanan LLM tunggal, menyimpan penyedia hulu
    (field provider OpenRouter) di llm_output, dan menormalkan panggilan yang terpotong di max_tokens menjadi
    finish_reason "length" (nilai asli disimpan sebagai finish_reason_asli) agar TRUNCATED terdeteksi juga pada
    pemanggilan alat, yang oleh OpenRouter dilaporkan sebagai "tool_calls"."""

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
        choice = (body.get("choices") or [{}])[0] or {}
        truncated = is_truncated(choice.get("finish_reason"), choice.get("native_finish_reason"),
                                 (body.get("usage") or {}).get("completion_tokens"), (self.extra_body or {}).get("max_tokens"))
        for generation in result.generations:
            info = dict(generation.generation_info or {})
            info["native_finish_reason"] = choice.get("native_finish_reason")
            if truncated:
                info["finish_reason_asli"] = info.get("finish_reason")
                info["finish_reason"] = "length"
            generation.generation_info = info
            generation.message.response_metadata = {**(generation.message.response_metadata or {}), **info}
        return result


def make_model(config: dict, subagent: str, key: str) -> OpenRouterChat:
    """max_tokens dikirim lewat badan permintaan dengan nama yang sama dengan C ("max_tokens"); field max_tokens milik
    ChatOpenAI akan dikirim sebagai max_completion_tokens."""
    generation = config.get("generation") or {}
    extra = {"provider": dict(config["provider_routing"])}
    if generation.get("max_tokens") is not None:
        extra["max_tokens"] = generation["max_tokens"]
    return OpenRouterChat(
        model=config["model"], base_url=BASE_URL, api_key=key, temperature=generation.get("temperature", 0),
        seed=generation.get("seed"), use_responses_api=False, max_retries=0, timeout=REQUEST_TIMEOUT_S,
        extra_body=extra, tags=[f"subagen:{subagent}"],
    )


def _finish_reason(response) -> str | None:
    messages = getattr(response, "result", None) or [response]
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return (message.response_metadata or {}).get("finish_reason")
    return None


class TruncationGuard(AgentMiddleware):
    """Panggilan model yang terpotong di max_tokens dicatat TRUNCATED dan diulang sekali; bila terpotong lagi, baris
    dihentikan (TruncatedOutput): label klasifikasi valid terakhir tetap dipakai (status ok/verification_failed/
    verification_skipped), tanpa klasifikasi valid -> PARSE_ERROR. Dipasang di LUAR ModelRetryMiddleware, jadi ulangan
    kegagalan layanan terjadi di dalam setiap percobaan (seperti C) dan panggilan terpotong diulang tepat sekali."""

    def __init__(self, subagent: str):
        super().__init__()
        self.subagent = subagent

    @property
    def name(self) -> str:
        return f"TruncationGuard[{self.subagent}]"

    def wrap_model_call(self, request, handler):
        for attempt in (1, 2):
            response = handler(request)
            if _finish_reason(response) != "length":
                return response
            ctx = context.current()
            with ctx.lock:
                ctx.truncations.append({"subagen": self.subagent, "percobaan": attempt, "putaran": ctx.verification_round})
        raise TruncatedOutput(f"{self.subagent}: keluaran terpotong di max_tokens dua kali berturut-turut (TRUNCATED)")


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


RESPONSE_FORMAT = {"type": "json_schema", "json_schema": {"name": "klasifikasi_log", "strict": True, "schema": OUTPUT_SCHEMA}}


def build_classifier(model, sleep=time.sleep) -> RunnableLambda:
    """response_format dikirim lewat extra_body (digabung dengan routing dan max_tokens model), bukan argumen
    response_format: argumen itu membuat langchain-openai memakai chat.completions.parse(), yang melempar
    LengthFinishReasonError pada keluaran terpotong sehingga TRUNCATED tidak dapat dicatat dan diulang (temuan review
    2026-10-08). Badan permintaan tetap sama dengan C (response_format json_schema ketat)."""
    structured = model.bind(extra_body={**(getattr(model, "extra_body", None) or {}), "response_format": RESPONSE_FORMAT})

    def run(state: dict, config: RunnableConfig) -> dict:
        ctx = context.current()
        messages = [SystemMessage(CLASSIFIER_PROMPT), HumanMessage(classifier_input(ctx))]
        output, reason = None, "tidak ada percobaan"
        for attempt in range(1, CLASSIFIER_ATTEMPTS + 1):
            reply = invoke_with_retries(structured, messages, as_subagent(config, "klasifikasi"), sleep)
            output, reason = parse_output(reply.content)
            finish = (reply.response_metadata or {}).get("finish_reason")
            if finish == "length":  # terpotong di max_tokens: TRUNCATED, diulang sekali seperti C
                with ctx.lock:
                    ctx.truncations.append({"subagen": "klasifikasi", "percobaan": attempt, "putaran": ctx.verification_round})
                output, reason = None, "TRUNCATED: finish_reason length"
            elif output is not None and finish not in (None, "stop"):
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
        with ctx.lock:
            index, latest = len(ctx.classifications), ctx.latest_classification()
        schema = json.loads(schema_check.invoke({}, cfg))
        missing = []
        if schema["valid"]:
            for item in latest["evidence"]:
                if not json.loads(evidence_exists.invoke({"item": item}, cfg))["ada"]:
                    missing.append(item)
        verdict = deterministic_verdict(schema, missing)
        with ctx.lock:
            verdict["putaran"] = len(ctx.verdicts) + 1
            verdict["klasifikasi_ke"] = index
            ctx.verdicts.append(verdict)
        return {"messages": [AIMessage(content=json.dumps({k: verdict[k] for k in ("lolos", "alasan", "putaran")},
                                                          ensure_ascii=False))]}

    return RunnableLambda(run, name="verifikasi")


SEQUENTIAL_SUBAGENTS = ("klasifikasi", "verifikasi")
EVIDENCE_SUBAGENTS = ("parser", "analisis_payload")
BATCH_MESSAGE = ("Panggil klasifikasi dan verifikasi satu per satu, tidak dalam satu pesan; hanya pemanggilan pertama di "
                 "pesan itu yang dijalankan.")
AFTER_EVIDENCE_MESSAGE = ("Panggil klasifikasi dalam pesan terpisah setelah parser dan analisis_payload di pesan ini selesai, "
                          "agar Klasifikasi menerima keluaran alatnya.")


def _batch(state, call_id: str) -> list[dict]:
    """Pemanggilan task pada pesan AI yang memuat pemanggilan `call_id` (urutan daftar)."""
    messages = (state or {}).get("messages", []) if isinstance(state, dict) else getattr(state, "messages", [])
    for message in reversed(messages or []):
        calls = getattr(message, "tool_calls", None) or []
        if any(c.get("id") == call_id for c in calls):
            return [c for c in calls if c.get("name") == "task"]
    return []


def _batch_position(state, call_id: str) -> int:
    """Urutan pemanggilan klasifikasi/verifikasi ini di antara pemanggilan sejenis pada pesan AI yang sama (0 = pertama)."""
    ordered = [c["id"] for c in _batch(state, call_id)
               if (c.get("args") or {}).get("subagent_type") in SEQUENTIAL_SUBAGENTS]
    return ordered.index(call_id) if call_id in ordered else 0


def _with_evidence_subagents(state, call_id: str) -> bool:
    """Apakah pesan yang sama juga memanggil parser/analisis_payload (yang akan berjalan paralel)."""
    return any((c.get("args") or {}).get("subagent_type") in EVIDENCE_SUBAGENTS for c in _batch(state, call_id))


class VerificationRoundGuard(AgentMiddleware):
    """Menahan pemanggilan sub-agen yang melanggar batas putaran (keputusan penulis: maksimum 2 putaran).

    Pemanggilan klasifikasi/verifikasi dijalankan berurutan: bila satu pesan orkestrator memuat lebih dari satu, hanya yang
    pertama (urutan daftar) dijalankan; sisanya ditahan. Klasifikasi yang dipanggil dalam pesan yang sama dengan parser atau
    analisis_payload ditahan sampai pesan berikutnya (masukannya tidak bergantung pada urutan thread). Pemeriksaan dan
    eksekusinya dikunci per baris agar putusan guard tidak bergantung pada urutan thread (alat paralel)."""

    def wrap_tool_call(self, request, handler):
        call = request.tool_call
        args = call.get("args") or {}
        if call.get("name") != "task":
            return handler(request)
        target = args.get("subagent_type")
        if target not in SEQUENTIAL_SUBAGENTS:
            return self._block_or_run(request, handler, self.blocked(args), args)
        ctx = context.current()
        if _batch_position(request.state, call["id"]) > 0:
            return self._block_or_run(request, handler, BATCH_MESSAGE, args)
        if target == "klasifikasi" and _with_evidence_subagents(request.state, call["id"]):
            return self._block_or_run(request, handler, AFTER_EVIDENCE_MESSAGE, args)
        with ctx.procedure_lock:
            return self._block_or_run(request, handler, self.blocked(args), args)

    @staticmethod
    def _block_or_run(request, handler, blocked: str | None, args: dict):
        if not blocked:
            return handler(request)
        ctx = context.current()
        with ctx.lock:
            ctx.guard_blocks.append({"subagen": args.get("subagent_type"), "alasan": blocked,
                                     "putaran": ctx.verification_round})
        return ToolMessage(content=blocked, tool_call_id=request.tool_call["id"], name="task")

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
         "middleware": [TruncationGuard("parser"), retry_middleware(), limit_middleware()]},
        {"name": "analisis_payload",
         "description": "Mendekode payload dan mencari indikator serangan atau pemindaian pada path, query, user "
                        "agent, dan referer dengan pencocok pola CRS, indikator pemindai, dan basis pengetahuan OWASP.",
         "system_prompt": PAYLOAD_PROMPT, "tools": PAYLOAD_TOOLS, "model": make_model(config, "analisis_payload", key),
         "middleware": [TruncationGuard("analisis_payload"), retry_middleware(), limit_middleware()]},
        {"name": "klasifikasi", "description": "Menetapkan satu dari enam kelas berdasarkan bukti yang dikumpulkan alat; "
                                               "keluaran JSON {label, confidence, evidence, explanation}.",
         "runnable": build_classifier(make_model(config, "klasifikasi", key))},
        {"name": "verifikasi", "description": "Memeriksa skema keluaran klasifikasi terakhir dan keberadaan literal setiap "
                                              "evidence di baris log; menjawab lolos atau tolak beserta alasan.",
         "runnable": build_verifier()},
    ]
    return create_deep_agent(
        model=make_model(config, "orkestrator", key), tools=[], system_prompt=ORCHESTRATOR_PROMPT, subagents=subagents,
        middleware=[TodoListMiddleware(), VerificationRoundGuard(), ProcedureGuard(), TruncationGuard("orkestrator"),
                    retry_middleware()], name="orkestrator",
    )
