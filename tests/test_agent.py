import ast
import json
import uuid
from collections import Counter
from pathlib import Path

import httpx
import openai
import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel, GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, LLMResult

from src.agent import context
from src.agent import graph as g
from src.agent import run as ar
from src.agent import tools as t
from src.agent.context import CallLogger, RowContext
from src.agent.prompts import CLASSIFIER_PROMPT, MASUKAN_SECTION, classifier_input
from src.baselines.llm_prompt import SYSTEM_PROMPT

AGENT_DIR = Path(__file__).resolve().parents[1] / "src" / "agent"
LOG = ('172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "GET /index.php?id=1%27%20UNION%20SELECT%201 HTTP/1.1" 200 5 '
       '"-" "sqlmap/1.4"')
GOOD = {"label": "SQLI", "confidence": 0.9, "evidence": ["UNION SELECT"], "explanation": "kueri UNION di parameter id"}


@pytest.fixture
def ctx():
    row = RowContext("run-1", "srbh-1", LOG)
    context.set_current(row)
    yield row
    context.set_current(None)


def _verdict(lolos, klasifikasi_ke, putaran):
    return {"lolos": lolos, "alasan": [] if lolos else ["evidence tidak ditemukan"], "lolos_menurut_llm": lolos,
            "putaran": putaran, "klasifikasi_ke": klasifikasi_ke}


def test_agent_never_imports_the_evidence_gate():
    for path in AGENT_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            assert not any("gate" in n.split(".") for n in names), f"{path.name} mengimpor modul gerbang bukti"


def test_classifier_prompt_is_the_single_llm_prompt_plus_the_masukan_section():
    """Keputusan K3: prompt Klasifikasi E = prompt C + bagian MASUKAN (disisipkan sebelum SKEMA KELUARAN)."""
    assert CLASSIFIER_PROMPT.replace(MASUKAN_SECTION + "\n\n", "") == SYSTEM_PROMPT
    assert CLASSIFIER_PROMPT.index("MASUKAN") > CLASSIFIER_PROMPT.index("ATURAN")
    assert CLASSIFIER_PROMPT.index("MASUKAN") < CLASSIFIER_PROMPT.index("SKEMA KELUARAN")
    assert "2. Setiap item evidence harus berupa potongan literal dari baris log (sebelum atau sesudah dekode)." in CLASSIFIER_PROMPT
    assert MASUKAN_SECTION.endswith(
        "Evidence ditulis persis seperti di baris log, tanpa awalan nama kolom dan tanpa menyalin pesan alat.")
    assert "yang dilaporkan alat" not in CLASSIFIER_PROMPT


def test_single_llm_prompt_is_unchanged_by_the_shared_rules_refactor():
    from src.baselines.llm_prompt import prompt_sha256

    assert prompt_sha256().startswith("3afd24b1e993")  # hash run C penuh dan pilot v2


def test_parser_tools_read_the_true_log_from_context(ctx):
    parsed = json.loads(t.parse_log_line.invoke({}))
    assert parsed["terurai"] and parsed["method"] == "GET" and parsed["path"] == "/index.php"
    assert parsed["query"] == "id=1%27%20UNION%20SELECT%201" and parsed["user_agent"] == "sqlmap/1.4"
    assert "time" not in parsed and "protocol" not in parsed
    assert json.loads(t.validate_fields.invoke({})) == {"valid": True, "masalah": []}


def test_validate_fields_flags_unparseable_lines():
    context.set_current(RowContext("run-1", "srbh-2", "bukan baris log"))
    try:
        assert json.loads(t.validate_fields.invoke({}))["valid"] is False
    finally:
        context.set_current(None)


def test_decoders_take_parts_of_the_true_log_not_free_text():
    log = ('1.2.3.4 - - [01/Jan/2020:00:00:00 +0000] "GET /a%253Cb+c?q=%26lt%3Bscript%26gt%3B HTTP/1.1" 200 5 "-" "UA"')
    row = RowContext("run-1", "srbh-3", log)
    context.set_current(row)
    try:
        assert json.loads(t.url_decode_recursive.invoke({"bagian": "path"}))["lapis"] == ["/a%253Cb+c", "/a%3Cb c", "/a<b c"]
        assert json.loads(t.html_decode.invoke({"bagian": "query"}))["hasil"] == ["q=%26lt%3Bscript%26gt%3B", "q=<script>"]
        assert len(row.decoded) == 1 and len(row.html_decoded) == 1
        with pytest.raises(Exception):
            t.url_decode_recursive.invoke({"bagian": "GET request to /a with user agent UA"})
    finally:
        context.set_current(None)


def test_lookup_owasp_reads_the_static_knowledge_base(ctx):
    entry = json.loads(t.lookup_owasp.invoke({"kelas": "sqli"}))["SQLI"]
    assert entry["ciri"].startswith("' OR 1=1") and any("CWE-89" in r for r in entry["rujukan"])
    assert "galat" in json.loads(t.lookup_owasp.invoke({"kelas": "DDOS"}))
    assert set(t._knowledge_base()) == {"SQLI", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "WEB_SCANNING", "NORMAL"}


def test_verifier_tools_check_literal_evidence_and_schema(ctx):
    assert json.loads(t.evidence_exists.invoke({"item": "UNION SELECT"}))["ada"] is True  # sesudah dekode
    assert json.loads(t.evidence_exists.invoke({"item": "DROP TABLE"}))["ada"] is False
    assert json.loads(t.schema_check.invoke({}))["valid"] is False
    ctx.classifications.append(dict(GOOD))
    assert json.loads(t.schema_check.invoke({}))["valid"] is True
    ctx.classifications.append({"_parse_error": "bukan JSON"})
    assert json.loads(t.schema_check.invoke({})) == {"valid": False, "alasan": "bukan JSON"}


@pytest.mark.slow
def test_pattern_match_and_scanner_indicators_use_crs_without_class_labels(ctx):
    hits = json.loads(t.pattern_match.invoke({}))["aturan_cocok"]
    assert any(str(h["aturan"]).startswith("942") for h in hits)
    assert all(set(h) == {"aturan", "pesan", "tag", "variabel", "cocok"} for h in hits)
    assert not any(label in json.dumps(hits) for label in ("SQLI", "WEB_SCANNING", "CMD_INJECTION"))
    indicators = json.loads(t.scanner_indicators.invoke({}))
    assert "sqlmap" in indicators["ua_pemindai"] and indicators["metode_non_standar"] is None


def test_classifier_input_is_assembled_from_tool_outputs_and_rejection_reasons(ctx):
    ctx.parsed, ctx.pattern_hits = {"terurai": True, "path": "/index.php"}, [{"aturan": "942100"}]
    text = classifier_input(ctx)
    assert text.startswith(f"<log>{LOG}</log>") and "<pattern_hits>" in text and "umpan_balik" not in text
    ctx.classifications.append(dict(GOOD))
    ctx.verdicts.append(_verdict(False, 1, 1))
    assert "<umpan_balik_verifikasi>" in classifier_input(ctx)


def test_classifier_retries_once_then_records_parse_error(ctx):
    node = g.build_classifier(FakeListChatModel(responses=["bukan json", json.dumps(GOOD)]))
    reply = node.invoke({"messages": []})
    assert ctx.classifications == [GOOD] and json.loads(reply["messages"][-1].content) == GOOD
    node = g.build_classifier(FakeListChatModel(responses=["x", "y"]))
    node.invoke({"messages": []})
    assert "_parse_error" in ctx.classifications[-1]


def test_verifier_is_deterministic_and_logs_its_tool_calls(ctx, tmp_path):
    """Keputusan K2: Verifikasi tanpa LLM; hanya schema_check dan evidence_exists yang mengikat."""
    path = tmp_path / "calls.jsonl"
    logger = CallLogger(path)
    node = g.build_verifier()
    config = {"callbacks": [ar.CallRecorder(logger)]}
    ctx.classifications.append(dict(GOOD))
    out = json.loads(node.invoke({"messages": []}, config)["messages"][-1].content)
    assert out["lolos"] and ctx.verdicts[-1]["skema_valid"] and ctx.verdicts[-1]["evidence_hilang"] == []
    ctx.classifications.append({**GOOD, "evidence": ["UNION SELECT", "path: /index.php", "DROP TABLE"]})
    node.invoke({"messages": []}, config)
    v = ctx.verdicts[-1]
    assert not v["lolos"] and v["evidence_hilang"] == ["path: /index.php", "DROP TABLE"]
    assert v["alasan"] == ["evidence tidak ditemukan di baris log: path: /index.php; DROP TABLE"]
    assert (v["putaran"], v["klasifikasi_ke"]) == (2, 2) and "lolos_menurut_llm" not in v
    ctx.classifications.append({"_parse_error": "bukan JSON"})
    node.invoke({"messages": []}, config)
    assert ctx.verdicts[-1]["alasan"] == ["schema_check gagal: bukan JSON"] and not ctx.verdicts[-1]["skema_valid"]
    logger.close()
    records = [json.loads(x) for x in path.read_text().splitlines()]
    assert {r["jenis"] for r in records} == {"alat"} and {r["subagen"] for r in records} == {"verifikasi"}
    assert [r["alat"] for r in records] == ["schema_check", "evidence_exists", "schema_check", "evidence_exists",
                                            "evidence_exists", "evidence_exists", "schema_check"]
    assert ctx.llm_calls == 0


def test_guard_enforces_order_and_two_verification_rounds(ctx):
    blocked = g.VerificationRoundGuard.blocked
    assert blocked({"subagent_type": "verifikasi"})  # belum ada klasifikasi
    assert blocked({"subagent_type": "klasifikasi"}) is None
    ctx.classifications.append(dict(GOOD))
    assert blocked({"subagent_type": "verifikasi"}) is None
    ctx.verdicts.append(_verdict(False, 1, 1))
    assert blocked({"subagent_type": "verifikasi"})  # klasifikasi terakhir sudah diverifikasi
    assert blocked({"subagent_type": "klasifikasi"}) is None  # putaran kedua boleh
    ctx.classifications.append(dict(GOOD))
    ctx.verdicts.append(_verdict(False, 2, 2))
    assert "Batas 2 putaran" in blocked({"subagent_type": "klasifikasi"})
    assert blocked({"subagent_type": "parser"}) is None


def test_guard_points_back_to_classification_after_a_rejection(ctx):
    ctx.classifications.append(dict(GOOD))
    ctx.verdicts.append(_verdict(False, 1, 1))
    assert "DITOLAK" in g.VerificationRoundGuard.blocked({"subagent_type": "verifikasi"})


def test_procedure_reminder_enforces_return_to_classification(ctx):
    assert "Belum ada keluaran klasifikasi" in g.procedure_reminder(ctx)
    ctx.classifications.append(dict(GOOD))
    assert "belum diverifikasi" in g.procedure_reminder(ctx)
    ctx.verdicts.append(_verdict(False, 1, 1))
    assert "Panggil sub-agen klasifikasi" in g.procedure_reminder(ctx)
    ctx.classifications.append(dict(GOOD))
    assert "belum diverifikasi" in g.procedure_reminder(ctx)
    ctx.verdicts.append(_verdict(False, 2, 2))
    assert g.procedure_reminder(ctx) is None  # dua putaran habis: boleh berhenti dengan label terakhir


def test_procedure_guard_sends_the_orchestrator_back_to_the_model_with_a_cap(ctx):
    guard = g.ProcedureGuard()
    assert guard.after_model({"messages": [AIMessage("", tool_calls=[{"name": "task", "args": {}, "id": "1"}])]}, None) is None
    for _ in range(g.MAX_REMINDERS):
        out = guard.after_model({"messages": [AIMessage("selesai")]}, None)
        assert out["jump_to"] == "model" and out["messages"][0].content.startswith("PENGINGAT PROSEDUR")
    assert guard.after_model({"messages": [AIMessage("selesai")]}, None) is None
    assert len(ctx.reminders) == g.MAX_REMINDERS
    ctx.classifications.append(dict(GOOD))
    ctx.verdicts.append(_verdict(True, 1, 1))
    ctx.reminders.clear()
    assert guard.after_model({"messages": [AIMessage("selesai")]}, None) is None


def test_subagent_config_attributes_nested_calls():
    config = g.as_subagent({"metadata": {"lc_agent_name": "orkestrator"}, "tags": ["subagen:orkestrator", "x"]}, "verifikasi")
    assert config["metadata"]["lc_agent_name"] == "verifikasi" and config["tags"] == ["x", "subagen:verifikasi"]
    assert ar._agent_name(config["tags"], config["metadata"]) == "verifikasi"


def test_guard_blocks_reclassification_after_a_pass(ctx):
    ctx.classifications.append(dict(GOOD))
    ctx.verdicts.append(_verdict(True, 1, 1))
    assert "sudah lolos" in g.VerificationRoundGuard.blocked({"subagent_type": "klasifikasi"})


@pytest.mark.parametrize("classifications, verdicts, label, status, used", [
    ([], [], "PARSE_ERROR", "PARSE_ERROR", None),
    ([{"_parse_error": "bukan JSON"}], [], "PARSE_ERROR", "PARSE_ERROR", None),
    ([GOOD], [_verdict(True, 1, 1)], "SQLI", "ok", 1),
    ([GOOD], [], "SQLI", "verification_skipped", 1),
    ([{**GOOD, "label": "XSS"}, GOOD], [_verdict(False, 1, 1), _verdict(False, 2, 2)], "SQLI", "verification_failed", 2),
    ([{**GOOD, "label": "XSS"}, GOOD], [_verdict(False, 1, 1), _verdict(True, 2, 2)], "SQLI", "ok", 2),
    ([GOOD, {"_parse_error": "x"}], [_verdict(False, 1, 1), _verdict(False, 2, 2)], "SQLI", "verification_failed", 1),
])
def test_assemble_uses_the_latest_valid_classification(classifications, verdicts, label, status, used):
    row = RowContext("run-1", "srbh-1", LOG, classifications=list(classifications), verdicts=list(verdicts))
    out = ar.assemble(row, "run-1", 1.0, "selesai")
    assert (out["label"], out["status"], out.get("klasifikasi_dipakai")) == (label, status, used)
    assert out["verifikasi"]["penolakan"] == sum(not v["lolos"] for v in verdicts)
    assert out["verifikasi"]["verification_failed"] == (status == "verification_failed")
    assert out["riwayat_label"] == [c.get("label", "PARSE_ERROR") for c in classifications]


def test_assemble_keeps_label_but_records_recursion_limit():
    row = RowContext("run-1", "srbh-1", LOG, classifications=[GOOD])
    out = ar.assemble(row, "run-1", 1.0, None, error="batas rekursi orkestrator (80 langkah) tercapai")
    assert out["label"] == "SQLI" and out["status"] == "verification_skipped" and "batas rekursi" in out["detail"]


def _completion(content="", tool_calls=None, **extra):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"id": "gen-1", "object": "chat.completion", "created": 0, "model": "openai/gpt-4.1-nano",
            "provider": "OpenAI", "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12, "cost": 0.000002}, **extra}


def test_http_200_failures_are_service_errors_like_the_single_llm():
    model = g.OpenRouterChat(model="openai/gpt-4.1-nano", api_key="sk-test", base_url=g.BASE_URL)
    with pytest.raises(g.ServiceFailure):
        model._create_chat_result({"error": {"message": "upstream", "code": 502}})
    with pytest.raises(g.ServiceFailure):
        model._create_chat_result(_completion(""))
    calls = [{"id": "c1", "type": "function", "function": {"name": "task", "arguments": "{}"}}]
    assert model._create_chat_result(_completion("", tool_calls=calls)).generations[0].message.tool_calls
    result = model._create_chat_result(_completion("halo"))
    assert result.llm_output["upstream_provider"] == "OpenAI" and result.llm_output["token_usage"]["cost"] == 0.000002


def _status_error(cls, code):
    request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    return cls("x", response=httpx.Response(code, request=request), body=None)


def test_service_error_policy_matches_the_single_llm():
    assert g.is_service_error(g.ServiceFailure("x"))
    assert g.is_service_error(_status_error(openai.RateLimitError, 429))
    assert g.is_service_error(_status_error(openai.InternalServerError, 502))
    assert not g.is_service_error(_status_error(openai.AuthenticationError, 401))
    assert not g.is_service_error(_status_error(openai.APIStatusError, 402))
    assert not g.is_service_error(ValueError("bug"))
    sleeps = []

    class Flaky:
        n = 0

        def invoke(self, messages, config):
            self.n += 1
            if self.n < 3:
                raise g.ServiceFailure("konten kosong")
            return "ok"

    assert g.invoke_with_retries(Flaky(), [], None, sleeps.append) == "ok" and sleeps == [2, 4]
    retry = g.retry_middleware()
    assert (retry.max_retries, retry.initial_delay, retry.max_delay, retry.jitter) == (6, 2.0, 64.0, False)


def test_recorder_logs_llm_and_tool_calls_with_subagent_and_cost(ctx, tmp_path):
    path = tmp_path / "calls.jsonl"
    logger = CallLogger(path)
    rec = ar.CallRecorder(logger)
    tools = [{"type": "function", "function": {"name": "parse_log_line"}}]
    result = LLMResult(generations=[[ChatGeneration(message=AIMessage("ok", response_metadata={"finish_reason": "stop"}))]],
                       llm_output={"token_usage": {"prompt_tokens": 100, "completion_tokens": 5, "cost": 0.00002},
                                   "model_name": "openai/gpt-4.1-nano-2025-04-14", "upstream_provider": "OpenAI"})
    for _ in range(2):
        run_id = uuid.uuid4()
        rec.on_chat_model_start(None, [[SystemMessage("sistem"), HumanMessage("halo")]], run_id=run_id,
                                tags=["subagen:parser"], invocation_params={"model": "m", "tools": tools,
                                                                            "api_key": "sk-or-v1-rahasia"})
        rec.on_llm_end(result, run_id=run_id)
    tool_run = uuid.uuid4()
    rec.on_tool_start({"name": "pattern_match"}, "{}", run_id=tool_run, metadata={"lc_agent_name": "analisis_payload"})
    rec.on_tool_end("{\"jumlah\": 0}", run_id=tool_run)
    logger.close()
    records = [json.loads(x) for x in path.read_text().splitlines()]
    assert [r["jenis"] for r in records] == ["prompt_sistem", "definisi_alat", "llm", "llm", "alat"]
    llm = records[2]
    assert llm["subagen"] == "parser" and llm["cost_usd"] == 0.00002 and llm["prompt"][0]["sha256"] == records[0]["sha256"]
    assert records[4]["subagen"] == "analisis_payload" and records[4]["alat"] == "pattern_match"
    assert ctx.llm_calls == 2 and ctx.prompt_tokens == 200 and ctx.tool_calls == 1
    assert "rahasia" not in path.read_text()


def test_safe_error_hides_key_like_values():
    assert "sk-or-v1-abcdef" not in ar.safe_error(RuntimeError("bad key sk-or-v1-abcdef123"))
    assert ar.safe_error(_status_error(openai.AuthenticationError, 401)) == "AuthenticationError (HTTP 401)"


class FakeAgent:
    """Agen tiruan: baris kedua memicu galat API sekali (untuk menguji --resume)."""

    def __init__(self, fail_on=None):
        self.fail_on = fail_on

    def invoke(self, state, config):
        ctx = context.current()
        if ctx.row_id == self.fail_on:
            raise _status_error(openai.APIStatusError, 402)
        ctx.classifications.append(dict(GOOD))
        ctx.verdicts.append({**_verdict(True, 1, 1)})
        return {"messages": [AIMessage(json.dumps(GOOD))]}


def test_run_writes_incrementally_and_resumes_after_api_abort(tmp_path, monkeypatch):
    rows = [{"id": f"srbh-{i}", "raw_log_masked": LOG} for i in range(3)]
    monkeypatch.setattr(ar, "method_rows", lambda path, split: (rows, ar.SAMPLE_PATH))
    monkeypatch.setattr(ar, "load_llm_config", lambda: {"model": "openai/gpt-4.1-nano"})
    monkeypatch.setattr(ar, "sha256_file", lambda path: "x")
    monkeypatch.setattr(ar, "run_info", lambda method, model, **extra: {"run_id": "run-1", "git_dirty": False, **extra})
    calls = tmp_path / "calls.jsonl"
    with pytest.raises(ar.RunAborted):
        ar.run(out_dir=tmp_path, inputs_path=ar.SAMPLE_PATH, calls_path=calls, agent=FakeAgent(fail_on="srbh-1"))
    assert [json.loads(x)["id"] for x in (tmp_path / "agent.partial.jsonl").read_text().splitlines()] == ["srbh-0"]
    info = ar.run(out_dir=tmp_path, inputs_path=ar.SAMPLE_PATH, calls_path=calls, resume=True, agent=FakeAgent())
    final = [json.loads(x) for x in (tmp_path / "agent.jsonl").read_text().splitlines()]
    assert [p["id"] for p in final] == ["srbh-0", "srbh-1", "srbh-2"] and {p["status"] for p in final} == {"ok"}
    assert info["totals"]["status_detail"]["ok"] == 3 and len(info["resumed"]) == 1
    assert any(json.loads(x)["jenis"] == "galat_api" for x in calls.read_text().splitlines())
    assert not (tmp_path / "agent.partial.jsonl").exists()


def test_remote_tracing_is_disabled_whatever_the_environment(monkeypatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    ar.disable_remote_tracing()
    import os
    assert all(os.environ[name] == "false" for name in ar.TRACING_VARS)


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def _task(subagent, n):
    return AIMessage("", tool_calls=[{"name": "task", "args": {"description": "x", "subagent_type": subagent},
                                      "id": f"c{n}"}])


def test_rejected_verification_returns_to_classification_in_the_real_graph(ctx):
    """Graf deepagents asli dengan orkestrator tiruan: berhenti setelah penolakan pertama -> pengingat -> putaran 2;
    klasifikasi ketiga ditahan; tidak ada pengingat setelah dua putaran."""
    from deepagents import create_deep_agent
    from langchain.agents.middleware import TodoListMiddleware
    from langchain_core.runnables import RunnableLambda

    def classify(state):
        context.current().classifications.append(dict(GOOD))
        return {"messages": [AIMessage(json.dumps(GOOD))]}

    def verify(state):
        c = context.current()
        c.verdicts.append({"lolos": False, "alasan": ["x"], "putaran": len(c.verdicts) + 1,
                           "klasifikasi_ke": len(c.classifications)})
        return {"messages": [AIMessage("ditolak")]}

    script = [_task("klasifikasi", 1), _task("verifikasi", 2), AIMessage("selesai 1"),
              _task("klasifikasi", 3), _task("verifikasi", 4), _task("klasifikasi", 5), AIMessage("selesai 2")]
    agent = create_deep_agent(
        model=_ScriptedModel(messages=iter(script)), tools=[], system_prompt="s",
        subagents=[{"name": "klasifikasi", "description": "k", "runnable": RunnableLambda(classify)},
                   {"name": "verifikasi", "description": "v", "runnable": RunnableLambda(verify)}],
        middleware=[TodoListMiddleware(), g.VerificationRoundGuard(), g.ProcedureGuard()], name="orkestrator")
    state = agent.invoke({"messages": [HumanMessage("mulai")]}, {"recursion_limit": 40})
    assert len(ctx.classifications) == 2 and len(ctx.verdicts) == 2 and len(ctx.reminders) == 1
    assert [b["subagen"] for b in ctx.guard_blocks] == ["klasifikasi"]
    assert state["messages"][-1].content == "selesai 2"
    out = ar.assemble(ctx, "run-1", 1.0, "selesai 2")
    assert out["status"] == "verification_failed" and out["klasifikasi_dipakai"] == 2


class _RecordingModel(GenericFakeChatModel):
    """Model tiruan yang melapor sebagai penyedia openai (seperti OpenRouterChat) dan mencatat alat yang dilihatnya."""

    seen_tools: list = []
    name_tag: str = ""

    def bind_tools(self, tools, **kwargs):
        names = sorted(t.name if hasattr(t, "name") else (t.get("name") or t["function"]["name"]) for t in tools)
        _RecordingModel.seen_tools.append((self.name_tag, names))
        return self

    def _get_ls_params(self, stop=None, **kwargs):
        return {"ls_provider": "openai", "ls_model_name": "openai/gpt-4.1-nano", "ls_model_type": "chat"}


def test_openrouter_model_resolves_to_the_openai_profile():
    model = g.make_model({"model": "openai/gpt-4.1-nano", "generation": {"temperature": 0, "seed": 42},
                          "provider_routing": {"order": ["openai"]}}, "parser", "sk-test")
    assert model._get_ls_params()["ls_provider"] == "openai"


def test_full_graph_offline_sees_only_specified_tools_and_delegates_to_all_four(ctx, monkeypatch, tmp_path):
    """K1: orkestrator hanya task + write_todos; sub-agen hanya alatnya sendiri. K2: verifikasi tanpa LLM."""
    _RecordingModel.seen_tools = []
    scripts = {
        "orkestrator": [_task("parser", 1), _task("analisis_payload", 2), _task("klasifikasi", 3), _task("verifikasi", 4),
                        AIMessage(json.dumps(GOOD))],
        "parser": [AIMessage("kolom valid")],
        "analisis_payload": [AIMessage("ada UNION SELECT")],
        "klasifikasi": [AIMessage(json.dumps(GOOD))],
    }

    def fake_model(config, subagent, key):
        assert subagent in scripts, f"model untuk {subagent} tidak boleh dibuat (verifikasi tanpa LLM)"
        return _RecordingModel(messages=iter(scripts[subagent]), name_tag=subagent)

    monkeypatch.setattr(g, "make_model", fake_model)
    monkeypatch.setattr(g, "api_key", lambda: "sk-test")
    agent = g.build_agent({"model": "openai/gpt-4.1-nano"})
    logger = CallLogger(tmp_path / "calls.jsonl")
    agent.invoke({"messages": [HumanMessage(f"<log>{LOG}</log>")]},
                 {"recursion_limit": 40, "callbacks": [ar.CallRecorder(logger)]})
    logger.close()
    records = [json.loads(x) for x in (tmp_path / "calls.jsonl").read_text().splitlines()]
    llm_by_agent = Counter(r["subagen"] for r in records if r["jenis"] == "llm")
    assert llm_by_agent == {"orkestrator": 5, "parser": 1, "analisis_payload": 1, "klasifikasi": 1}
    assert {r["alat"] for r in records if r["jenis"] == "alat" and r["subagen"] == "verifikasi"} == {
        "schema_check", "evidence_exists"}
    seen = {}
    for tag, names in _RecordingModel.seen_tools:
        seen.setdefault(tag, set()).update(names)
    assert seen["orkestrator"] == {"task", "write_todos"}
    assert seen["parser"] == {"parse_log_line", "validate_fields"}
    assert seen["analisis_payload"] == {"url_decode_recursive", "html_decode", "pattern_match", "scanner_indicators",
                                        "lookup_owasp"}
    assert not (set().union(*seen.values()) & g.EXCLUDED_TOOLS)
    assert ctx.verdicts[-1]["lolos"] and ctx.llm_calls == 8
    out = ar.assemble(ctx, "run-1", 1.0, "selesai")
    assert out["status"] == "ok" and out["label"] == "SQLI" and out["llm_calls"] == 8
    assert out["delegasi"] == {"parser": True, "analisis_payload": True, "klasifikasi": True, "verifikasi": True,
                               "keempat_subagen": True}


def _graph_with_scripts(monkeypatch, scripts):
    def fake_model(config, subagent, key):
        return _RecordingModel(messages=iter(scripts[subagent]), name_tag=subagent)

    monkeypatch.setattr(g, "make_model", fake_model)
    monkeypatch.setattr(g, "api_key", lambda: "sk-test")
    return g.build_agent({"model": "openai/gpt-4.1-nano"})


def _batch(*calls):
    return AIMessage("", tool_calls=[{"name": "task", "args": {"description": "x", "subagent_type": s}, "id": f"b{k}-{s}"}
                                     for k, s in enumerate(calls)])


@pytest.mark.parametrize("attempt", range(5))
def test_klasifikasi_and_verifikasi_in_one_message_run_one_at_a_time(ctx, monkeypatch, attempt):
    """Review v2: pemanggilan paralel tidak boleh melompati aturan putaran. Hanya pemanggilan pertama di pesan yang jalan."""
    bad = {**GOOD, "label": "CMD_INJECTION", "evidence": ["DROP TABLE"]}
    scripts = {"orkestrator": [_task("klasifikasi", 1), _batch("klasifikasi", "verifikasi"), _task("verifikasi", 3),
                               AIMessage("selesai"), _task("klasifikasi", 4), _task("verifikasi", 5), AIMessage("selesai")],
               "parser": [], "analisis_payload": [],
               "klasifikasi": [AIMessage(json.dumps(GOOD)), AIMessage(json.dumps(bad)), AIMessage(json.dumps(GOOD))]}
    agent = _graph_with_scripts(monkeypatch, scripts)
    agent.invoke({"messages": [HumanMessage(f"<log>{LOG}</log>")]}, {"recursion_limit": 60})
    assert [b["alasan"] for b in ctx.guard_blocks] == [g.BATCH_MESSAGE]  # verifikasi di batch ditahan
    assert len(ctx.classifications) == 3 and [v["klasifikasi_ke"] for v in ctx.verdicts] == [2, 3]
    assert [v["lolos"] for v in ctx.verdicts] == [False, True] and len(ctx.reminders) == 1
    out = ar.assemble(ctx, "run-1", 1.0, "selesai")
    assert out["status"] == "ok" and out["klasifikasi_dipakai"] == 3 and out["label"] == "SQLI"


def test_two_verifikasi_calls_in_one_message_use_a_single_round(ctx, monkeypatch):
    scripts = {"orkestrator": [_task("klasifikasi", 1), _batch("verifikasi", "verifikasi"), AIMessage("selesai")],
               "parser": [], "analisis_payload": [], "klasifikasi": [AIMessage(json.dumps(GOOD))]}
    agent = _graph_with_scripts(monkeypatch, scripts)
    agent.invoke({"messages": [HumanMessage(f"<log>{LOG}</log>")]}, {"recursion_limit": 40})
    assert len(ctx.verdicts) == 1 and ctx.verdicts[0]["lolos"] and len(ctx.guard_blocks) == 1


def test_delegation_counts_only_task_calls_that_ran(ctx, monkeypatch, tmp_path):
    """Review v2: task dengan argumen tidak valid (sub-agen tidak jalan) tidak dihitung sebagai delegasi."""
    invalid = AIMessage("", tool_calls=[{"name": "task", "args": {"subagent_type": "parser", "prompt": "x"}, "id": "i1"}])
    scripts = {"orkestrator": [invalid, _task("analisis_payload", 2), _task("klasifikasi", 3), _task("verifikasi", 4),
                               AIMessage("selesai")],
               "parser": [AIMessage("tidak boleh terpakai")], "analisis_payload": [AIMessage("ok")],
               "klasifikasi": [AIMessage(json.dumps(GOOD))]}
    agent = _graph_with_scripts(monkeypatch, scripts)
    logger = CallLogger(tmp_path / "calls.jsonl")
    agent.invoke({"messages": [HumanMessage(f"<log>{LOG}</log>")]},
                 {"recursion_limit": 40, "callbacks": [ar.CallRecorder(logger)]})
    logger.close()
    out = ar.assemble(ctx, "run-1", 1.0, "selesai")
    assert out["delegasi"]["parser"] is False and out["delegasi"]["keempat_subagen"] is False
    assert out["delegasi"]["analisis_payload"] and out["delegasi"]["klasifikasi"] and out["delegasi"]["verifikasi"]
    assert out["alat_dipanggil"].get("task:parser") == 1  # percobaan tetap dihitung sebagai pemanggilan alat


def test_resume_with_different_rows_or_calls_is_refused_before_any_call(tmp_path, monkeypatch):
    rows = [{"id": f"srbh-{i}", "raw_log_masked": LOG} for i in range(3)]
    other = [{"id": f"val-{i}", "raw_log_masked": LOG} for i in range(3)]
    current = {"rows": rows}
    monkeypatch.setattr(ar, "method_rows", lambda path, split: (current["rows"], ar.SAMPLE_PATH))
    monkeypatch.setattr(ar, "load_llm_config", lambda: {"model": "openai/gpt-4.1-nano"})
    monkeypatch.setattr(ar, "sha256_file", lambda path: "x")
    monkeypatch.setattr(ar, "run_info", lambda method, model, **extra: {"run_id": "run-1", "git_dirty": False, **extra})
    calls = tmp_path / "calls.jsonl"
    with pytest.raises(ar.RunAborted):
        ar.run(out_dir=tmp_path, calls_path=calls, agent=FakeAgent(fail_on="srbh-1"))

    class Counting(FakeAgent):
        n = 0

        def invoke(self, state, config):
            Counting.n += 1
            return super().invoke(state, config)

    current["rows"] = other
    with pytest.raises(RuntimeError, match="row_ids_sha256"):
        ar.run(out_dir=tmp_path, calls_path=calls, resume=True, agent=Counting())
    current["rows"] = rows
    with pytest.raises(RuntimeError, match="calls_file"):
        ar.run(out_dir=tmp_path, calls_path=tmp_path / "lain.jsonl", resume=True, agent=Counting())
    assert Counting.n == 0
    ar.run(out_dir=tmp_path, calls_path=calls, resume=True, agent=Counting())
    assert Counting.n == 2


def test_classifier_input_marks_tools_that_never_ran(ctx):
    """Review v2: alat yang tidak dijalankan tidak boleh tampak sebagai 'dijalankan, hasil kosong'."""
    from src.agent.prompts import NOT_RUN

    text = classifier_input(ctx)
    for tag in ("parsed", "decoded", "pattern_hits", "scanner_indicators"):
        assert f"<{tag}>{NOT_RUN}</{tag}>" in text
    ctx.pattern_hits, ctx.scanner_indicators = [], {"ua_pemindai": []}
    text = classifier_input(ctx)
    assert "<pattern_hits>[]</pattern_hits>" in text and NOT_RUN not in text.split("<pattern_hits>")[1]


def test_klasifikasi_batched_with_evidence_subagents_waits_for_the_next_message(ctx, monkeypatch):
    scripts = {"orkestrator": [_batch("analisis_payload", "klasifikasi"), _task("klasifikasi", 2), _task("verifikasi", 3),
                               AIMessage("selesai")],
               "parser": [], "analisis_payload": [AIMessage("selesai analisis")],
               "klasifikasi": [AIMessage(json.dumps(GOOD))]}
    agent = _graph_with_scripts(monkeypatch, scripts)
    agent.invoke({"messages": [HumanMessage(f"<log>{LOG}</log>")]}, {"recursion_limit": 40})
    assert [b["alasan"] for b in ctx.guard_blocks] == [g.AFTER_EVIDENCE_MESSAGE]
    assert len(ctx.classifications) == 1 and ctx.verdicts[-1]["lolos"]
