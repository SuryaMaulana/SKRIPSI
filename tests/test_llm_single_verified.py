import io
import json

import httpx
import pytest

from src.agent import context as agent_context
from src.agent.context import MAX_VERIFICATION_ROUNDS, RowContext
from src.agent.graph import deterministic_verdict
from src.agent.prompts import CLASSIFIER_PROMPT, MASUKAN_SECTION, classifier_input
from src.baselines import llm_single as ls
from src.baselines import llm_single_verified as lv
from src.baselines.llm_prompt import SYSTEM_PROMPT, prompt_sha256, user_message
from src.llm.klasifikasi import SCHEMA_SECTION
from src.llm.openrouter import OpenRouterClient

CONFIG = {"model": "openai/gpt-4.1-nano", "generation": {"temperature": 0, "seed": 42, "max_tokens": 4096},
          "provider_routing": {"order": ["openai"], "allow_fallbacks": False, "require_parameters": True}}
SECRET = "sk-or-v1-test-secret"
RAW = '1.2.3.4 - - [01/Jan/2020:00:00:00 +0000] "GET /?q=1%27%20OR%201=1-- HTTP/1.1" 404 5 "-" "UA"'
ROW = {"id": "srbh-1", "raw_log_masked": RAW}
LITERAL = {"label": "SQLI", "confidence": 0.9, "evidence": ["' OR 1=1--"], "explanation": "tautologi SQL"}
NOT_LITERAL = {"label": "SQLI", "confidence": 0.8, "evidence": ["injeksi SQL pada parameter q"],
               "explanation": "parafrasa"}
NOT_LITERAL_XSS = {"label": "XSS", "confidence": 0.6, "evidence": ["<script>"], "explanation": "tidak ada di log"}
TOOL_TAGS = ("<parsed>", "<decoded>", "<pattern_hits>", "<scanner_indicators>")


def _response(content, finish="stop", cached=0):
    return httpx.Response(200, json={
        "id": "gen-1", "model": "openai/gpt-4.1-nano", "provider": "OpenAI",
        "choices": [{"message": {"content": content}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 900, "completion_tokens": 50, "cost": 0.00011,
                  "prompt_tokens_details": {"cached_tokens": cached}},
    })


def _runner(responses, cls=lv.VerifiedRunner):
    queue = list(responses)
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return queue.pop(0)

    calls = io.StringIO()
    client = OpenRouterClient(SECRET, transport=httpx.MockTransport(handler))
    return cls(client, CONFIG, "run-1", calls, sleep=lambda s: None), calls, sent


def _records(calls):
    return [json.loads(line) for line in calls.getvalue().splitlines()]


def test_first_call_is_byte_identical_to_the_official_single_llm_call():
    runner, _, sent = _runner([_response(json.dumps(LITERAL))])
    runner.classify(ROW)
    single, _, sent_single = _runner([_response(json.dumps(LITERAL))], cls=ls.Runner)
    single.classify(ROW)
    assert sent[0] == sent_single[0]
    assert sent[0]["messages"] == [{"role": "system", "content": SYSTEM_PROMPT},
                                   {"role": "user", "content": user_message(RAW)}]
    assert lv.prompt_sha256() == prompt_sha256()


def test_retry_prompt_is_the_classifier_input_section_without_tool_outputs():
    assert lv.EVIDENCE_SENTENCE == ("Evidence ditulis persis seperti di baris log, tanpa awalan nama kolom dan tanpa "
                                    "menyalin pesan alat.")
    assert lv.EVIDENCE_SENTENCE in CLASSIFIER_PROMPT and lv.EVIDENCE_SENTENCE in lv.RETRY_PROMPT
    assert lv.EVIDENCE_SENTENCE not in SYSTEM_PROMPT  # panggilan pertama tetap prompt LLM tunggal
    assert lv.RETRY_PROMPT == SYSTEM_PROMPT.replace(SCHEMA_SECTION, lv.MASUKAN_ABLASI + "\n\n" + SCHEMA_SECTION)
    assert lv.MASUKAN_ABLASI.splitlines()[1] == ("<log>baris log tersamar</log>; bila ada, <umpan_balik_verifikasi> "
                                                 "berisi alasan penolakan putaran sebelumnya.")
    assert MASUKAN_SECTION.splitlines()[1].startswith("<log>baris log tersamar</log> <parsed>")
    assert not any(tag in lv.RETRY_PROMPT for tag in TOOL_TAGS)
    # sama dengan prompt Klasifikasi E kecuali baris yang mendaftar tag alat
    assert lv.RETRY_PROMPT.replace(lv.MASUKAN_ABLASI.splitlines()[1], MASUKAN_SECTION.splitlines()[1]) == CLASSIFIER_PROMPT


def test_literal_evidence_passes_after_one_call():
    runner, calls, sent = _runner([_response(json.dumps(LITERAL))])
    result = runner.classify(ROW)
    assert result["status"] == "ok" and result["label"] == "SQLI" and result["llm_calls"] == 1
    assert result["verifikasi"]["putaran"] == 1 and result["verifikasi"]["penolakan"] == 0
    assert result["klasifikasi_dipakai"] == 1 and len(sent) == 1
    (rec,) = _records(calls)
    assert rec["putaran_verifikasi"] == 0 and rec["cost_usd"] == 0.00011 and rec["cached_tokens"] == 0
    assert rec["finish_reason"] == "stop" and SECRET not in calls.getvalue()


def test_rejection_retries_once_with_reasons_and_no_tool_outputs():
    runner, calls, sent = _runner([_response(json.dumps(NOT_LITERAL)), _response(json.dumps(LITERAL), cached=768)])
    result = runner.classify(ROW)
    assert result["status"] == "ok" and result["klasifikasi_dipakai"] == 2 and result["llm_calls"] == 2
    assert result["riwayat_label"] == ["SQLI", "SQLI"] and result["evidence"] == LITERAL["evidence"]
    first, second = result["verifikasi"]["putusan"]
    assert not first["lolos"] and first["evidence_hilang"] == NOT_LITERAL["evidence"] and second["lolos"]
    system, user = sent[1]["messages"]
    assert system == {"role": "system", "content": lv.RETRY_PROMPT}
    expected_user = "\n".join([f"<log>{RAW}</log>",
                               "<umpan_balik_verifikasi>" + json.dumps(first["alasan"], ensure_ascii=False)
                               + "</umpan_balik_verifikasi>"])
    assert user == {"role": "user", "content": expected_user}
    assert "evidence tidak ditemukan di baris log: injeksi SQL pada parameter q" in user["content"]
    assert not any(tag in user["content"] for tag in TOOL_TAGS)
    assert {k: v for k, v in sent[1].items() if k != "messages"} == {k: v for k, v in sent[0].items() if k != "messages"}
    assert [r["putaran_verifikasi"] for r in _records(calls)] == [0, 1]  # berbasis 0 seperti log deep agent
    assert result["prompt_tokens"] == 1800 and result["cost_usd"] == pytest.approx(0.00022)


def test_retry_user_message_matches_the_agent_classifier_input_without_tool_sections():
    ctx = RowContext("run-1", "srbh-1", RAW)
    ctx.verdicts.append({"lolos": False, "alasan": ["evidence tidak ditemukan di baris log: x"]})
    agent_input = classifier_input(ctx).splitlines()
    ablation_input = lv.retry_messages(RAW, ["evidence tidak ditemukan di baris log: x"])[1]["content"].splitlines()
    assert ablation_input == [line for line in agent_input if not line.startswith(TOOL_TAGS)]


def test_two_rejections_keep_the_last_label_as_verification_failed():
    runner, _, sent = _runner([_response(json.dumps(NOT_LITERAL)), _response(json.dumps(NOT_LITERAL_XSS))])
    result = runner.classify(ROW)
    assert MAX_VERIFICATION_ROUNDS == 2 and len(sent) == 2
    assert result["status"] == "verification_failed" and result["label"] == "XSS"
    assert result["verifikasi"]["verification_failed"] and result["verifikasi"]["penolakan"] == 2
    assert result["riwayat_label"] == ["SQLI", "XSS"] and result["klasifikasi_dipakai"] == 2


def test_parse_failure_uses_the_single_llm_retry_then_schema_rejection_feeds_the_loop():
    runner, calls, sent = _runner([_response("x"), _response("{"), _response(json.dumps(LITERAL))])
    result = runner.classify(ROW)
    assert result["status"] == "ok" and result["llm_calls"] == 3 and result["klasifikasi_dipakai"] == 2
    first = result["verifikasi"]["putusan"][0]
    assert not first["lolos"] and not first["skema_valid"] and first["alasan"][0].startswith("schema_check gagal: bukan JSON")
    assert [r["outcome"] for r in _records(calls)] == ["parse_error", "parse_error", "ok"]
    assert sent[0] == sent[1] and sent[2]["messages"][0]["content"] == lv.RETRY_PROMPT


def test_no_valid_classification_is_parse_error_and_truncation_is_counted():
    runner, calls, sent = _runner([_response("{", finish="length")] * 4)
    result = runner.classify(ROW)
    assert result["status"] == "PARSE_ERROR" and result["label"] == "PARSE_ERROR" and result["llm_calls"] == 4
    assert result["truncated_calls"] == 4 and result["detail"] == "TRUNCATED: finish_reason length"
    assert result["truncations"] == [{"subagen": "klasifikasi", "percobaan": a, "putaran": p}
                                     for p in (0, 1) for a in (1, 2)]
    records = _records(calls)
    assert [r["outcome"] for r in records] == ["TRUNCATED"] * 4
    assert records[0]["detail"].startswith("TRUNCATED: finish_reason length, 50 token")  # rincian hanya di log
    # umpan balik ke model memakai teks alasan deep agent (graph.build_classifier)
    assert '["schema_check gagal: TRUNCATED: finish_reason length"]' in sent[2]["messages"][1]["content"]


def test_reasons_with_lone_surrogates_are_sanitized_before_the_retry_is_sent():
    content = json.dumps({"label": "XSS", "confidence": 0.5, "evidence": ["\ud83d"], "explanation": "x"})
    runner, _, sent = _runner([_response(content), _response(json.dumps(LITERAL))])
    result = runner.classify(ROW)
    assert result["status"] == "ok" and len(sent) == 2
    assert "evidence tidak ditemukan di baris log: ?" in sent[1]["messages"][1]["content"]


def test_valid_first_label_survives_a_parse_error_on_the_retry():
    runner, _, _ = _runner([_response(json.dumps(NOT_LITERAL)), _response("x"), _response("y")])
    result = runner.classify(ROW)
    assert result["status"] == "verification_failed" and result["label"] == "SQLI" and result["klasifikasi_dipakai"] == 1
    assert result["riwayat_label"] == ["SQLI", "PARSE_ERROR"]


def test_verdict_equals_the_deep_agent_verifier():
    from src.agent.tools import evidence_exists, schema_check

    for classification in (LITERAL, NOT_LITERAL, {"_parse_error": "bukan JSON: x"},
                           {**LITERAL, "confidence": 1.5}):
        ctx = RowContext("run-1", "srbh-1", RAW)
        ctx.classifications.append(classification)
        agent_context.set_current(ctx)
        try:
            schema = json.loads(schema_check.invoke({}))
            missing = [e for e in classification.get("evidence", [])
                       if not json.loads(evidence_exists.invoke({"item": e}))["ada"]] if schema["valid"] else []
        finally:
            agent_context.set_current(None)
        assert lv.verify(classification, RAW) == deterministic_verdict(schema, missing)


def test_run_writes_outputs_and_resumes_after_abort(tmp_path, monkeypatch):
    rows = [{**ROW, "id": f"srbh-{k}"} for k in range(3)]
    monkeypatch.setattr(lv, "method_rows", lambda path, split: (rows, lv.SAMPLE_PATH))
    monkeypatch.setattr(lv, "load_llm_config", lambda: {**CONFIG, "model_version": "openai/gpt-4.1-nano-2025-04-14"})
    monkeypatch.setattr(lv, "sha256_file", lambda path: "x")
    monkeypatch.setattr(lv, "run_info", lambda method, model, **extra: {"run_id": "run-1", "git_dirty": False,
                                                                        "method": method, "model": model, **extra})
    first = OpenRouterClient(SECRET, transport=httpx.MockTransport(
        lambda r, q=[_response(json.dumps(LITERAL)), httpx.Response(402, json={"error": {"code": 402}})]: q.pop(0)))
    calls = tmp_path / "calls.jsonl"
    with pytest.raises(ls.RunAborted):
        lv.run(out_dir=tmp_path, client=first, calls_path=calls, name="llm_single_verified_r1")
    second = OpenRouterClient(SECRET, transport=httpx.MockTransport(lambda r: _response(json.dumps(LITERAL))))
    info = lv.run(out_dir=tmp_path, resume=True, client=second, calls_path=calls, name="llm_single_verified_r1")
    final = [json.loads(x) for x in (tmp_path / "llm_single_verified_r1.jsonl").read_text().splitlines()]
    assert [p["id"] for p in final] == ["srbh-0", "srbh-1", "srbh-2"] and {p["status"] for p in final} == {"ok"}
    assert info["method"] == "llm_single_verified" and info["max_verification_rounds"] == 2
    assert info["prompt_sha256"] == prompt_sha256() and info["retry_system_prompt"] == lv.RETRY_PROMPT
    assert info["totals"]["status"] == {"ok": 3, "verification_failed": 0, "PARSE_ERROR": 0}
    assert len(info["resumed"]) == 1 and SECRET not in calls.read_text()
    records = [json.loads(x) for x in calls.read_text().splitlines()]
    marker = [r for r in records if r.get("jenis") == "galat_api"]
    assert len(marker) == 1 and marker[0]["id"] == "srbh-1" and marker[0]["galat"].startswith("RunAborted")


def test_resume_refuses_a_changed_round_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(lv, "method_rows", lambda path, split: ([ROW], lv.SAMPLE_PATH))
    monkeypatch.setattr(lv, "load_llm_config", lambda: CONFIG)
    monkeypatch.setattr(lv, "sha256_file", lambda path: "x")
    monkeypatch.setattr(lv, "run_info", lambda method, model, **extra: {"run_id": "run-1", "git_dirty": False, **extra})
    aborted = OpenRouterClient(SECRET, transport=httpx.MockTransport(
        lambda r: httpx.Response(402, json={"error": {"code": 402}})))
    with pytest.raises(ls.RunAborted):
        lv.run(out_dir=tmp_path, client=aborted, calls_path=tmp_path / "c.jsonl", name="x")
    monkeypatch.setattr(lv, "MAX_VERIFICATION_ROUNDS", 3)
    with pytest.raises(RuntimeError, match="batas putaran"):
        lv.run(out_dir=tmp_path, resume=True, client=aborted, calls_path=tmp_path / "c.jsonl", name="x")
