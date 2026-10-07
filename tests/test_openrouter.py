import json
from decimal import Decimal

import httpx
import pytest

from src.llm import openrouter

CONFIG = {
    "model": "openai/gpt-4.1-nano",
    "generation": {"temperature": 0, "seed": 42},
    "provider_routing": {"order": ["openai"], "allow_fallbacks": False, "require_parameters": True},
}
SECRET = "sk-or-v1-test-secret-key"


def test_api_key_reads_only_the_given_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text(f"OTHER=1\nOPENROUTER_API_KEY={SECRET}\n", encoding="utf-8")
    assert openrouter.api_key(env) == SECRET
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY tidak ditemukan") as err:
        openrouter.api_key(tmp_path / "missing.env")
    assert SECRET not in str(err.value)


def test_malformed_key_is_rejected_without_revealing_it(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text(f'OPENROUTER_API_KEY="{SECRET} "\n', encoding="utf-8")
    assert openrouter.api_key(env) == SECRET  # spasi di tepi dibuang
    env.write_text(f'OPENROUTER_API_KEY="{SECRET}\\tx"\n', encoding="utf-8")
    with pytest.raises(RuntimeError) as err:
        openrouter.api_key(env)
    assert SECRET not in str(err.value)


def test_header_errors_do_not_leak_the_key():
    def handler(request):
        raise httpx.LocalProtocolError(f"Illegal header value b'Bearer {SECRET}'")

    with openrouter.OpenRouterClient(SECRET, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError) as err:
            client.chat({"model": "m", "messages": []})
    assert SECRET not in str(err.value) and err.value.__cause__ is None and err.value.__suppress_context__


def test_build_payload_has_structured_output_temperature_seed_routing_and_usage():
    schema = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False}
    p = openrouter.build_payload(CONFIG, [{"role": "user", "content": "x"}], schema, "uji", max_tokens=5)
    assert p["model"] == "openai/gpt-4.1-nano" and p["temperature"] == 0 and p["seed"] == 42 and p["max_tokens"] == 5
    assert p["response_format"] == {"type": "json_schema", "json_schema": {"name": "uji", "strict": True, "schema": schema}}
    assert p["provider"] == CONFIG["provider_routing"] and "usage" not in p  # usage selalu dikirim OpenRouter


def test_chat_sends_key_but_never_returns_it():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "id": "gen-1", "model": "openai/gpt-4.1-nano", "provider": "OpenAI",
            "choices": [{"message": {"content": '{"status":"ok"}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 6, "cost": 0.0000054,
                      "prompt_tokens_details": {"cached_tokens": 10}},
        })

    with openrouter.OpenRouterClient(SECRET, transport=httpx.MockTransport(handler)) as client:
        call = client.chat({"model": "m", "messages": []})
    assert seen["auth"] == f"Bearer {SECRET}" and seen["body"]["model"] == "m"
    assert SECRET not in json.dumps(call)
    s = openrouter.summarize(call, {"input": Decimal("0.0000001"), "output": Decimal("0.0000004"),
                                    "cache_read": Decimal("0.000000025")})
    assert (s["prompt_tokens"], s["completion_tokens"], s["cost_usd"]) == (30, 6, 0.0000054)
    assert s["cost_usd_from_rates"] == pytest.approx(20 * 1e-7 + 10 * 2.5e-8 + 6 * 4e-7) and s["cached_tokens"] == 10
    assert s["served_model"] == "openai/gpt-4.1-nano" and s["upstream_provider"] == "OpenAI"
    assert s["content"] == '{"status":"ok"}' and s["error"] is None and s["latency_s"] >= 0


def test_summarize_reports_errors_and_non_json_bodies():
    s = openrouter.summarize({"http_status": 400, "latency_s": 0.1, "response": {"error": {"message": "bad", "code": 400}}})
    assert s["error"] == {"message": "bad", "code": 400} and s["prompt_tokens"] is None and s["cost_usd_from_rates"] is None
    s = openrouter.summarize({"http_status": 502, "latency_s": 0.1, "response": {"raw_text": "<html>"}})
    assert s["content"] is None and s["http_status"] == 502


def test_model_info_and_rates():
    data = {"data": [{"id": "openai/gpt-4.1-nano", "canonical_slug": "openai/gpt-4.1-nano-2025-04-14",
                      "pricing": {"prompt": "0.0000001", "completion": "0.0000004", "input_cache_read": "0.000000025"}}]}
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=data))
    info = openrouter.model_info("openai/gpt-4.1-nano", transport=transport)
    rates = openrouter.per_token_rates(info)
    assert info["canonical_slug"] == "openai/gpt-4.1-nano-2025-04-14"
    assert rates["input"] * 1_000_000 == Decimal("0.1") and rates["output"] * 1_000_000 == Decimal("0.4")
    assert rates["cache_read"] * 1_000_000 == Decimal("0.025")
    with pytest.raises(KeyError):
        openrouter.model_info("openai/none", transport=transport)
