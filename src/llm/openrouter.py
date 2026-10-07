"""Klien OpenRouter minimal (chat completions non-streaming) untuk cek API, LLM tunggal, dan deep agent.

Kunci API dibaca dari .env milik penulis (OPENROUTER_API_KEY) dan tidak pernah ditulis ke log, keluaran, atau pesan galat.
Setiap panggilan mengembalikan respons mentah beserta latensi ujung ke ujung; token dan biaya diambil dari blok `usage`.
"""

from __future__ import annotations

import json
import os
import re
import time
from decimal import Decimal
from pathlib import Path

import httpx
import yaml
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / ".env"
LLM_CONFIG = ROOT / "configs" / "llm.yaml"
BASE_URL = "https://openrouter.ai/api/v1"
MODELS_URL = f"{BASE_URL}/models"


_KEY_CHARS = re.compile(r"[A-Za-z0-9_\-]+")


def api_key(env_file: Path = ENV_FILE) -> str:
    """OPENROUTER_API_KEY dari .env (atau environment bila tidak ada di .env). Nilainya tidak pernah ditampilkan."""
    key = dotenv_values(env_file).get("OPENROUTER_API_KEY") if env_file.exists() else None
    key = (key or os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if not key:
        raise RuntimeError(f"OPENROUTER_API_KEY tidak ditemukan di {env_file.name} maupun environment")
    if not _KEY_CHARS.fullmatch(key):
        raise RuntimeError("OPENROUTER_API_KEY memuat karakter tidak valid (nilai tidak ditampilkan)")
    return key


def load_llm_config(path: Path = LLM_CONFIG) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def model_info(model: str, transport: httpx.BaseTransport | None = None) -> dict:
    """Metadata publik satu model dari GET /models (tarif per token, canonical_slug, parameter yang didukung)."""
    with httpx.Client(timeout=60, transport=transport) as client:
        resp = client.get(MODELS_URL)
        resp.raise_for_status()
    for entry in resp.json()["data"]:
        if entry["id"] == model:
            return entry
    raise KeyError(f"model {model} tidak ada di daftar model OpenRouter")


def per_token_rates(info: dict) -> dict[str, Decimal]:
    """Tarif USD per token (masukan, keluaran, baca cache) dari metadata model, sebagai Decimal tanpa galat pembulatan."""
    pricing = info["pricing"]
    rates = {"input": Decimal(pricing["prompt"]), "output": Decimal(pricing["completion"])}
    rates["cache_read"] = Decimal(pricing.get("input_cache_read") or pricing["prompt"])
    return rates


def build_payload(config: dict, messages: list[dict], schema: dict | None = None, schema_name: str = "output",
                  max_tokens: int | None = None) -> dict:
    """Badan permintaan chat completions dari configs/llm.yaml: model, temperature, seed, routing, structured output."""
    generation = config.get("generation") or {}
    payload: dict = {"model": config["model"], "messages": messages, "temperature": generation.get("temperature", 0)}
    if generation.get("seed") is not None:
        payload["seed"] = generation["seed"]
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    if schema is not None:
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": schema_name, "strict": True, "schema": schema},
        }
    if config.get("provider_routing"):
        payload["provider"] = dict(config["provider_routing"])
    return payload  # blok usage (token, biaya) selalu dikirim OpenRouter tanpa parameter tambahan


class OpenRouterClient:
    def __init__(self, key: str, timeout: float = 120.0, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(
            base_url=BASE_URL, timeout=timeout, transport=transport, headers={"Authorization": f"Bearer {key}"}
        )

    def __enter__(self) -> "OpenRouterClient":
        return self

    def __exit__(self, *exc) -> None:
        self._client.close()

    def chat(self, payload: dict) -> dict:
        """Satu panggilan non-streaming: status HTTP, latensi (detik, ujung ke ujung), dan respons mentah."""
        start = time.perf_counter()
        try:
            resp = self._client.post("/chat/completions", json=payload)
        except httpx.LocalProtocolError:
            # pesan aslinya memuat nilai header (termasuk kunci API): jangan diteruskan
            raise RuntimeError("header permintaan tidak valid (nilai tidak ditampilkan)") from None
        latency = time.perf_counter() - start
        try:
            body = resp.json()
        except ValueError:  # bukan JSON, atau bukan UTF-8 (UnicodeDecodeError)
            body = {"raw_text": resp.content.decode("utf-8", "replace")}
        return {"http_status": resp.status_code, "latency_s": latency, "response": body}


def summarize(call: dict, rates: dict[str, Decimal] | None = None) -> dict:
    """Ringkasan satu panggilan: model dan penyedia yang melayani, token, biaya, isi jawaban, dan galat bila ada."""
    body = call["response"] if isinstance(call["response"], dict) else {}
    usage = body.get("usage") or {}
    choice = (body.get("choices") or [{}])[0]
    prompt, completion = usage.get("prompt_tokens"), usage.get("completion_tokens")
    cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0
    from_rates = None
    if rates and prompt is not None and completion is not None:
        from_rates = float((prompt - cached) * rates["input"] + cached * rates.get("cache_read", rates["input"])
                           + completion * rates["output"])
    return {
        "http_status": call["http_status"],
        "latency_s": round(call["latency_s"], 3),
        "generation_id": body.get("id"),
        "served_model": body.get("model"),
        "upstream_provider": body.get("provider"),
        "system_fingerprint": body.get("system_fingerprint"),
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "reasoning_tokens": (usage.get("completion_tokens_details") or {}).get("reasoning_tokens"),
        "cached_tokens": (usage.get("prompt_tokens_details") or {}).get("cached_tokens"),
        "cost_usd": usage.get("cost"),
        "cost_usd_from_rates": from_rates,
        "finish_reason": choice.get("finish_reason"),
        "content": (choice.get("message") or {}).get("content"),
        "refusal": (choice.get("message") or {}).get("refusal"),
        "error": body.get("error"),
        "choice_error": choice.get("error"),  # galat tingkat pilihan (OpenRouter), mis. galat hulu saat generasi
        "non_json_body": "raw_text" in body,
    }
