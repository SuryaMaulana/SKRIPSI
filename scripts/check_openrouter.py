"""Langkah A — cek API OpenRouter: satu prompt pendek ke model di configs/llm.yaml.

Mencetak nama model persis, token masuk/keluar, latensi, dan biaya USD; menulis versi model dan tarif per 1M token ke
configs/llm.yaml (untuk BAB IV) dan mencatat run ke results/check_openrouter.json. Jalankan dari akar proyek:
    make check-api        (atau: .venv/bin/python scripts/check_openrouter.py)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.common.runinfo import run_info  # noqa: E402
from src.llm.openrouter import (  # noqa: E402
    LLM_CONFIG,
    MODELS_URL,
    OpenRouterClient,
    api_key,
    build_payload,
    load_llm_config,
    model_info,
    per_token_rates,
    summarize,
)

RESULT_PATH = ROOT / "results" / "check_openrouter.json"
SCHEMA = {
    "type": "object",
    "properties": {"status": {"type": "string", "enum": ["ok"]}},
    "required": ["status"],
    "additionalProperties": False,
}
MESSAGES = [
    {"role": "system", "content": "Jawab hanya dengan JSON sesuai skema."},
    {"role": "user", "content": "Uji koneksi: kembalikan status ok."},
]
CONFIG_HEADER = """\
# Model LLM untuk LLM tunggal dan deep agent (keputusan penulis 2026-10-07: openai/gpt-4.1-nano).
# Ubah `model`, `generation`, atau `provider_routing` di sini. Blok `model_version`, `pricing_usd_per_1m_tokens`,
# `pricing_retrieved_utc`, dan `api_check` ditulis ulang oleh scripts/check_openrouter.py (make check-api) untuk BAB IV.
"""


def usd(value: float | None) -> str:
    return "tidak tersedia" if value is None else f"${value:.8f}"


def per_million(rate: Decimal) -> float:
    return float((rate * 1_000_000).normalize())


def main() -> int:
    config = load_llm_config()
    info = model_info(config["model"])
    rates = per_token_rates(info)
    payload = build_payload(config, MESSAGES, SCHEMA, "api_check", max_tokens=20)
    with OpenRouterClient(api_key()) as client:
        call = client.chat(payload)
    s = summarize(call, rates)
    if s["http_status"] != 200 or s["error"]:
        print(f"GAGAL: HTTP {s['http_status']}: {json.dumps(s['error'], ensure_ascii=False)}")
        return 1
    try:
        parsed = json.loads(s["content"])
        structured = "valid" if parsed == {"status": "ok"} else f"tidak sesuai: {parsed}"
    except (TypeError, json.JSONDecodeError):
        structured = f"bukan JSON: {s['content']!r}"

    print(f"Model diminta        : {config['model']}")
    print(f"Model yang melayani  : {s['served_model']} (penyedia: {s['upstream_provider']})")
    print(f"Versi model (OpenRouter canonical_slug): {info.get('canonical_slug')}")
    print(f"Token masuk / keluar : {s['prompt_tokens']} / {s['completion_tokens']}")
    print(f"Latensi              : {s['latency_s']:.3f} s (ujung ke ujung)")
    print(f"Biaya                : {usd(s['cost_usd'])} (usage.cost OpenRouter); dari tarif: {usd(s['cost_usd_from_rates'])}")
    print(f"Tarif per 1M token   : masukan ${per_million(rates['input'])}, keluaran ${per_million(rates['output'])}, "
          f"baca cache ${per_million(rates['cache_read'])}")
    print(f"Structured output    : {structured}")

    run = run_info("check_openrouter", config["model"])
    check = {
        "run_id": run["run_id"],
        "date_utc": run["date_utc"],
        "git_commit": run["git_commit"],
        "git_dirty": run["git_dirty"],
        "model_version": info.get("canonical_slug"),
        "served_model": s["served_model"],
        "upstream_provider": s["upstream_provider"],
        "prompt_tokens": s["prompt_tokens"],
        "completion_tokens": s["completion_tokens"],
        "latency_s": s["latency_s"],
        "cost_usd": s["cost_usd"],
        "structured_output": structured,
    }
    config.update({
        "model_version": info.get("canonical_slug"),
        "pricing_usd_per_1m_tokens": {key: per_million(rate) for key, rate in rates.items()},
        "pricing_source": f"GET {MODELS_URL}",
        "pricing_retrieved_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "api_check": check,
    })
    LLM_CONFIG.write_text(CONFIG_HEADER + yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding="utf-8")
    RESULT_PATH.parent.mkdir(exist_ok=True)
    RESULT_PATH.write_text(json.dumps({**run, "summary": s, "request": payload}, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(f"Ditulis: {LLM_CONFIG.relative_to(ROOT)}, {RESULT_PATH.relative_to(ROOT)}")
    return 0 if structured == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
