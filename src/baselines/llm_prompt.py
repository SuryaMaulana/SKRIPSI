"""Prompt LLM tunggal (§3.5 skripsi): Lampiran A tanpa bagian keluaran alat (keputusan penulis, 2026-10-07).

Definisi kelas, aturan, dan skema berasal dari src/llm/klasifikasi.py yang juga dipakai sub-agen Klasifikasi deep
agent; satu-satunya perbedaan kedua metode adalah arsitektur.
"""

from __future__ import annotations

from ..llm.klasifikasi import CLASS_LABELS, CLASS_SECTION, OUTPUT_SCHEMA, SCHEMA_SECTION, TABLE_2_1, rules, sha256

__all__ = ["CLASS_LABELS", "OUTPUT_SCHEMA", "SYSTEM_PROMPT", "TABLE_2_1", "prompt_sha256", "user_message"]

SYSTEM_PROMPT = "\n".join([
    "PERAN",
    "Anda adalah analis keamanan aplikasi web. Tugas Anda menetapkan SATU kelas untuk satu baris log akses web server "
    "(Combined Log Format) berdasarkan bukti pada baris log itu, bukan tebakan.",
    "",
    CLASS_SECTION,
    "",
    rules("baris log"),
    "",
    SCHEMA_SECTION,
])


def user_message(raw_log_masked: str) -> str:
    return f"<log>{raw_log_masked}</log>"


def prompt_sha256() -> str:
    return sha256(SYSTEM_PROMPT)
