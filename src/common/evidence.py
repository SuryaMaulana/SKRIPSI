"""Pemeriksaan evidence literal: satu definisi untuk metrik Tabel 4.5 (src/eval/evaluate.py) dan alat evidence_exists
sub-agen Verifikasi deep agent (keputusan penulis, 2026-10-07).

Sebuah item evidence dianggap literal bila, setelah spasi di tepinya dibuang, item itu muncul apa adanya (peka huruf
besar/kecil) sebagai substring raw_log_masked mentah atau salah satu bentuk hasil decode-nya. Bentuk decode: URL-decode
berulang sampai tiga lapis, dengan dan tanpa '+' sebagai spasi, serta decode entity HTML pada setiap lapis. Batas tiga
lapis sama dengan normalisasi data (§3.3).
"""

from __future__ import annotations

import html
from functools import lru_cache
from urllib.parse import unquote, unquote_plus

MAX_LAYERS = 3


@lru_cache(maxsize=8192)
def decoded_forms(text: str) -> tuple[str, ...]:
    """Teks mentah diikuti semua bentuk berbeda hasil decode sampai MAX_LAYERS lapis."""
    forms, seen, frontier = [text], {text}, [text]
    for _ in range(MAX_LAYERS):
        found = []
        for form in frontier:
            for decoded in (unquote(form), unquote_plus(form), html.unescape(form)):
                if decoded not in seen:
                    seen.add(decoded)
                    forms.append(decoded)
                    found.append(decoded)
        frontier = found
    return tuple(forms)


def evidence_exists(item: str, raw_log_masked: str) -> bool:
    """Apakah satu item evidence ada secara harfiah di baris log (mentah atau hasil decode)."""
    item = item.strip()
    return bool(item) and any(item in form for form in decoded_forms(raw_log_masked))
