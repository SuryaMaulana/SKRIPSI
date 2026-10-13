"""Sampel uji publik (revisi jurnal): sampel/test_sample_500_masukan.jsonl.

Isinya 500 baris data/processed/test_sample_500.jsonl dalam urutan berkas yang sama, hanya dengan id opak dan kolom
masukan metode (src/common/inputs.METHOD_COLUMNS), yaitu persis yang dibaca regex, LLM tunggal, deep agent, dan ablasi.
Kolom evaluasi (label gerbang dan template_key) tidak disertakan (keputusan penulis). SR-BH 2020 berlisensi CC0 1.0.
id = "srbh-" + 16 digit heksadesimal pertama SHA-256("srbh2020:<nomor baris di CSV SR-BH>") (src/data/prepare.py
opaque_id); id yang sama dipakai di results/*.jsonl.
Jalankan: make sampel-publik  (atau python -m src.data.sampel_publik)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..common.inputs import METHOD_COLUMNS, SAMPLE_PATH, load_inputs
from .config import ROOT

PUBLIC_SAMPLE_PATH = ROOT / "sampel" / "test_sample_500_masukan.jsonl"


def write(src: Path = SAMPLE_PATH, dst: Path = PUBLIC_SAMPLE_PATH) -> int:
    rows = load_inputs(src)
    assert all(tuple(r) == METHOD_COLUMNS for r in rows)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(rows)


def main() -> int:
    n = write()
    print(f"{n} baris -> {PUBLIC_SAMPLE_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
