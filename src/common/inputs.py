"""Masukan metode dari test_sample_500.jsonl: `id` + kolom masukan saja.

Aturan umum tahap sistem: semua metode (regex, LLM tunggal, deep agent) membaca kolom masukan yang sama dan tidak pernah
membaca `label` atau `template_key`; hanya skrip evaluasi yang boleh membaca keduanya.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..data.config import PROCESSED_DIR
from ..data.sample import EVAL_COLUMNS, INPUT_COLUMNS

SAMPLE_PATH = PROCESSED_DIR / "test_sample_500.jsonl"
METHOD_COLUMNS = ("id", *INPUT_COLUMNS)
assert not set(EVAL_COLUMNS) & set(METHOD_COLUMNS), "kolom evaluasi tidak boleh menjadi masukan metode"


def load_inputs(path: Path = SAMPLE_PATH) -> list[dict]:
    """Baris sampel uji dalam urutan berkas, hanya berisi METHOD_COLUMNS."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            record = json.loads(line)
            missing = [c for c in METHOD_COLUMNS if c not in record]
            if missing:
                raise KeyError(f"{path.name} baris {n}: kolom masukan tidak ada: {missing}")
            rows.append({c: record[c] for c in METHOD_COLUMNS})
    return rows
