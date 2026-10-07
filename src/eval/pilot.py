"""Pemilihan baris pilot LLM tunggal: 5 baris per kelas dari test_sample_500 (random_state=42).

Pemilihan membutuhkan label, jadi dilakukan di sisi evaluasi; metode hanya menerima daftar id (results/pilot/
pilot_ids.json) tanpa label. Jalankan: make llm-single-pilot
"""

from __future__ import annotations

import json
import sys

import pandas as pd

from ..common.inputs import SAMPLE_PATH
from ..data.config import CLASSES, RANDOM_STATE, ROOT

PILOT_PATH = ROOT / "results" / "pilot" / "pilot_ids.json"
PER_CLASS = 5


def select(per_class: int = PER_CLASS, random_state: int = RANDOM_STATE) -> list[str]:
    sample = pd.read_json(SAMPLE_PATH, lines=True)
    picked = [sample[sample["label"] == c].sample(n=per_class, random_state=random_state) for c in CLASSES]
    # urutan berkas sampel (sudah diacak saat sampel ditulis), bukan urutan kelas
    ids = set(pd.concat(picked)["id"])
    return [i for i in sample["id"] if i in ids]


def main() -> int:
    ids = select()
    PILOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    PILOT_PATH.write_text(json.dumps({"ids": ids, "per_class": PER_CLASS, "random_state": RANDOM_STATE,
                                      "source": str(SAMPLE_PATH.relative_to(ROOT))}, indent=1) + "\n", encoding="utf-8")
    print(f"[pilot] {len(ids)} id -> {PILOT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
