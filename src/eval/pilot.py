"""Pemilihan baris pilot: 5 baris per kelas (random_state=42) dari test_sample_500, atau dari split lain (mis. val untuk
validasi perubahan deep agent setelah pilot v1, keputusan penulis K4).

Pemilihan membutuhkan label, jadi dilakukan di sisi evaluasi; metode hanya menerima daftar id tanpa label.
Jalankan: make llm-single-pilot | make agent-val
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from ..common.inputs import SAMPLE_PATH, split_path
from ..data.config import CLASSES, RANDOM_STATE, ROOT

PILOT_PATH = ROOT / "results" / "pilot" / "pilot_ids.json"  # pilot v1 kini di results/archive/pilot/
PER_CLASS = 5
# baris srbh_val yang sudah dipakai uji asap deep agent (2026-10-07): tidak ikut validasi agar tidak pernah dilihat
SMOKE_TEST_IDS = ("srbh-39d12485e402cc62", "srbh-187f9f0e43273cb1", "srbh-7ac0a8cdf16e2eee", "srbh-24574608e4559ffd")


def select(per_class: int = PER_CLASS, random_state: int = RANDOM_STATE) -> list[str]:
    sample = pd.read_json(SAMPLE_PATH, lines=True)
    picked = [sample[sample["label"] == c].sample(n=per_class, random_state=random_state) for c in CLASSES]
    # urutan berkas sampel (sudah diacak saat sampel ditulis), bukan urutan kelas
    ids = set(pd.concat(picked)["id"])
    return [i for i in sample["id"] if i in ids]


def select_split(split: str, per_class: int = PER_CLASS, random_state: int = RANDOM_STATE,
                 exclude: tuple[str, ...] = ()) -> list[str]:
    frame = pd.read_parquet(split_path(split), columns=["id", "label"])
    frame = frame[~frame["id"].isin(set(exclude))]
    picked = [frame[frame["label"] == c].sample(n=per_class, random_state=random_state) for c in CLASSES]
    ids = set(pd.concat(picked)["id"])
    return [i for i in frame["id"] if i in ids]


def default_out(split: str | None) -> Path:
    """Berkas id bawaan: pilot uji di results/pilot/, pilihan dari split lain di results/validasi/ (tidak menimpa pilot)."""
    return ROOT / "results" / "validasi" / f"{split}_ids.json" if split else PILOT_PATH


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pemilihan baris pilot (5 per kelas)")
    parser.add_argument("--split", help="pilih dari srbh_<split>.parquet (mis. val), bukan test_sample_500")
    parser.add_argument("--out", type=Path, help="bawaan: results/pilot/pilot_ids.json (uji) atau "
                                                     "results/validasi/<split>_ids.json (--split)")
    args = parser.parse_args(argv)
    if args.split:
        exclude = SMOKE_TEST_IDS if args.split == "val" else ()
        ids = select_split(args.split, exclude=exclude)
        meta = {"source": str(split_path(args.split).relative_to(ROOT)), "excluded": list(exclude),
                "excluded_reason": "sudah dipakai uji asap deep agent" if exclude else None}
    else:
        ids = select()
        meta = {"source": str(SAMPLE_PATH.relative_to(ROOT))}
    out = (args.out or default_out(args.split)).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"ids": ids, "per_class": PER_CLASS, "random_state": RANDOM_STATE, **meta}, indent=1) + "\n",
                   encoding="utf-8")
    print(f"[pilot] {len(ids)} id -> {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
