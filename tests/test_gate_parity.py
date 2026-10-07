"""Uji regresi: setiap modul gerbang mereproduksi target per (baris, label) dari analisis bukti yang disetujui.

Target disimpan di tests/fixtures/ (ikut versi kode). Lambat (memakai data penuh) dan dilewati hanya bila CSV mentah
belum diunduh (`make download`). Jalankan dengan `make test-slow`.
"""

import numpy as np
import pandas as pd
import pytest

from src.data.config import ROOT, SRBH_CSV

TARGETS = ROOT / "tests" / "fixtures" / "gate_parity_targets.parquet"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not SRBH_CSV.exists(), reason="CSV mentah belum diunduh (make download)"),
]


@pytest.fixture(scope="module")
def data():
    from src.data.gate.common import add_decoded
    from src.data.load import detect_label_columns, read_raw

    raw = read_raw()
    labels = detect_label_columns(raw)
    return add_decoded(raw.astype({c: np.int8 for c in labels})), pd.read_parquet(TARGETS)


def test_every_module_matches_targets(data):
    from src.data.gate import MODULES

    df, targets = data
    for module in MODULES:
        has = df[list(module.LABELS)].astype(int).eq(1).any(axis=1)
        out = module.evaluate(df[has]).rename_axis("row_id").reset_index()
        out = out[out["label"] != "248 - Command Injection"]  # 248 tidak punya target (selalu netral, aturan C0)
        expected = targets[targets["label"].isin(module.LABELS)]
        merged = out.merge(expected, on=["row_id", "label"], how="outer", suffixes=("", "_t"), indicator=True)
        mismatch = merged[
            (merged["_merge"] != "both")
            | (merged["candidate"] != merged["candidate_t"])
            | (merged["reason"] != merged["reason_t"])
            | (merged["rule_id"] != merged["rule_id_t"])
            | (merged["weak"] != merged["weak_t"])
        ]
        assert mismatch.empty, f"{module.__name__}: {len(mismatch)} entri berbeda, contoh {mismatch.head(3).to_dict('records')}"
