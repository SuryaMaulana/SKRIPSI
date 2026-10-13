import json

import pytest

from src.common.inputs import METHOD_COLUMNS, SAMPLE_PATH, load_inputs
from src.data import sampel_publik
from src.data.config import ROOT
from src.data.sample import EVAL_COLUMNS


def _rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_public_sample_has_500_opaque_ids_and_method_input_columns_only():
    rows = _rows(sampel_publik.PUBLIC_SAMPLE_PATH)
    assert len(rows) == 500 and len({r["id"] for r in rows}) == 500
    assert all(tuple(r) == METHOD_COLUMNS for r in rows)
    assert not any(set(EVAL_COLUMNS) & set(r) for r in rows)
    assert all(r["id"].startswith("srbh-") and len(r["id"]) == 21 for r in rows)
    results = {json.loads(line)["id"] for line in (ROOT / "results" / "regex.jsonl").read_text().splitlines()}
    assert results == {r["id"] for r in rows}
    assert load_inputs(sampel_publik.PUBLIC_SAMPLE_PATH) == rows  # bisa langsung dipakai sebagai masukan metode


def test_public_sample_matches_the_processed_sample_in_order_without_eval_columns(tmp_path):
    if not SAMPLE_PATH.exists():
        pytest.skip("butuh data/processed/test_sample_500.jsonl (make data)")
    assert sampel_publik.write(SAMPLE_PATH, tmp_path / "s.jsonl") == 500
    assert (tmp_path / "s.jsonl").read_bytes() == sampel_publik.PUBLIC_SAMPLE_PATH.read_bytes()
    full = _rows(SAMPLE_PATH)
    assert [{k: r[k] for k in METHOD_COLUMNS} for r in full] == _rows(sampel_publik.PUBLIC_SAMPLE_PATH)
