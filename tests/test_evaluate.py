import json

import numpy as np
import pytest
from sklearn.metrics import f1_score

from src.data.config import CLASSES
from src.eval import evaluate as ev


def _idx(truth, pred):
    return ev._indices(truth, pred)


def test_macro_f1_matches_sklearn_and_invalid_predictions_count_as_wrong():
    rng = np.random.default_rng(0)
    truth = list(rng.choice(CLASSES, 300))
    pred = list(rng.choice(CLASSES, 300))
    t, p = _idx(truth, pred)
    assert ev.macro_f1(t, p) == pytest.approx(f1_score(truth, pred, labels=list(CLASSES), average="macro", zero_division=0))
    pred[:20] = ["PARSE_ERROR"] * 20
    t, p = _idx(truth, pred)
    m = ev.multiclass(t, p)
    assert m["invalid_predictions"] == 20 and m["accuracy"] == pytest.approx(np.mean(np.array(truth) == np.array(pred)))
    assert m["macro_f1"] == pytest.approx(f1_score(truth, pred, labels=list(CLASSES), average="macro", zero_division=0))


def test_binary_treats_invalid_predictions_as_errors():
    truth = ["SQLI", "NORMAL", "XSS", "NORMAL", "NORMAL"]
    pred = ["PARSE_ERROR", "PARSE_ERROR", "SQLI", "NORMAL", "WEB_SCANNING"]
    b = ev.binary(*_idx(truth, pred))
    assert (b["tp"], b["fn"], b["fp"], b["tn"]) == (1, 1, 2, 1)
    assert b["fpr"] == pytest.approx(2 / 3) and b["recall"] == pytest.approx(0.5)


def test_cluster_bootstrap_is_deterministic_and_degenerate_when_perfect():
    truth = [c for c in CLASSES for _ in range(4)]  # 6 kelas x 4 baris, dua templat per kelas
    keys = [f"{c}|t{i % 2}" for c in CLASSES for i in range(4)]
    t, p = _idx(truth, truth)
    ci = ev.bootstrap_macro_f1(t, p, keys, n=200)
    assert ci["low"] == ci["high"] == 1.0 and ci["clusters"] == 12
    pred = list(truth)
    pred[0] = pred[1] = "NORMAL"  # dua baris SQLI (satu per templat) salah
    t, p = _idx(truth, pred)
    a = ev.bootstrap_macro_f1(t, p, keys, n=200)
    assert a == ev.bootstrap_macro_f1(t, p, keys, n=200)
    assert a["low"] <= ev.macro_f1(t, p) <= a["high"] and a["low"] < 1.0


def test_prediction_files_post_hoc_and_coverage(tmp_path):
    rows = [{"id": "a", "label": "SQLI", "post_hoc": True}, {"id": "b", "label": "NORMAL", "post_hoc": True}]
    path = tmp_path / "regex_full.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    (tmp_path / "llm_single_calls.jsonl").write_text("", encoding="utf-8")
    assert ev.is_prediction_file(path) and not ev.is_prediction_file(tmp_path / "llm_single_calls.jsonl")
    method = ev.load_method(path)
    assert method.post_hoc and method.display == "regex_full (post hoc)"
    truth = ev.Truth({"a": "SQLI", "b": "XSS", "c": "NORMAL"}, {"a": "k1", "b": "k2", "c": "k3"}, "uji")
    result = ev.evaluate(method, truth)
    assert result["coverage"] == "2/3" and result["multiclass"]["n"] == 2
    with pytest.raises(ValueError, match="id tidak ada"):
        ev.evaluate(ev.Method("x", path, {"zzz": "SQLI"}, False), truth)
