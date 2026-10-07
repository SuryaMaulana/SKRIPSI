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


def test_prediction_files_post_hoc_and_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(ev, "RESULTS_DIR", tmp_path)  # berkas langsung di folder hasil: tanpa tanda pembeda
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


def test_bootstrap_resamples_whole_templates_not_rows():
    """Satu templat per kelas: bootstrap klaster selalu mengambil kembali baris yang sama sehingga IK = titik;
    bootstrap per baris tidak akan begitu. Juga dicocokkan dengan replika tulisan tangan (persentil 2,5/97,5)."""
    truth = [c for c in CLASSES for _ in range(5)]
    keys = [f"{c}|satu" for c in CLASSES for _ in range(5)]
    pred = list(truth)
    pred[0] = "NORMAL"  # satu baris SQLI salah
    t, p = _idx(truth, pred)
    ci = ev.bootstrap_macro_f1(t, p, keys, n=300)
    point = ev.macro_f1(t, p)
    assert ci["low"] == pytest.approx(point) and ci["high"] == pytest.approx(point) and point < 1

    truth = [c for c in CLASSES for _ in range(6)]
    keys = [f"{c}|t{i % 3}" for c in CLASSES for i in range(6)]
    pred = list(truth)
    pred[0] = pred[3] = "XSS"
    t, p = _idx(truth, pred)
    rng = np.random.default_rng(42)
    groups = []
    for k in range(len(CLASSES)):
        rows = np.flatnonzero(t == k)
        by_key = {}
        for i in rows:
            by_key.setdefault(keys[i], []).append(i)
        groups.append([np.array(by_key[key]) for key in sorted(by_key)])
    scores = [ev.macro_f1(t[idx], p[idx]) for idx in (
        np.concatenate([g[j] for g in groups for j in rng.integers(0, len(g), len(g))]) for _ in range(1000))]
    low, high = np.percentile(scores, [2.5, 97.5])
    ci = ev.bootstrap_macro_f1(t, p, keys)
    assert (ci["low"], ci["high"]) == (low, high) and ci["n_bootstrap"] == 1000


def test_macro_and_per_class_precision_recall_and_binary_match_sklearn():
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, precision_score, recall_score
    rng = np.random.default_rng(7)
    truth = list(rng.choice(CLASSES, 400))
    pred = list(rng.choice([*CLASSES, "PARSE_ERROR"], 400))
    m = ev.multiclass(*_idx(truth, pred))
    prec, rec, f1, sup = precision_recall_fscore_support(truth, pred, labels=list(CLASSES), zero_division=0)
    assert m["macro_precision"] == pytest.approx(prec.mean()) and m["macro_recall"] == pytest.approx(rec.mean())
    for i, c in enumerate(CLASSES):
        assert m["per_class"][c]["precision"] == pytest.approx(prec[i]) and m["per_class"][c]["f1"] == pytest.approx(f1[i])
    flip = [(x != "NORMAL") if y not in CLASSES else (y != "NORMAL") for x, y in zip(truth, pred)]
    flip = [(not (x != "NORMAL")) if y not in CLASSES else v for x, y, v in zip(truth, pred, flip)]
    actual = [x != "NORMAL" for x in truth]
    b = ev.binary(*_idx(truth, pred))
    assert b["accuracy"] == pytest.approx(accuracy_score(actual, flip))
    assert b["precision"] == pytest.approx(precision_score(actual, flip)) and b["recall"] == pytest.approx(recall_score(actual, flip))


def test_subset_without_some_classes_and_without_normal_rows():
    truth, pred = ["SQLI", "SQLI", "XSS"], ["SQLI", "SQLI", "XSS"]
    m = ev.multiclass(*_idx(truth, pred))
    assert m["macro_f1"] == 1.0 and m["classes_in_macro"] == ["SQLI", "XSS"]
    assert ev.binary(*_idx(truth, pred))["fpr"] is None


def test_default_files_skip_calls_pilot_and_tuning_and_render_format(tmp_path, monkeypatch):
    for name in ("regex.jsonl", "llm_single_calls.jsonl", "pilot/llm_single.jsonl", "tuning/regex_full_val.jsonl"):
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_text('{"id": "a", "label": "SQLI"}\n', encoding="utf-8")
    monkeypatch.setattr(ev, "RESULTS_DIR", tmp_path)
    assert [p.name for p in ev.default_files()] == ["regex.jsonl"]
    (tmp_path / "dup.jsonl").write_text('{"id": "a", "label": "SQLI"}\n{"id": "a", "label": "XSS"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="id ganda"):
        ev.load_method(tmp_path / "dup.jsonl")
    method = ev.load_method(tmp_path / "pilot" / "llm_single.jsonl")
    assert method.display == "llm_single [pilot]"
    truth = ev.Truth({"a": "SQLI"}, {"a": "k"}, "uji")
    text = ev.render([ev.evaluate(ev.Method("m", tmp_path / "regex.jsonl", {"a": "PARSE_ERROR"}, True), truth)], [], truth)
    assert "| m (post hoc) | 1/1 | 0,000 |" in text and "tidak valid" in text and "| SQLI | 0 | 0 | 0 | 0 | 0 | 0 | 1 |" in text
