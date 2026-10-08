import json

import numpy as np
import pytest

from src.eval import replikasi as rp
from src.eval.evaluate import Method, Truth

CLASSES = ["SQLI", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "WEB_SCANNING", "NORMAL"]


def _truth():
    labels, keys, logs = {}, {}, {}
    for k, c in enumerate(CLASSES):
        for j in range(4):
            i = f"{c}-{j}"
            labels[i], keys[i], logs[i] = c, f"t{j % 2}", "GET /?q=%3Cscript%3E HTTP/1.1"
    return Truth(labels, keys, "uji", logs)


def _method(truth, wrong: set[str], name="llm_single", run=None, cost=0.0002):
    preds = {i: ("NORMAL" if i in wrong and truth.labels[i] != "NORMAL" else
                 "SQLI" if i in wrong else truth.labels[i]) for i in truth.labels}
    rows = [{"id": i, "label": p, "evidence": ["<script>"], "prompt_tokens": 900, "completion_tokens": 90,
             "latency_s": 1.5, "cost_usd": cost, "attempts": 1, "status": "ok"} for i, p in preds.items()]
    return Method(name, rp.RESULTS_DIR / f"{name}.jsonl", preds, False, run or {"run_id": name, "model": "m"}, rows)


def test_single_run_aggregate_equals_the_run_and_ranges_collapse():
    truth = _truth()
    g = rp.aggregate([_method(truth, {"SQLI-0"})], truth)
    m = g["metrics"]["accuracy"]
    assert m["mean"] == m["min"] == m["max"] == pytest.approx(23 / 24)
    assert rp._cell(m) == "0,958" and g["baris_label_berubah_antar_run"] == 0


def test_mean_min_max_and_label_changes_across_runs():
    truth = _truth()
    runs = [_method(truth, set()), _method(truth, {"SQLI-0"}), _method(truth, {"SQLI-0", "XSS-1"}, cost=0.0004)]
    g = rp.aggregate(runs, truth)
    acc = g["metrics"]["accuracy"]
    assert acc["values"] == pytest.approx([1.0, 23 / 24, 22 / 24])
    assert acc["mean"] == pytest.approx(np.mean([1.0, 23 / 24, 22 / 24])) and acc["min"] == pytest.approx(22 / 24)
    assert g["baris_label_berubah_antar_run"] == 2
    assert g["metrics"]["biaya_per_1000_baris_usd"]["max"] == pytest.approx(0.4)
    assert rp._cell(acc) == "0,958 (0,917–1,000)"
    cm = np.array(g["confusion_mean"])
    assert cm[0, 0] == pytest.approx((4 + 3 + 3) / 3) and cm[0, 5] == pytest.approx(2 / 3)
    ci = g["macro_f1_ci95"]
    assert ci["runs"] == 3 and ci["low"] <= g["metrics"]["macro_f1"]["mean"] <= ci["high"]


def test_runs_with_different_configuration_are_refused():
    truth = _truth()
    a = _method(truth, set(), run={"run_id": "a", "model": "m", "prompt_sha256": "x"})
    b = _method(truth, set(), run={"run_id": "b", "model": "m", "prompt_sha256": "y"})
    with pytest.raises(ValueError, match="prompt_sha256"):
        rp.check_consistent([a, b])
    assert rp.check_consistent([a, a])["prompt_sha256"] == "x"


def test_group_files_finds_main_and_numbered_replications(tmp_path):
    (tmp_path / "rep").mkdir()
    for path in ("agent.jsonl", "rep/agent_r1.jsonl", "rep/agent_r2.jsonl", "rep/agent_r10.jsonl",
                 "rep/agent_r1_calls.jsonl", "rep/llm_single_r1.jsonl", "rep/agent_r3.partial.jsonl"):
        (tmp_path / path).write_text(json.dumps({"id": "x", "label": "NORMAL"}) + "\n")
    files = rp.group_files("agent", tmp_path, tmp_path / "rep")
    assert [p.name for p in files] == ["agent_r1.jsonl", "agent_r2.jsonl", "agent_r10.jsonl"]  # run resmi saja
    assert [p.name for p in rp.group_files("agent", tmp_path, tmp_path / "rep", include_main=True)][0] == "agent.jsonl"


def test_degenerate_outputs_and_call_latency_are_reported_per_run(tmp_path, monkeypatch):
    truth = _truth()
    calls = tmp_path / "calls.jsonl"
    calls.write_text("".join(json.dumps(r) + "\n" for r in [
        {"run_id": "r1", "jenis": "llm", "latency_s": 1.0}, {"run_id": "r1", "jenis": "llm", "latency_s": 3.0},
        {"run_id": "r1", "jenis": "alat", "latency_s": 0.1}, {"run_id": "lain", "jenis": "llm", "latency_s": 99.0},
        *({"run_id": "r1", "outcome": "TRUNCATED"} for _ in range(3))]))
    method = _method(truth, {"SQLI-0"}, run={"run_id": "r1", "model": "m", "calls_file": str(calls)})
    for row in method.rows:
        row["truncated_calls"] = 0
    method.rows[0].update(truncated_calls=2, status="PARSE_ERROR", label="PARSE_ERROR")
    method.rows[1].update(truncated_calls=1)
    metrics = rp.run_metrics(method, truth)
    assert rp.call_latencies(method) == [1.0, 3.0] and metrics["latensi_panggilan_median_s"] == 2.0
    assert metrics["degeneratif_kejadian"] == 3 and metrics["degeneratif_baris_terdampak"] == 2
    assert metrics["degeneratif_terdampak_parse_error"] == 1 and metrics["degeneratif_terdampak_ok"] == 1
    text = rp.render({"llm_single": rp.aggregate([method], truth)})
    assert "Keluaran degeneratif" in text and "latensi per panggilan median" in text


def test_incomplete_or_unfinished_groups_are_refused(tmp_path):
    truth = _truth()
    runs = [_method(truth, set()) for _ in range(3)]
    for m in runs:
        m.run["rows"] = len(truth.labels)
    rp.check_complete("agent", runs, truth, tmp_path)
    with pytest.raises(ValueError, match="2 run"):
        rp.check_complete("agent", runs[:2], truth, tmp_path)
    short = _method(truth, set())
    short.run["rows"] = 10
    with pytest.raises(ValueError, match="cakupan"):
        rp.check_complete("agent", [*runs[:2], short], truth, tmp_path)
    (tmp_path / "agent_r3.partial.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="belum selesai"):
        rp.check_complete("agent", runs, truth, tmp_path)


def test_degenerate_outcomes_include_verification_skipped():
    truth = _truth()
    method = _method(truth, set(), run={"run_id": "r", "model": "m"})
    for row in method.rows:
        row["truncated_calls"] = 0
    method.rows[0].update(truncated_calls=2, status="verification_skipped")
    out = rp.degenerate(method, truth)
    assert out["terdampak_verification_skipped"] == 1 and out["baris_terdampak"] == 1


def test_calls_from_attempts_aborted_by_api_errors_are_excluded_from_call_latency(tmp_path):
    truth = _truth()
    calls = tmp_path / "calls.jsonl"
    calls.write_text("".join(json.dumps(r) + "\n" for r in [
        {"run_id": "r1", "jenis": "llm", "id": "a", "timestamp_utc": "2026-10-08T00:30:00.000+00:00", "latency_s": 50.0,
         "cost_usd": 0.001},
        {"run_id": "r1", "jenis": "galat_api", "id": "a", "timestamp_utc": "2026-10-08T00:32:41.000+00:00"},
        {"run_id": "r1", "jenis": "llm", "id": "a", "timestamp_utc": "2026-10-08T00:35:20.000+00:00", "latency_s": 1.0},
        {"run_id": "r1", "jenis": "llm", "id": "b", "timestamp_utc": "2026-10-08T00:31:00.000+00:00", "latency_s": 3.0}]))
    method = _method(truth, set(), run={"run_id": "r1", "model": "m", "calls_file": str(calls)})
    used, dropped = rp.call_records(method)
    assert [r["latency_s"] for r in used] == [1.0, 3.0] and [r["latency_s"] for r in dropped] == [50.0]
    metrics = rp.run_metrics(method, truth)
    assert metrics["panggilan_dibatalkan_galat_api"] == 1 and metrics["biaya_panggilan_dibatalkan_usd"] == 0.001
