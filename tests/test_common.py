import json

import pytest

from src.common import runinfo
from src.common.inputs import METHOD_COLUMNS, load_inputs
from src.data.sample import SAMPLE_COLUMNS


def _write_sample(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_load_inputs_never_returns_evaluation_columns(tmp_path):
    record = {c: f"v-{c}" for c in SAMPLE_COLUMNS}
    _write_sample(tmp_path / "s.jsonl", [record, {**record, "id": "b"}])
    rows = load_inputs(tmp_path / "s.jsonl")
    assert [r["id"] for r in rows] == ["v-id", "b"]
    assert all(set(r) == set(METHOD_COLUMNS) for r in rows)
    assert all("label" not in r and "template_key" not in r for r in rows)


def test_load_inputs_rejects_missing_input_column(tmp_path):
    record = {c: "x" for c in SAMPLE_COLUMNS if c != "raw_log_masked"}
    _write_sample(tmp_path / "s.jsonl", [record])
    with pytest.raises(KeyError, match="raw_log_masked"):
        load_inputs(tmp_path / "s.jsonl")


def test_run_info_records_date_commit_and_model(monkeypatch):
    monkeypatch.setattr(runinfo, "_git", lambda *a: {"rev-parse": "abc1234def", "status": ' M results/regex.jsonl\n?? "results/x y.jsonl"'}[a[0]])
    info = runinfo.run_info("regex", None, rules=3)
    assert info["method"] == "regex" and info["model"] is None and info["rules"] == 3
    assert info["git_commit"] == "abc1234def" and info["git_dirty"] is False  # hanya berkas keluaran yang berubah
    assert info["run_id"].startswith("regex-") and info["run_id"].endswith("-abc1234")
    assert info["date_utc"].endswith("+00:00")


def test_git_dirty_when_code_changes(monkeypatch):
    monkeypatch.setattr(runinfo, "_git", lambda *a: " M src/baselines/regex_baseline.py" if a[0] == "status" else "abc")
    assert runinfo.git_state()["git_dirty"] is True


def test_thesis_draft_changes_do_not_mark_runs_dirty(monkeypatch):
    status = ' D "Draft Skripsi (1).docx"\n?? "Draft Skripsi (2).docx"\n M results/regex.jsonl'
    monkeypatch.setattr(runinfo, "_git", lambda *a: status if a[0] == "status" else "abc")
    assert runinfo.git_state()["git_dirty"] is False


def test_method_rows_switches_between_the_test_sample_and_a_split(monkeypatch):
    from src.common import inputs

    monkeypatch.setattr(inputs, "load_inputs", lambda path: ["sampel", path])
    monkeypatch.setattr(inputs, "load_split_inputs", lambda split: ["split", split])
    assert inputs.method_rows() == (["sampel", inputs.SAMPLE_PATH], inputs.SAMPLE_PATH)
    assert inputs.method_rows(split="val") == (["split", "val"], inputs.split_path("val"))


def test_repo_path_never_raises_for_paths_outside_the_repository(tmp_path):
    from src.common import runinfo

    assert runinfo.repo_path(runinfo.ROOT / "results" / "x.json") == "results/x.json"
    assert runinfo.repo_path(tmp_path / "ids.json") == str((tmp_path / "ids.json").resolve())
    assert runinfo.repo_path(None) is None


def test_reports_are_outputs_for_the_dirty_check(monkeypatch):
    from src.common import runinfo

    monkeypatch.setattr(runinfo, "_git", lambda *a: "?? reports/validasi_agent_val.md" if a[0] == "status" else "abc")
    assert runinfo.git_state()["git_dirty"] is False


def test_val_selection_does_not_overwrite_the_test_pilot_ids():
    from src.eval import pilot

    assert pilot.default_out(None) == pilot.PILOT_PATH
    assert pilot.default_out("val").parts[-2:] == ("validasi", "val_ids.json")
