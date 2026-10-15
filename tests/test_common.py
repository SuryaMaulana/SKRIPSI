import json
from pathlib import Path

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


def test_parallel_runs_started_in_the_same_second_get_distinct_run_ids(monkeypatch):
    from src.common import runinfo

    monkeypatch.setattr(runinfo, "git_state", lambda: {"git_commit": "abcdef0123", "git_branch": "b", "git_dirty": False})
    ids = {runinfo.run_info("llm_single", "m", run_name=f"llm_single_r{r}")["run_id"].split("-")[0] for r in (1, 2, 3)}
    assert ids == {"llm_single_r1", "llm_single_r2", "llm_single_r3"}
    assert runinfo.run_info("evaluate", None)["run_id"].startswith("evaluate-")


def test_commit_terkini_maps_recorded_commits_to_the_rewritten_history(monkeypatch, tmp_path):
    path = tmp_path / "pemetaan_commit.json"
    path.write_text(json.dumps({"lama_ke_baru": {"a" * 40: "b" * 40}}), encoding="utf-8")
    monkeypatch.setattr(runinfo, "COMMIT_MAP", path)
    assert runinfo.commit_terkini("a" * 40) == "b" * 40
    assert runinfo.commit_terkini("c" * 40) == "c" * 40  # tidak dipetakan -> apa adanya
    assert runinfo.commit_terkini(None) is None
    monkeypatch.setattr(runinfo, "COMMIT_MAP", tmp_path / "tidak_ada.json")
    assert runinfo.commit_terkini("a" * 40) == "a" * 40


def test_every_recorded_run_commit_has_a_mapping_or_exists_in_the_current_history():
    import subprocess

    mapping = json.loads(runinfo.COMMIT_MAP.read_text(encoding="utf-8"))["lama_ke_baru"]
    runs = sorted((runinfo.ROOT / "results").rglob("*.run.json"))
    assert runs
    unmapped = [path for path in runs if json.loads(path.read_text(encoding="utf-8"))["git_commit"] not in mapping]
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=runinfo.ROOT, capture_output=True, text=True)
    if unmapped and (top.returncode != 0 or Path(top.stdout.strip()).resolve() != runinfo.ROOT.resolve()):
        # salinan tanpa .git (mis. zip lampiran): run sesudah penulisan ulang riwayat tidak bisa dicek ke riwayat
        pytest.skip("butuh riwayat git repositori ini untuk run yang tidak ada di pemetaan commit")
    for path in unmapped:
        commit = json.loads(path.read_text(encoding="utf-8"))["git_commit"]
        exists = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=runinfo.ROOT,
                                capture_output=True).returncode == 0
        assert exists, path  # run sebelum penulisan ulang riwayat dipetakan; run sesudahnya ada di riwayat
