import json

from src.eval import pilot_compare as pc

LOG = '1.2.3.4 - - [01/Jan/2020:00:00:00 +0000] "GET /?q=%3Cscript%3E HTTP/1.1" 200 5 "-" "UA"'


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _agent_row(i, label, verdicts, status):
    return {"id": i, "label": label, "status": status, "evidence": ["<script>"], "prompt_tokens": 5000,
            "completion_tokens": 300, "cost_usd": 0.002, "latency_s": 20.0, "llm_calls": 12, "tool_calls": 14,
            "klasifikasi_dipakai": len(verdicts) or 1, "pengingat_prosedur": [], "ditahan_guard": [],
            "batas_panggilan_subagen": 0,
            "verifikasi": {"putaran": len(verdicts), "penolakan": sum(not v["lolos"] for v in verdicts),
                           "batas_panggilan_verifikator": 0, "putusan": verdicts}}


def test_compare_reports_rows_rejections_and_label_history(tmp_path, monkeypatch):
    truth = tmp_path / "sample.jsonl"
    _write(truth, [{"id": "a", "label": "XSS", "raw_log_masked": LOG}, {"id": "b", "label": "NORMAL", "raw_log_masked": LOG}])
    monkeypatch.setattr(pc, "SAMPLE_PATH", truth)
    (tmp_path / "ids.json").write_text(json.dumps({"ids": ["a", "b"]}))
    rejected = {"putaran": 1, "klasifikasi_ke": 1, "lolos": False, "lolos_menurut_llm": False, "alasan": ["label salah"]}
    passed = {"putaran": 2, "klasifikasi_ke": 2, "lolos": True, "lolos_menurut_llm": True, "alasan": []}
    agent_dir = tmp_path / "pilot"
    agent_dir.mkdir()
    _write(agent_dir / "agent.jsonl", [_agent_row("a", "XSS", [rejected, passed], "ok"),
                                        _agent_row("b", "NORMAL", [{**passed, "putaran": 1, "klasifikasi_ke": 1}], "ok")])
    (agent_dir / "agent.run.json").write_text(json.dumps({"run_id": "agent-1", "git_commit": "abcdef0", "git_dirty": False,
                                                          "model": "m"}))
    single = [{"id": i, "label": label, "evidence": ["<script>"], "prompt_tokens": 940, "completion_tokens": 90,
               "cost_usd": 0.0001, "latency_s": 1.5} for i, label in (("a", "SQLI"), ("b", "NORMAL"))]
    _write(tmp_path / "llm_single.jsonl", single)
    (tmp_path / "llm_single.run.json").write_text(json.dumps({"run_id": "llm_single-1"}))
    _write(agent_dir / "llm_single.jsonl", single)
    calls = tmp_path / "calls.jsonl"
    _write(calls, [
        {"run_id": "agent-1", "id": "a", "jenis": "llm", "subagen": "klasifikasi", "putaran_verifikasi": 0,
         "respons": {"content": json.dumps({"label": "SQLI", "confidence": 0.5, "evidence": [], "explanation": "x"})}},
        {"run_id": "agent-1", "id": "a", "jenis": "llm", "subagen": "klasifikasi", "putaran_verifikasi": 1,
         "respons": {"content": json.dumps({"label": "XSS", "confidence": 0.9, "evidence": [], "explanation": "x"})}},
        {"run_id": "lain", "id": "a", "jenis": "llm", "subagen": "klasifikasi", "putaran_verifikasi": 0,
         "respons": {"content": "bukan json"}},
    ])
    assert pc.classification_history(calls, "agent-1") == {"a": ["SQLI", "XSS"]}
    text = pc.compare(tmp_path / "ids.json", agent_dir / "agent.jsonl",
                      [("C (500 penuh)", tmp_path / "llm_single.jsonl"), ("C pilot", agent_dir / "llm_single.jsonl")], calls)
    assert "| 1 | `a` | XSS | SQLI ✗ | XSS ✓ | ok | 2 | 1 |" in text
    assert "| benar (dari 2) | 1 | 1 | 2 |" in text
    assert "E benar di baris yang C (500 penuh) salah: 1 (`a`)" in text
    assert "mendelegasikan ke keempat sub-agen: 0/2 baris" in text
    assert "riwayat label klasifikasi: SQLI -> XSS" in text
    assert "label berubah setelah penolakan: 1 baris" in text
    assert "penilaian LLM verifikator: 1" in text


def test_rejection_kind_does_not_trust_llm_text_that_mimics_tool_reasons():
    llm_only = {"lolos": False, "lolos_menurut_llm": False,
                "alasan": ["schema_check menunjukkan bahwa evidence tidak ditemukan secara harfiah dalam log"]}
    assert pc._rejection_kind(llm_only) == "penilaian LLM verifikator"
    tool = {"lolos": False, "lolos_menurut_llm": True, "alasan": ["ok", "evidence tidak ditemukan di baris log: x"]}
    assert pc._rejection_kind(tool) == "evidence/skema (deterministik)"
    structured = {"lolos": False, "lolos_menurut_llm": False, "skema_valid": True, "evidence_hilang": ["x"], "alasan": []}
    assert pc._rejection_kind(structured) == "evidence/skema + penilaian LLM"


def test_rejection_without_a_verifier_verdict_is_its_own_category():
    no_verdict = {"lolos": False, "lolos_menurut_llm": False,
                  "alasan": ["verifikator tidak memberi putusan", "evidence tidak ditemukan di baris log: x"]}
    assert pc._rejection_kind(no_verdict) == "verifikator tanpa putusan + evidence/skema"


def test_deterministic_verifier_rejections_are_categorised_without_llm():
    verdict = {"lolos": False, "skema_valid": True, "evidence_hilang": ["x"],
               "alasan": ["evidence tidak ditemukan di baris log: x"], "putaran": 1, "klasifikasi_ke": 1}
    assert pc._rejection_kind(verdict) == "evidence/skema (deterministik)"
    schema = {"lolos": False, "skema_valid": False, "evidence_hilang": [], "alasan": ["schema_check gagal: bukan JSON"]}
    assert pc._rejection_kind(schema) == "evidence/skema (deterministik)"


def test_truth_can_come_from_a_split(tmp_path, monkeypatch):
    import pandas as pd

    path = tmp_path / "srbh_val.parquet"
    pd.DataFrame([{"id": "v1", "label": "XSS", "raw_log_masked": LOG, "template_key": "t"},
                  {"id": "v2", "label": "NORMAL", "raw_log_masked": LOG, "template_key": "u"}]).to_parquet(path)
    monkeypatch.setattr(pc, "split_path", lambda split: path)
    assert pc.load_truth("val", ["v2"]) == {"v2": {"id": "v2", "label": "NORMAL", "raw_log_masked": LOG}}
