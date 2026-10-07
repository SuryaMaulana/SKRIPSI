from types import SimpleNamespace

import pandas as pd
import pytest
import yaml

from src.data.gate.common import entries
from src.data.labels import EXCLUDED, evaluate_rules, load_mapping, map_labels_only, resolve, validate_columns, validate_rules

NORMAL = "000 - Normal"
SQL = "66 - SQL Injection"
CMD = "88 - OS Command Injection"
TRAV = "126 - Path Traversal"
SPLIT = "34 - HTTP Response Splitting"
PRIORITY = ["CMD_INJECTION", "SQLI", "XSS", "PATH_TRAVERSAL", "WEB_SCANNING"]


def write_yaml(tmp_path, **overrides):
    spec = {
        "normal_label": NORMAL,
        "priority": PRIORITY,
        "labels": {
            NORMAL: {"capec": "000", "target": "NORMAL", "rules": [{"id": "N4"}]},
            SQL: {"capec": 66, "target": "SQLI", "rules": [{"id": "S1"}, {"id": "S5"}]},
            CMD: {"capec": 88, "target": "CMD_INJECTION"},
            TRAV: {"capec": 126, "target": "PATH_TRAVERSAL"},
            SPLIT: {"capec": 34, "target": "UNMAPPED"},
        },
    }
    spec.update(overrides)
    path = tmp_path / "label_mapping.yaml"
    path.write_text(yaml.safe_dump(spec, allow_unicode=True))
    return path


def frame(rows):
    cols = [NORMAL, SQL, CMD, TRAV, SPLIT]
    return pd.DataFrame([{c: str(int(c in active)) for c in cols} for active in rows])


def test_labels_only_priority_unmapped_and_normal(tmp_path):
    mapping = load_mapping(write_yaml(tmp_path))
    out = map_labels_only(frame([{NORMAL}, {SQL}, {SQL, CMD}, {CMD, TRAV}, {SPLIT}, {SQL, SPLIT}]), mapping)
    assert out["label"].tolist() == ["NORMAL", "SQLI", "CMD_INJECTION", "CMD_INJECTION", EXCLUDED, "SQLI"]
    assert out["capec_labels"].tolist() == ["", "66", "66+88", "88+126", "34", "66+34"]


def test_mapping_metadata(tmp_path):
    mapping = load_mapping(write_yaml(tmp_path, status="disetujui", evidence_gate=True))
    assert mapping.status == "disetujui" and mapping.evidence_gate
    assert mapping.rules[SQL] == {"S1": "", "S5": ""}
    assert load_mapping(write_yaml(tmp_path)).status == "usulan"


def test_unknown_or_missing_label_columns_fail(tmp_path):
    mapping = load_mapping(write_yaml(tmp_path))
    with pytest.raises(ValueError, match="tanpa entri YAML"):
        validate_columns([NORMAL, SQL, CMD, TRAV, SPLIT, "999 - Baru"], mapping)
    with pytest.raises(ValueError, match="tanpa kolom di dataset"):
        validate_columns([NORMAL, SQL, CMD, TRAV], mapping)


def test_invalid_target_or_priority_fail(tmp_path):
    bad_target = {NORMAL: {"capec": "000", "target": "NORMAL"}, SQL: {"capec": 66, "target": "SQL"}}
    with pytest.raises(ValueError, match="Target tidak valid"):
        load_mapping(write_yaml(tmp_path, labels=bad_target))
    with pytest.raises(ValueError, match="priority"):
        load_mapping(write_yaml(tmp_path, priority=["SQLI", "XSS"]))


def test_rule_ids_must_match_code(tmp_path):
    mapping = load_mapping(write_yaml(tmp_path))
    ok = SimpleNamespace(__name__="sqli", LABELS=(SQL,), RULES={"S1": "", "S5": ""})
    validate_rules(mapping, [ok])
    with pytest.raises(ValueError, match="tidak sama"):
        validate_rules(mapping, [SimpleNamespace(__name__="sqli", LABELS=(SQL,), RULES={"S1": ""})])


def test_resolve_priority_reasons_neutral_and_weak():
    e = pd.concat([
        entries([0], SQL, candidate="SQLI", rule_id="S1"),
        entries([1], CMD, candidate="CMD_INJECTION", rule_id="C1"),
        entries([1], TRAV, candidate="PATH_TRAVERSAL", rule_id="T2"),
        entries([2], SPLIT, reason="OUT_OF_SCOPE", rule_id="R1"),
        entries([2], SQL, reason="HIDDEN_EVIDENCE", rule_id="S5"),
        entries([3], SQL, rule_id="S7"),
        entries([4], NORMAL, candidate="NORMAL", rule_id="N4"),
        entries([5], NORMAL, reason="LABELER_BLIND", rule_id="N1"),
        entries([6], SQL, candidate="SQLI", rule_id="S2", weak=True),
        entries([7], TRAV, reason="HIDDEN_EVIDENCE", rule_id="T4"),
        entries([7], SQL, candidate="SQLI", rule_id="S1"),
    ])
    out = resolve(e, pd.RangeIndex(8), PRIORITY)
    assert out["label"].tolist() == ["SQLI", "CMD_INJECTION", EXCLUDED, EXCLUDED, "NORMAL", EXCLUDED, "SQLI", "SQLI"]
    assert out["label_rule"].tolist() == ["S1", "C1", "R1", "", "N4", "N1", "S2", "S1"]
    assert out["exclusion_reason"].tolist() == ["", "", "OUT_OF_SCOPE", "NO_EVIDENCE", "", "LABELER_BLIND", "", ""]
    assert out["weak_evidence"].tolist() == [False, False, False, False, False, False, True, False]
    assert out["candidates"].iat[1] == "CMD_INJECTION+PATH_TRAVERSAL"


def test_evaluate_rules_requires_one_entry_per_active_label():
    df = frame([{SQL}, {SQL}])
    missing = SimpleNamespace(LABELS=(SQL,), RULES={}, evaluate=lambda d: entries(d.index[:1], SQL, rule_id="S1"))
    with pytest.raises(ValueError, match="tepat satu entri"):
        evaluate_rules(df.assign(request_http_request="", request_user_agent="", request_referer="", request_cookie="", request_body=""), [missing])
