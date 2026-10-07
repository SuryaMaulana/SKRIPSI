import json

import pandas as pd
import pytest

from src.data.sample import SAMPLE_COLUMNS, _json_value, cap_normal_templates, draw_sample, quotas, write_jsonl
from src.data.split import cap_rfi_templates, dedup, stratified_split


def test_dedup_keeps_first_and_drops_conflicting_lines():
    df = pd.DataFrame(
        {"row_id": range(5), "raw_log_masked": ["a", "a", "b", "c", "c"], "label": ["SQLI", "SQLI", "NORMAL", "XSS", "NORMAL"]}
    )
    kept, stats = dedup(df)
    assert kept["row_id"].tolist() == [0, 2]
    assert (stats["duplicates_dropped"], stats["conflict_rows_dropped"], stats["conflict_lines"]) == (1, 2, 1)


def test_rfi_cap_only_touches_f1_rows():
    df = pd.DataFrame(
        {
            "row_id": range(9),
            "label_rule": ["F1"] * 5 + ["F1"] * 2 + ["T1", "S1"],
            "rfi_template": ["A"] * 5 + ["B"] * 2 + ["", ""],
        }
    )
    capped, table, dropped = cap_rfi_templates(df, cap=3, random_state=42)
    assert table.to_dict("records") == [{"rfi_template": "A", "before": 5, "after": 3}, {"rfi_template": "B", "before": 2, "after": 2}]
    assert len(dropped) == 2 and set(dropped["rfi_template"]) == {"A"}
    assert {7, 8} <= set(capped["row_id"]) and len(capped) == 7
    again, _, _ = cap_rfi_templates(df, cap=3, random_state=42)
    assert again["row_id"].tolist() == capped["row_id"].tolist()


def test_stratified_split_proportions():
    df = pd.DataFrame({"row_id": range(200), "label": ["SQLI"] * 100 + ["NORMAL"] * 100})
    train, val, test = stratified_split(df)
    assert (len(train), len(val), len(test)) == (140, 30, 30)
    assert (test["label"] == "SQLI").sum() == 15
    assert set(train.row_id).isdisjoint(test.row_id) and set(val.row_id).isdisjoint(test.row_id)
    assert test["row_id"].is_monotonic_increasing


def make_test_split(n_xss=57):
    rows = []
    for cls, n in [("SQLI", 150), ("XSS", n_xss), ("PATH_TRAVERSAL", 120), ("CMD_INJECTION", 100), ("WEB_SCANNING", 100), ("NORMAL", 300)]:
        for i in range(n):
            normal = cls == "NORMAL"
            rows.append({
                "row_id": len(rows), "label": cls, "weak_evidence": cls == "SQLI" and i < 50, "method": "GET",
                "path": f"/p{i % 40}" if normal else "/x", "query": "a=1" if normal and i % 7 == 0 else "",
            })
    return pd.DataFrame(rows)


def test_quotas_give_all_xss_and_split_the_rest_evenly():
    q = quotas(make_test_split())
    assert q == {"SQLI": 89, "XSS": 57, "PATH_TRAVERSAL": 89, "CMD_INJECTION": 89, "WEB_SCANNING": 88, "NORMAL": 88}
    assert sum(q.values()) == 500


def normal_pool(spec):
    """spec: {path: (baris ber-query, baris tanpa query)}"""
    rows = []
    for path, (n_q, n_plain) in spec.items():
        rows += [{"method": "GET", "path": path, "query": "q=1"} for _ in range(n_q)]
        rows += [{"method": "GET", "path": path, "query": ""} for _ in range(n_plain)]
    return pd.DataFrame(rows).rename_axis("row_id").reset_index()


def test_normal_template_cap_is_proportional_with_query_rounded_up():
    pool = normal_pool({"/a": (3, 7), "/b": (0, 3), "/c": (5, 1), "/d": (1, 7), "/e": (0, 40)})
    capped = cap_normal_templates(pool, per_template=5, random_state=42)
    counts = capped.assign(q=capped["query"] != "").groupby("path")["q"].agg(["size", "sum"])
    assert counts.loc["/a"].tolist() == [5, 2]  # ceil(5*3/10) = 2 ber-query
    assert counts.loc["/b"].tolist() == [3, 0]  # templat kecil diambil semua
    assert counts.loc["/c"].tolist() == [5, 5]  # ceil(5*5/6) = 5 ber-query
    assert counts.loc["/d"].tolist() == [5, 1]  # ceil(5*1/8) = 1 ber-query
    assert counts.loc["/e"].tolist() == [5, 0]
    again = cap_normal_templates(pool, per_template=5, random_state=42)
    assert sorted(again["row_id"]) == sorted(capped["row_id"])


def test_sample_excludes_weak_sqli_caps_normal_templates_and_is_deterministic():
    test = make_test_split()
    sample, pools = draw_sample(test)
    assert len(sample) == 500 and (sample["label"] == "XSS").sum() == 57
    assert not sample.loc[sample["label"] == "SQLI", "weak_evidence"].any()
    normal = sample[sample["label"] == "NORMAL"]
    assert len(normal) == 88 and normal.groupby("path").size().max() <= 5
    assert pools["NORMAL_before_template_cap"] == 300 and pools["NORMAL"] == 200 and pools["SQLI"] == 100
    assert draw_sample(test)[0]["row_id"].tolist() == sample["row_id"].tolist()


def test_sample_fails_when_pool_too_small():
    with pytest.raises(ValueError, match="kurang dari kuota"):
        draw_sample(make_test_split().query("label != 'CMD_INJECTION' or row_id % 10 == 0"))


def test_jsonl_has_only_masked_input_and_eval_columns(tmp_path):
    record = {c: "x" for c in SAMPLE_COLUMNS}
    record.update(bytes=pd.NA, raw_log="asli", time="t", timestamp=pd.Timestamp("2020-07-17", tz="UTC"), protocol="HTTP/1.0",
                  sess_req_60s=3)
    path = tmp_path / "s.jsonl"
    write_jsonl(pd.DataFrame([record]).astype({"bytes": "Int64"}), path)
    out = json.loads(path.read_text())
    assert list(out) == SAMPLE_COLUMNS and out["bytes"] is None
    assert not {"raw_log", "time", "timestamp", "protocol"} & set(out) and not any(k.startswith("sess_") for k in out)
    assert {"raw_log_masked", "label", "template_key"} <= set(out)


def test_weak_sqli_option():
    test = make_test_split()
    included, pools = draw_sample(test, weak_sqli="include")
    assert pools["SQLI"] == 150 and len(included) == 500
    with pytest.raises(ValueError, match="sample_weak_sqli"):
        draw_sample(test, weak_sqli="proporsional")


def test_jsonl_is_written_in_shuffled_order(tmp_path):
    sample, _ = draw_sample(make_test_split())
    sample = sample.assign(**{c: "x" for c in SAMPLE_COLUMNS if c not in sample.columns})
    sample["id"] = sample["row_id"].map(lambda i: f"r{i:04d}")
    path = tmp_path / "s.jsonl"
    write_jsonl(sample, path)
    ids = [json.loads(line)["id"] for line in path.read_text().splitlines()]
    assert sorted(ids) == sorted(sample["id"]) and ids != sorted(ids)


def test_json_value_handles_missing_scalars():
    assert _json_value(pd.NaT) is None and _json_value(pd.NA) is None and _json_value(float("nan")) is None
    assert _json_value(pd.Timestamp("2020-07-17", tz="UTC")) == "2020-07-17T00:00:00+00:00"
