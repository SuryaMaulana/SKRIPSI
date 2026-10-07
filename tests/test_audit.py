import pandas as pd
import pytest

from src.data.audit import content_key, content_overlap, normal_windows, offset_runs, template_concentration, time_proxy

LOG = '1.2.3.4 - - [17/Jul/2020:12:00:0{s} +0000] "GET /a HTTP/1.1" 200 5 "-" "UA"'


def test_content_key_drops_only_the_time_field():
    keys = content_key(pd.Series([LOG.format(s=1), LOG.format(s=2), LOG.format(s=1).replace("/a", "/b")]))
    assert keys.iat[0] == keys.iat[1] != keys.iat[2]
    assert "[" not in keys.iat[0] and '"GET /a HTTP/1.1"' in keys.iat[0]


def test_content_overlap_counts_train_twins_per_class():
    part = lambda logs, labels: pd.DataFrame({"raw_log": logs, "label": labels})
    train = part([LOG.format(s=1)], ["NORMAL"])
    test = part([LOG.format(s=5), LOG.format(s=6).replace("/a", "/z")], ["NORMAL", "SQLI"])
    out = content_overlap({"train": train, "val": test.iloc[:0], "test": test}, test)
    assert out["test"]["NORMAL"] == (1, 1) and out["test"]["SQLI"] == (0, 1) and out["test"]["_total"] == (1, 2)
    assert out["sample"]["_total"] == (1, 2) and out["distinct_contents"] == 2


def test_offset_runs_merge_across_empty_rows_and_find_redated_copies():
    times = ["17/Jul/2020:12:00:00 +0100", "17/Jul/2020:12:00:05 +0200", "", "17/Jul/2020:12:00:09 +0200",
             "01/Nov/2020:12:00:00 +0100", "01/Nov/2020:12:00:05 +0100", "19/Jul/2020:23:00:00 +0100"]
    raw = pd.DataFrame({
        "timestamp": times,
        "request_http_request": ["/a", "/b", "", "/c", "/a", "/b", "/d"],
        "request_user_agent": ["u", "u", "", "u", "u", "u", "u"],
    })
    out = offset_runs(raw)
    assert [(r["offset"], r["first_row"], r["last_row"], r["rows"]) for r in out["runs"]] == [
        ("+0100", 0, 0, 1), ("+0200", 1, 3, 2), ("+0100", 4, 6, 3)]
    assert (out["nov_rows"], out["nov_first_row"], out["nov_copies_of_first_rows"]) == (2, 4, 2)


def test_time_proxy_uses_majority_label_of_the_same_minute():
    ts = lambda m: pd.Timestamp(f"2020-07-17 10:{m:02d}:30", tz="UTC")
    train = pd.DataFrame({"timestamp": [ts(1), ts(1), ts(2)], "label": ["SQLI", "SQLI", "NORMAL"]})
    sample = pd.DataFrame({"timestamp": [ts(1), ts(2), ts(3)], "label": ["SQLI", "XSS", "NORMAL"]})
    out = time_proxy(train, sample)
    assert out["accuracy"] == pytest.approx(1 / 3)
    assert list(out["days"].columns) == ["17 Jul"]


def test_normal_windows_counts_scan_window_before_and_after_template_cap():
    ts = lambda day: pd.Timestamp(f"2020-07-{day} 10:00:00", tz="UTC")
    rows = [("NORMAL", ts(17), f"/s{i}") for i in range(3)] + [("NORMAL", ts(21), "/g")] * 8 + [("SQLI", ts(18), "/x")]
    test = pd.DataFrame(rows, columns=["label", "timestamp", "path"]).assign(method="GET", query="")
    out = normal_windows(test)
    assert out["pool"] == {"rows": 11, "scan_rows": 3, "scan_templates": 3, "other_templates": 1}
    assert out["capped"] == {"rows": 8, "scan_rows": 3, "scan_templates": 3, "other_templates": 1}


def test_kish_effective_n():
    rows = [{"label": "WEB_SCANNING", "label_rule": "V1", "method": m, "path": "/x", "query": "", "user_agent": "",
             "referer": "", "rfi_template": ""} for m in ["PUT"] * 3 + ["LOCK"]]
    rows += [{"label": c, "label_rule": "", "method": "GET", "path": f"/{c}", "query": "", "user_agent": "", "referer": "",
              "rfi_template": ""} for c in ["SQLI", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "NORMAL"]]
    conc = template_concentration(pd.DataFrame(rows)).set_index("kelas")
    ws = conc.loc["WEB_SCANNING"]
    assert (ws["baris"], ws["templat"], ws["terbesar"], ws["terbesar_n"]) == (4, 2, "V1:PUT", 3)
    assert ws["n_eff"] == pytest.approx(16 / 10)
