import pandas as pd

from src.data.gate.common import OUTPUT_COLUMNS, multi_decode
from src.data.gate.protocol import LABELS, RULES, evaluate

L34, L33 = LABELS
TAMPER = "Set-cookie%3A+Tamper%3D16ddfcdc-f5a9-4b45-b782-cc6315615757"
COMMENT = "/blog/wp-comments-post.php"
PHP_CGI = "/blog/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
REASON = {"R0": "", "R1": "OUT_OF_SCOPE", "R2": "LABEL_MISMATCH", "R3": "HIDDEN_EVIDENCE"}

# row_id -> (field mentah yang diisi, rule_id yang diharapkan untuk setiap label aktif)
CASES = {
    1: ({"request_http_request": f"/blog/index.php/any%3F%0D%0A{TAMPER}%0D%0A/at-quos"}, "R1"),
    2: ({"request_http_request": f"/blog/dashicons.min.css?ver=any%0D%0A{TAMPER}", L33: 1}, "R1"),
    3: ({"request_http_request": "/blog/uploads/a.png%0Acat+%2Fetc%2Fpasswd%0A"}, "R2"),
    4: ({"request_http_request": "/blog/index.php%0Asleep+15%0A/2020/04/04/hic"}, "R2"),
    5: ({"request_http_request": "/blog/index.php/any%3F%0Asleep+15%0A/feed"}, "R2"),  # '%3F' tetap bagian path
    6: ({"request_http_request": COMMENT, "request_body": f"submit=Post+Comment&comment_parent=any%3F%0D%0A{TAMPER}",
         L33: 1}, "R3"),
    7: ({"request_http_request": COMMENT, "request_body": "comment_parent=0%0Asleep+15%0A", L34: 0, L33: 1}, "R3"),
    8: ({"request_http_request": PHP_CGI, "request_body": "<?php exec('echo jrpk',$colm);echo join(\"", L34: 0, L33: 1},
        "R0"),
    9: ({"request_http_request": "/blog/?p=1%0Asleep+15%0A"}, "R0"),  # R2 hanya melihat path
    10: ({"request_http_request": f"/a.png%0Acat+%2Fetc%2Fpasswd%0A?x=any%0D%0A{TAMPER}"}, "R2"),  # R2 mengalahkan R1
    11: ({"request_http_request": f"/blog/{TAMPER}"}, "R0"),  # penanda tanpa CR/LF di depannya: netral
}


def frame(rows):
    """Baris sintetis berindeks row_id dengan semua kolom yang dibaca modul; bawaan: hanya label 34 aktif."""
    base = {"request_http_request": "/", "request_body": "", L34: 1, L33: 0}
    df = pd.DataFrame.from_dict({rid: {**base, **fields} for rid, fields in rows.items()}, orient="index")
    df["uri_dec"] = [multi_decode(value) for value in df["request_http_request"]]
    df["body_dec"] = [multi_decode(value) for value in df["request_body"]]
    return df


def test_rules_r0_to_r3_apply_to_each_active_label():
    df = frame({rid: fields for rid, (fields, _) in CASES.items()})
    out = evaluate(df)
    assert list(out.columns) == OUTPUT_COLUMNS
    assert (out["candidate"] == "").all() and not out["weak"].any()
    expected = {
        (rid, label): (REASON[rule], rule)
        for rid, (_, rule) in CASES.items()
        for label in LABELS
        if df.loc[rid, label] == 1
    }
    assert {(row.Index, row.label): (row.reason, row.rule_id) for row in out.itertuples()} == expected
    assert set(out["rule_id"]) == set(RULES)


def test_values_differing_only_after_nul_are_judged_separately():
    df = frame({
        1: {"request_http_request": f"/a%00b/any%3F%0A{TAMPER}"},
        2: {"request_http_request": "/a%00b.png%0Acat+%2Fetc%2Fpasswd%0A"},
        3: {"request_http_request": "/blog/wp-login.php", "request_body": f"log=a%00b&email=any%0D%0A{TAMPER}"},
        4: {"request_http_request": "/a%00b/index.php", "request_body": "log=a%00b"},
    })
    assert all("\x00" in value for value in df["uri_dec"][[1, 2, 4]]) and "\x00" in df.loc[3, "body_dec"]
    assert evaluate(df)["rule_id"].to_dict() == {1: "R1", 2: "R2", 3: "R3", 4: "R0"}


def test_string_labels_and_unlabeled_rows_skipped():
    probe = f"/any%3F%0A{TAMPER}"
    df = frame({
        1: {"request_http_request": probe, L34: "1", L33: "1"},
        2: {"request_http_request": probe, L34: "0", L33: "0"},
    })
    out = evaluate(df)
    assert sorted(zip(out.index, out["label"], out["rule_id"])) == [(1, L33, "R1"), (1, L34, "R1")]
    empty = evaluate(df.loc[[2]])
    assert empty.empty and list(empty.columns) == OUTPUT_COLUMNS
