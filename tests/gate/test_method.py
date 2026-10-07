import pandas as pd

from src.data.gate.common import OUTPUT_COLUMNS, multi_decode
from src.data.gate.method import LABELS, RULES, evaluate

L272, L274 = LABELS
OUTCOME = {
    "V1": ("WEB_SCANNING", ""), "P1": ("WEB_SCANNING", ""), "P2": ("", "NO_EVIDENCE"),
    "P3": ("", "HIDDEN_EVIDENCE"), "P4": ("", "OUT_OF_SCOPE"),
}
FORM = "application/x-www-form-urlencoded"

# row_id -> (field mentah yang diubah dari bawaan "GET / ke test-site.com", rule_id yang diharapkan untuk label 272)
CASES = {
    1: ({"request_http_method": "PROPFIND", L274: 1}, "P1"),
    2: ({"request_http_request": "/blog/wp-login.php.bak"}, "P1"),
    3: ({"request_http_request": "/blog/xmlrpc.SWP"}, "P1"),
    4: ({"request_http_request": "/.svn/wc%2Edb"}, "P1"),
    5: ({"request_http_request": "/blog/index.php~", "request_host": "172.26.0.1"}, "P1"),
    6: ({"request_http_request": "http://165.175.88.110:41200/pass"}, "P1"),
    7: ({"request_http_request": "?feed=rss"}, "P1"),
    8: ({"request_http_request": "/backup.sql?id=%00"}, "P1"),
    9: ({"request_http_request": "/blog/www.google.com", "request_host": "172.26.0.1"}, "P4"),
    10: ({"request_http_request": "/tiki-listmovies.php?movie=../../etc/passwd%001234"}, "P4"),
    11: ({"request_http_request": "/img.bak%00.png"}, "P4"),
    12: ({"request_host": "172.26.0.1:80"}, "P3"),
    13: ({"request_host": ""}, "P3"),
    14: ({"request_http_method": "POST", "request_body": "password_current=%00", "request_content_type": FORM}, "P3"),
    15: ({"request_http_method": "OPTIONS", "request_body": "comment=", "request_content_type": " ; charset=UTF-8"}, "P3"),
    16: ({"request_http_request": "/blog/wp-login.php.orig"}, "P2"),
    17: ({"request_http_method": "POST", "request_body": "log=a&pwd=b", "request_content_type": FORM}, "P2"),
    18: ({"request_http_request": "/x%252Ebak"}, "P2"),  # satu lapis unquote -> 'x%2Ebak'; uri_dec -> 'x.bak'
    19: ({"request_http_request": "/a.bak%3Fx=1"}, "P2"),  # '%3F' bukan pemisah query: ekstensi 'bak?x=1'
    20: ({"request_http_request": "/dump.sqlite"}, "P2"),  # fullmatch, bukan substring 'sql'
    21: ({"request_http_request": "/boot.ini"}, "P1"),
    22: ({"request_http_request": "/a.old"}, "P1"),
    23: ({"request_http_request": "/a.backup"}, "P1"),
    24: ({"request_http_request": "/a.log"}, "P1"),
    25: ({"request_http_request": "/_vti_pvt/users.pwd"}, "P1"),
    26: ({"request_http_request": "/_vti_bin/shtml.dll"}, "P1"),
    27: ({"request_http_request": "/db/users.mdb"}, "P1"),
}


def frame(rows):
    """Baris sintetis berindeks row_id dengan semua kolom yang dibaca modul; bawaan: hanya label 272 aktif."""
    base = {
        "request_http_method": "GET", "request_http_request": "/", "request_host": "test-site.com",
        "request_content_type": "", "request_body": "", L272: 1, L274: 0,
    }
    df = pd.DataFrame.from_dict({rid: {**base, **fields} for rid, fields in rows.items()}, orient="index")
    df["uri_dec"] = [multi_decode(value) for value in df["request_http_request"]]
    df["body_dec"] = [multi_decode(value) for value in df["request_body"]]
    return df


def test_rules_p1_to_p4_and_v1():
    out = evaluate(frame({rid: fields for rid, (fields, _) in CASES.items()}))
    assert list(out.columns) == OUTPUT_COLUMNS and not out["weak"].any()
    assert len(out) == len(CASES) + 1 and set(out["rule_id"]) == set(RULES)
    assert all(OUTCOME[row.rule_id] == (row.candidate, row.reason) for row in out.itertuples())
    assert out.loc[out["label"] == L272, "rule_id"].to_dict() == {rid: rule for rid, (_, rule) in CASES.items()}


def test_label_274_always_web_scanning_and_unlabeled_rows_skipped():
    out = evaluate(frame({
        1: {"request_http_method": "PROPFIND", L272: "1", L274: "1"},
        2: {"request_http_method": "TRACK", "request_host": "", L272: "0", L274: "1"},
        3: {"request_http_request": "/blog/wp-login.php.bak", L272: "0", L274: "0"},
    }))
    assert sorted(zip(out.index, out["label"], out["rule_id"])) == [(1, L272, "P1"), (1, L274, "V1"), (2, L274, "V1")]


def test_values_differing_only_after_nul_are_judged_separately():
    df = frame({
        1: {"request_http_request": "/blog/?p=1%00x"},
        2: {"request_http_request": "/blog/?p=1"},
        3: {"request_body": "a=1%00x", "request_content_type": "text/plain"},
        4: {"request_body": "a=1", "request_content_type": "text/plain"},
    })
    assert "\x00" in df.at[1, "uri_dec"] and "\x00" in df.at[3, "body_dec"]
    assert evaluate(df)["rule_id"].to_dict() == {1: "P4", 2: "P2", 3: "P3", 4: "P2"}
