import pandas as pd
import yaml

from src.data.config import LABEL_MAPPING_SRC
from src.data.gate.common import OUTPUT_COLUMNS
from src.data.gate.sqli import LABELS, RULES, evaluate

LABEL = LABELS[0]
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
NMAP = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
TEXT = [
    "uri_dec", "ref_dec", "body_dec", "cookie_dec", "request_host", "request_origin", "request_content_type",
    "request_accept", "request_accept_language", "request_accept_encoding", "request_connection", "request_do_not_track",
]
S1 = ("SQLI", "", "S1", False)
S2 = ("SQLI", "", "S2", True)
S3 = ("", "LABEL_MISMATCH", "S3", False)
S4 = ("", "OUT_OF_SCOPE", "S4", False)
S5 = ("", "HIDDEN_EVIDENCE", "S5", False)
S6 = ("", "NO_EVIDENCE", "S6", False)
S7 = ("", "", "S7", False)
SCANNER = {"request_user_agent": NMAP, "ua_dec": NMAP}

# row_id -> (field yang diisi, (candidate, reason, rule_id, weak) yang diharapkan)
CASES = {
    1: ({"uri_dec": "/blog' AND 1234=1234-- -/index.php/2020/04/"}, S1),  # sqlmap
    2: ({"ua_dec": FIREFOX + "' OR '1'='1' -- "}, S1),  # ZAP di UA
    3: ({"uri_dec": "/blog/wp-login.php?action=lostpassword / sleep(15) "}, S1),  # varian di luar templat
    4: ({"uri_dec": "/blog and 0 in (select sleep(15) ) -- ;sleep 15;/x"}, S1),  # SQL menang atas CMD
    5: ({"uri_dec": "/blog;sleep 15;/wp-content/uploads/"}, S3),
    6: ({"ref_dec": "'\"<script>alert(1);</script>"}, S3),  # XSS di Referer
    7: ({"uri_dec": "/blog/etc/passwd/my-account/"}, S3),
    8: ({"uri_dec": "/${@print(chr(122).chr(97))}/etc/passwd"}, S4),  # PHP mendahului traversal
    9: ({"uri_dec": "/etc/passwd\r\nSet-cookie: Tamper=1234"}, S3),  # traversal mendahului CRLF
    10: ({"uri_dec": "/blog/0;URL='http://1234.owasp.org'/index.php"}, S4),
    11: ({"uri_dec": "/blog/]]>/2020/04/"}, S4),
    12: ({"uri_dec": "/blog/?url=http://www.example.com"}, S4),
    13: ({"uri_dec": "/blog/index.php/'/my-account/"}, S2),  # segmen hanya metakarakter
    14: ({"uri_dec": "/blog/wp-login.php?action=lostpassword%"}, S2),  # metakarakter di akhir nilai
    15: ({"uri_dec": "/blogNULL/index.php"}, S2),
    16: ({"uri_dec": "/blognull/index.php"}, S6),  # mode append hanya NULL huruf besar
    17: ({"ua_dec": FIREFOX + "'"}, S6),  # metakarakter hanya dihitung di URI
    18: ({"uri_dec": "/blog/wp-login.php", "body_dec": "log=admin' OR '1'='1' -- &pwd=x"}, S5),
    19: ({"uri_dec": "/blog/", "request_accept": "text/html AND 1=1 -- "}, S5),
    20: ({"uri_dec": "/blog/", "body_dec": "s=x'&submit=Search"}, S5),  # nilai metakarakter di body
    21: ({"uri_dec": "/blog/", "body_dec": "url=http://www.example.com"}, S6),  # URL form biasa bukan probe
    22: ({"uri_dec": "/wp-content/plugins/all-in-one-seo-pack/", **SCANNER}, S7),
    23: ({"uri_dec": "/blog/", "body_dec": "log=' OR '1'='1", **SCANNER}, S5),  # S5 mendahului S7
    24: ({"uri_dec": "/blog/index.php/my-account/edit-profile/"}, S6),
    25: ({"uri_dec": "/blog/", "cookie_dec": "wordpress_test_cookie=WP Cookie check' OR '1'='1"}, S5),  # hanya di cookie
    26: ({"uri_dec": "/blog/", "cookie_dec": "wp_lang=en'"}, S5),  # nilai metakarakter di cookie
}


def frame(rows):
    """Baris sintetis berindeks row_id dengan semua kolom yang dibaca modul; bawaan: UA Firefox, field lain kosong."""
    base = {LABEL: 1, "request_user_agent": FIREFOX, "ua_dec": FIREFOX, **dict.fromkeys(TEXT, "")}
    return pd.DataFrame.from_dict({rid: {**base, **fields} for rid, fields in rows.items()}, orient="index")


def test_rules_s1_to_s7_and_precedence():
    out = evaluate(frame({rid: fields for rid, (fields, _) in CASES.items()}))
    assert list(out.columns) == OUTPUT_COLUMNS
    assert sorted(out.index) == sorted(CASES) and (out["label"] == LABEL).all()
    got = {rid: tuple(row) for rid, row in out[["candidate", "reason", "rule_id", "weak"]].iterrows()}
    assert got == {rid: expected for rid, (_, expected) in CASES.items()}
    assert set(out["rule_id"]) == set(RULES)


def test_values_differing_only_after_nul_are_judged_separately():
    out = evaluate(frame({
        1: {"uri_dec": "/\x00/wp-admin/load-styles.php?c=0&dir=ltr"},
        2: {"uri_dec": "/\x00/wp-admin/load-styles.php?c=0' AND 1234=1234-- -"},
        3: {"uri_dec": "/"},
        4: {"uri_dec": "/blog/", "body_dec": "log=\x00' OR '1'='1"},
        5: {"uri_dec": "/blog/", "body_dec": "log=\x00"},
    }))
    assert out["rule_id"].to_dict() == {1: "S6", 2: "S1", 3: "S6", 4: "S5", 5: "S6"}


def test_string_labels_and_unlabeled_rows_are_skipped():
    df = frame({1: CASES[1][0], 2: CASES[1][0]})
    df[LABEL] = ["1", "0"]
    assert evaluate(df)["rule_id"].to_dict() == {1: "S1"}
    empty = evaluate(df.loc[[2]])
    assert empty.empty and list(empty.columns) == OUTPUT_COLUMNS


def test_rule_ids_match_yaml():
    spec = yaml.safe_load(LABEL_MAPPING_SRC.read_text(encoding="utf-8"))
    assert [rule["id"] for rule in spec["labels"][LABEL]["rules"]] == list(RULES)
