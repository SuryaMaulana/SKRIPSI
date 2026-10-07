import pandas as pd
import yaml

from src.data.config import LABEL_MAPPING_SRC
from src.data.gate.common import OUTPUT_COLUMNS, multi_decode
from src.data.gate.traversal import LABELS, RULES, evaluate

LABEL = LABELS[0]
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
NMAP = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
T1 = ("PATH_TRAVERSAL", "", "T1")
T2 = ("PATH_TRAVERSAL", "", "T2")
T3 = ("WEB_SCANNING", "", "T3")
T4 = ("", "HIDDEN_EVIDENCE", "T4")

# row_id -> (request line mentah, ua_dec, (candidate, reason, rule_id) yang diharapkan)
CASES = {
    1: ("/blog/index.php/2020/" + "..%5C" * 16 + "/04/ipsa-repellat/feed", FIREFOX, T1),  # hanya bentuk ter-decode
    2: ("/blog/?p=..%252F..%252F..%252Fetc%252Fpasswd", FIREFOX, T1),
    3: ("/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/index.php", NMAP, T1),  # overlong: hanya bentuk mentah cocok
    4: ("/blog/index.php/my-account/", "../../../../../../etc/passwd", T1),
    5: ("/blog/index.php/page/2/?s=etc%2Fpasswd", FIREFOX, T1),
    6: ("/blog/post.php/?action=edit%3Bcat+%2Fetc%2Fpasswd%3B&post=1", FIREFOX, T2),
    7: ("/blog/?a=..%2F..%2Fetc%2Fpasswd&b=edit%7Ccat+%2Fetc%2Fpasswd%23", FIREFOX, T2),  # T2 mengalahkan T1
    8: ("/blog/wp-content/.svn/wc.db", FIREFOX, T3),
    9: ("/%23wp-config.php%23", NMAP, T3),
    10: ("/.svn/text-base/Web.config.svn-base", NMAP, T3),  # T3 mengalahkan berkas OS (web.config)
    11: ("/blog/.git/index", "..\\..\\..\\..\\", T1),  # traversal di UA mengalahkan T3
    12: ("/blog/?file=.htaccess", FIREFOX, T4),  # T3 hanya melihat path
    13: ("/blog/index.php/my-account/edit-profile/", FIREFOX, T4),
    14: ("/blog/%2Esvn/entries", FIREFOX, T3),  # path ter-decode
    15: ("/blog/index.php/nihil-dolorem/feed/.htaccess", FIREFOX, T3),  # probe .htaccess ZAP
    16: ("/.gitignore", NMAP, T3),  # Nmap NSE
    17: ("/blog/post.php/?action=edit%0Acat+%2Fetc%2Fpasswd%0A&post=1", FIREFOX, T2),  # pemisah newline
}


def frame(rows):
    """Baris sintetis berindeks row_id dengan semua kolom yang dibaca modul; uri_dec seperti `add_decoded`, label
    int8 seperti di pipeline."""
    return pd.DataFrame.from_dict(
        {rid: {LABEL: 1, "request_http_request": request, "uri_dec": multi_decode(request), "ua_dec": ua}
         for rid, (request, ua) in rows.items()},
        orient="index",
    ).astype({LABEL: "int8"})


def test_rules_t1_to_t4_and_precedence():
    out = evaluate(frame({rid: (request, ua) for rid, (request, ua, _) in CASES.items()}))
    assert list(out.columns) == OUTPUT_COLUMNS
    assert sorted(out.index) == sorted(CASES)
    assert (out["label"] == LABEL).all() and not out["weak"].any()
    got = {rid: tuple(row) for rid, row in out[["candidate", "reason", "rule_id"]].iterrows()}
    assert got == {rid: expected for rid, (_, _, expected) in CASES.items()}
    assert set(out["rule_id"]) == set(RULES)


def test_values_differing_only_after_nul_are_judged_separately():
    df = frame({
        1: ("/a.js?ver=1%00..%2F..%2Fetc%2Fpasswd", FIREFOX),
        2: ("/a.js?ver=1%00", FIREFOX),
        3: ("/blog/", "Mozilla/5.0\x00../../../etc/passwd"),
        4: ("/blog/", "Mozilla/5.0\x00"),
    })
    assert df.at[1, "uri_dec"] == "/a.js?ver=1\x00../../etc/passwd"
    assert evaluate(df)["rule_id"].to_dict() == {1: "T1", 2: "T4", 3: "T1", 4: "T4"}


def test_string_labels_and_unlabeled_rows_are_skipped():
    df = frame({1: CASES[6][:2], 2: CASES[6][:2]})
    df[LABEL] = ["1", "0"]
    assert evaluate(df)["rule_id"].to_dict() == {1: "T2"}
    empty = evaluate(df.loc[[2]])
    assert empty.empty and list(empty.columns) == OUTPUT_COLUMNS


def test_rule_ids_match_yaml():
    spec = yaml.safe_load(LABEL_MAPPING_SRC.read_text(encoding="utf-8"))
    assert [rule["id"] for rule in spec["labels"][LABEL]["rules"]] == list(RULES)
