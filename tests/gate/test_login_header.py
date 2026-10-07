import pandas as pd

from src.data.gate.common import OUTPUT_COLUMNS
from src.data.gate.login_header import LABELS, RULES, evaluate

L16, L153 = LABELS
FF70 = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
FF62 = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0"
FF73 = "Mozilla/5.0 (X11; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0"
LOGIN = "http://test-site.com/blog/wp-login.php"
REAUTH = LOGIN + "?reauth=1&redirect_to=http%3A%2F%2Ftest-site.com%2Fblog%2Fwp-admin%2F"
# Kata sandi dasar memuat semua simbol alfabet generator: 'K*x-9&a!b#c$d_e' setelah decode.
BODY = (
    "log=gleefulLizard3&pwd=K*x-9%26a%21b%23c%24d_e&wp-submit=Log+In"
    "&redirect_to=http%3A%2F%2Ftest-site.com%2Fblog%2Fwp-admin%2Fprofile.php&testcookie=1"
)
METHOD, URI, UA, REF, CT, REQ_BODY = (
    "request_http_method", "request_http_request", "request_user_agent", "request_referer", "request_content_type",
    "request_body",
)
BASE = {
    METHOD: "POST",
    URI: "/blog/wp-login.php",
    UA: FF70,
    REF: REAUTH + "profile.php",
    CT: "application/x-www-form-urlencoded",
    REQ_BODY: BODY,
}
HIDDEN, OUT = ("HIDDEN_EVIDENCE", "B1"), ("OUT_OF_SCOPE", "B2")

# row_id -> (field yang diganti dari permintaan login dasar, (reason, rule_id) yang diharapkan untuk label 16).
# Kasus B1 memakai setiap Referer dasar; kasus B2 yang terlihat juga membawa penyimpangan tersembunyi.
CASES = {
    1: ({REF: "", CT: "application/x-www-form-urlencoded' AND '1'='2' --"}, HIDDEN),
    2: ({REF: LOGIN, REQ_BODY: BODY.replace("pwd=K*x-9%26a%21b%23c%24d_e", "pwd=Kx9%21a%23b%27")}, HIDDEN),
    3: ({REF: LOGIN + "?loggedout=true", REQ_BODY: BODY.replace("Lizard3", "Lizard3%3Bsleep+15%3B")}, HIDDEN),
    4: ({REQ_BODY: BODY.replace("&wp-submit", "&rememberme=forever%22&wp-submit")}, HIDDEN),
    5: ({REQ_BODY: BODY.replace("Log+In", "Log+In+OR+1%3D1")}, HIDDEN),
    6: ({REQ_BODY: BODY.replace("profile.php", "profile.php0W45pz4p")}, HIDDEN),
    7: ({REF: REAUTH + "about.php", REQ_BODY: BODY.replace("testcookie=1", "testcookie=1+DESC+--")}, HIDDEN),
    8: ({REQ_BODY: BODY.replace("wp-submit=Log+In", "=")}, HIDDEN),  # nama parameter dihapus ZAP
    9: ({}, OUT),  # login otomatis tanpa penyimpangan
    10: ({REF: "", REQ_BODY: BODY.replace("&wp-submit", "&rememberme=forever&wp-submit")}, OUT),
    11: ({REF: REAUTH + "about.php", REQ_BODY: BODY.replace("profile.php", "about.php")}, OUT),
    12: ({REF: LOGIN, REQ_BODY: BODY.replace("gleefulLizard3", "rafael").replace("profile.php", "")}, OUT),
    13: ({UA: FF70 + " OR 1=1", CT: "x"}, OUT),
    14: ({URI: "/blog/wp-login.php/../../etc/passwd", REQ_BODY: ""}, OUT),
    15: ({METHOD: "PROPFIND", CT: "text/xml"}, OUT),
    16: ({REF: "http://www.google.com/", CT: ""}, OUT),
    17: ({  # bot brute force lambat Firefox 62
        UA: FF62,
        URI: "/wp-login.php",
        REQ_BODY: "log=tomas&pwd=p%40ss+w0rd&wp-submit=Log+In"
                  "&redirect_to=http%3A%2F%2Ftest-site.com%2Fwp-admin%2F&testcookie=1",
    }, OUT),
    18: ({UA: FF73, REQ_BODY: BODY.replace("K*x-9%26a%21b%23c%24d_e", "s3cr%3Ft+%2B")}, OUT),  # login interaktif sah
}


def frame(rows):
    """Baris sintetis berindeks row_id dengan semua kolom yang dibaca modul; bawaan: login dasar berlabel 16 saja."""
    base = {L16: 1, L153: 0, **BASE}
    return pd.DataFrame.from_dict({rid: {**base, **fields} for rid, fields in rows.items()}, orient="index")


def test_rules_b1_b2():
    out = evaluate(frame({rid: fields for rid, (fields, _) in CASES.items()}))
    assert list(out.columns) == OUTPUT_COLUMNS
    assert (out["label"] == L16).all() and (out["candidate"] == "").all() and not out["weak"].any()
    got = {rid: tuple(row) for rid, row in out[["reason", "rule_id"]].iterrows()}
    assert got == {rid: expected for rid, (_, expected) in CASES.items()}


def test_label_153_always_hidden_and_16_evaluated_separately():
    df = frame({
        1: {L16: 0, L153: 1, METHOD: "GET", URI: "/blog/", REQ_BODY: ""},
        2: {L16: 1, L153: 1, CT: "application/x-www-form-urlencoded' OR '1'='1"},
        3: {L16: 0, L153: 0, CT: "<script>"},
        4: {},
    })
    out = evaluate(df)
    assert sorted(zip(out.index, out["label"], out["reason"], out["rule_id"])) == [
        (1, L153, "HIDDEN_EVIDENCE", "I1"),
        (2, L153, "HIDDEN_EVIDENCE", "I1"),
        (2, L16, "HIDDEN_EVIDENCE", "B1"),
        (4, L16, "OUT_OF_SCOPE", "B2"),
    ]
    assert set(out["rule_id"]) == set(RULES) and (out["candidate"] == "").all()


def test_string_label_columns_give_same_result():
    df = frame({rid: fields for rid, (fields, _) in CASES.items()})
    pd.testing.assert_frame_equal(evaluate(df.astype({L16: str, L153: str})), evaluate(df))


def test_values_differing_only_after_nul_are_deviations():
    # '%00' menjadi '\x00' setelah decode; nilai yang sama dengan nilai dasar sampai NUL tetap menyimpang.
    df = frame({
        1: {REQ_BODY: BODY.replace("profile.php", "profile.php%00")},
        2: {REQ_BODY: BODY.replace("log=gleefulLizard3", "log=gleefulLizard3%00x")},
        3: {REQ_BODY: BODY.replace("testcookie=1", "testcookie=1%00")},
        4: {},
    })
    assert evaluate(df)["rule_id"].to_dict() == {1: "B1", 2: "B1", 3: "B1", 4: "B2"}
