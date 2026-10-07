import pandas as pd
import yaml

from src.data.config import LABEL_MAPPING_SRC
from src.data.gate.common import OUTPUT_COLUMNS
from src.data.gate.rfi import LABELS, RULES, evaluate, rfi_template

LABEL = LABELS[0]
VISIBLE = ["ua_dec", "ref_dec"]
HIDDEN = [
    "body_dec", "cookie_dec", "request_host", "request_origin", "request_content_type", "request_accept",
    "request_accept_language", "request_accept_encoding", "request_connection", "request_do_not_track",
]
COLUMNS = ["uri_dec", "request_user_agent", *VISIBLE, *HIDDEN]
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

# (field yang diisi, rule_id yang diharapkan); field lain berisi string kosong.
CASES = [
    ({"uri_dec": "/blog/index.php/HTTP://www.google.com:80/search?q=OWASP kitten/"}, "F1"),
    ({"uri_dec": "/blog/wp-login.php?redirect_to=https://www.google.com/"}, "F1"),
    ({"uri_dec": "/blog/\x00/http://www.google.com/"}, "F1"),
    ({"uri_dec": "/blog/x/http://www.google.com/", "ua_dec": "www.google.com"}, "F1"),
    ({"uri_dec": "/blog/index.php/WWW.Google.COM:80/"}, "F2"),
    ({"uri_dec": "/blog/?s=www.google.com", "body_dec": "a=http://www.google.com/"}, "F2"),
    ({"ua_dec": "HTTP://www.google.com/"}, "F3"),
    ({"ref_dec": "www.google.com:80/", "body_dec": "a=www.google.com"}, "F3"),
    ({"request_user_agent": GOOGLEBOT, "ua_dec": GOOGLEBOT}, "F3"),
    ({"body_dec": "log=a&_wp_http_referer=https://www.google.com"}, "F4"),
    ({"request_accept_language": "https://www.google.com/search?q=OWASP%20grandmother"}, "F4"),
    ({"request_user_agent": GOOGLEBOT, "ua_dec": GOOGLEBOT, "cookie_dec": "u=www.google.com/"}, "F4"),
    ({"uri_dec": "/blog/index.php/2020/04/04/"}, "F5"),
    ({"uri_dec": "/blog/?s=www.google.com.au&t=awww.google.com", "ref_dec": "http://www.google.com/bot.html"}, "F5"),
    ({"uri_dec": "/blog/a\x00b", "body_dec": "x\x00y"}, "F5"),
]

# uri_dec -> kunci templat. Garis miring tunggal yang diikuti segmen path adalah pemisah, bukan bagian payload.
TEMPLATES = {
    "/blog/HTTP://www.google.com:80//feed": "HTTP://www.google.com:80/",
    "/blog/http://www.google.com/feed": "http://www.google.com",
    "/blog/https://www.google.com/": "https://www.google.com/",
    "/blog/?u=http://www.google.com/&v=1": "http://www.google.com/",
    "/blog/http://www.google.com?ver=4.9.5": "http://www.google.com",
    "/blog/?u=https://www.google.com:80/search?q=OWASP employee&v=1": "https://www.google.com:80/search?q=OWASP <w>",
    "/blog/\x00/http://www.google.com/search?q=OWASP x/": "http://www.google.com/search?q=OWASP <w>",
    "/blog/www.google.com/": "",
}


def frame(cases, labels=None) -> pd.DataFrame:
    rows = [{c: fields.get(c, "") for c in COLUMNS} for fields, _ in cases]
    df = pd.DataFrame(rows, index=[100 + 3 * i for i in range(len(rows))])
    df[LABEL] = ["1"] * len(rows) if labels is None else labels
    return df


def yaml_rules() -> dict:
    spec = yaml.safe_load(LABEL_MAPPING_SRC.read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in spec["labels"][LABEL]["rules"]}


def test_rule_ids_match_yaml():
    assert list(yaml_rules()) == list(RULES)


def test_every_case_gets_expected_rule_and_yaml_outcome():
    df = frame(CASES)
    out = evaluate(df)
    assert list(out.columns) == OUTPUT_COLUMNS
    assert sorted(out.index) == list(df.index)
    assert out.loc[df.index, "rule_id"].tolist() == [rule for _, rule in CASES]
    assert set(out["rule_id"]) == set(RULES)
    spec = yaml_rules()
    for _, entry in out.iterrows():
        rule = spec[entry["rule_id"]]
        assert entry["candidate"] == ("" if rule["then"] == "EXCLUDED" else rule["then"])
        assert entry["reason"] == rule.get("reason_code", "")
        assert entry["label"] == LABEL and not entry["weak"]


def test_each_location_outside_uri():
    cases = [({column: "http://www.google.com/"}, "F3" if column in VISIBLE else "F4") for column in VISIBLE + HIDDEN]
    df = frame(cases)
    assert evaluate(df).loc[df.index, "rule_id"].tolist() == [rule for _, rule in cases]


def test_only_rows_carrying_the_label():
    cases = CASES[:3]
    out = evaluate(frame(cases, labels=pd.array([1, 0, 1], dtype="int8")))
    assert out.index.tolist() == [100, 106]
    assert evaluate(frame(cases, labels=["0", "0", "0"])).empty


def test_template_key():
    assert {uri: rfi_template(uri) for uri in TEMPLATES} == TEMPLATES
