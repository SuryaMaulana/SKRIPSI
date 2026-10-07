import pandas as pd
import yaml

from src.data.config import LABEL_MAPPING_SRC
from src.data.gate.common import OUTPUT_COLUMNS, add_decoded
from src.data.gate.normal import LABELS, RULES, benign_vocabulary, evaluate

LABEL = LABELS[0]
FEATURES = [
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "request_http_method", "request_http_request",
    "request_http_protocol", "request_user_agent", "request_referer", "request_host", "request_origin",
    "request_cookie", "request_content_type", "request_accept", "request_accept_language", "request_accept_encoding",
    "request_do_not_track", "request_connection", "request_body", "response_http_protocol",
    "response_http_status_code", "response_http_status_message", "response_content_length",
]
FIREFOX70 = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
POOL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0"
NMAP = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
SITE = "http://test-site.com/blog/"
BASE = {**dict.fromkeys(FEATURES, ""), "request_http_method": "GET", "request_http_request": "/blog/",
        "request_http_protocol": "HTTP/1.1", "request_user_agent": FIREFOX70, "response_http_status_code": "404"}
POOL_URIS = [
    "/blog/index.php/2020/04/04/hello-world/",
    "/blog/wp-json/oembed/1.0/embed?url=http%3A%2F%2Ftest-site.com%2F",
]
POOL_VOCAB = {"", "blog", "index.php", "2020", "04", "hello-world", "wp-json", "oembed", "1.0", "embed", "url",
              "http://test-site.com/"}

# (field mentah yang diubah dari BASE, rule_id yang diharapkan)
CASES = [
    (dict.fromkeys(FEATURES, ""), "N0"),
    ({"request_http_request": "/blog/%2Fetc%2Fpasswd"}, "N1"),
    ({"request_http_request": "/blog/%3Cscript%3Ealert(1);%3C%2fscript%3E?x=1"}, "N1"),
    ({"request_http_method": "TRACE"}, "N1"),
    ({"request_http_request": "/blog/%27%22%3Cscript%3Ealert(1);%3C/script%3E"}, "N2"),
    ({"request_http_request": "/blog/%27;cat%20/etc/passwd;%27"}, "N2"),
    ({"request_http_request": "/blog/?p=1%27+%2F+sleep%2815%29+%2F+%27"}, "N2"),
    ({"request_user_agent": "() { :;}; /bin/sleep 15"}, "N2"),
    ({"request_referer": SITE + "?a=${@print(chr(122).chr(97))}"}, "N2"),
    ({"request_http_request": "/blog/http:%5C%5C123456789.owasp.org"}, "N2"),
    ({"request_http_request": "/blog/http://example.com/"}, "N2"),  # hanya _EXTERNAL_IN_PATH yang cocok
    ({"request_http_request": "/blog/my-account/?avatar=http://1.gravatar.com/avatar/x"}, "N2"),
    ({"request_http_request": "/blog/0W45pz4p%3Cscript%3E"}, "N2"),
    ({"request_http_request": "/blog/0W45pz4p/index.php"}, "N3"),
    ({"request_http_request": "/blog/?-s"}, "N3"),
    ({"request_http_request": "/blog/%40/"}, "N3"),
    ({"request_http_request": "/blog/%2B/"}, "N3"),
    ({"request_http_request": "/blog/%00/"}, "N3"),
    ({"request_http_request": "/blog%25/index.php"}, "N3"),
    ({"request_http_request": "/blog/%5Cindex.php"}, "N3"),
    ({"request_http_request": "/blog.7z"}, "N3"),
    ({"request_http_request": "/blog/wp-json/oembed/2.0"}, "N3"),
    ({"request_http_request": "/.git"}, "N3"),
    ({"request_user_agent": NMAP}, "N3"),
    ({"request_user_agent": "any?"}, "N3"),
    ({"request_user_agent": FIREFOX70 + "NULL"}, "N3"),
    ({"request_referer": "]]>"}, "N3"),
    ({"request_http_request": "/blog//index.php", "request_user_agent": "<!--"}, "N3"),
    ({}, "N4"),
    ({"request_http_request": "/blog/wp-json/oembed/1.0"}, "N4"),
    ({"request_http_request": "/blog//index.php"}, "N4"),
    ({"request_http_request": "/blog/my-account/%7B%7B%20data.link%20%7D%7D"}, "N4"),
    ({"request_http_method": "OPTIONS"}, "N4"),
    ({"request_http_method": "POST", "request_body": "comment=%27%3Bcat+%2Fetc%2Fpasswd%3B%27"}, "N4"),
    ({"request_http_request": "/blog/%3F-s"}, "N4"),
    ({"request_http_request": "/blog/?url=" + SITE, "request_referer": SITE}, "N4"),
    ({"request_user_agent": "msnbot/1.1 (+http://search.msn.com/msnbot.htm)"}, "N4"),
    ({"request_user_agent": ""}, "N4"),
]


def frame(cases, pool_rows: int = 50) -> pd.DataFrame:
    """Baris pool benign (row_id 0..) untuk kosakata, lalu kasus (row_id 100, 103, ...); kolom *_dec via add_decoded."""
    pool = [{**BASE, "request_user_agent": POOL_UA, "request_http_request": POOL_URIS[i % 2],
             "response_http_status_code": "200"} for i in range(pool_rows)]
    rows = [{**BASE, **fields} for fields, _ in cases]
    df = pd.DataFrame(pool + rows, index=[*range(pool_rows), *case_ids(cases)])
    df[LABEL] = "1"
    return add_decoded(df)


def case_ids(cases) -> list[int]:
    return [100 + 3 * i for i in range(len(cases))]


def yaml_rules() -> dict:
    spec = yaml.safe_load(LABEL_MAPPING_SRC.read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in spec["labels"][LABEL]["rules"]}


def test_rule_ids_match_yaml():
    assert list(yaml_rules()) == list(RULES)


def test_every_case_gets_expected_rule_and_yaml_outcome():
    df = frame(CASES)
    out = evaluate(df)
    assert list(out.columns) == OUTPUT_COLUMNS
    assert sorted(out.index) == sorted(df.index)
    assert out.loc[case_ids(CASES), "rule_id"].tolist() == [rule for _, rule in CASES]
    assert set(out["rule_id"]) == set(RULES)
    assert (out.loc[range(50), "rule_id"] == "N4").all()
    spec = yaml_rules()
    for _, entry in out.iterrows():
        rule = spec[entry["rule_id"]]
        assert entry["candidate"] == ("" if rule["then"] == "EXCLUDED" else rule["then"])
        assert entry["reason"] == rule.get("reason_code", "")
        assert entry["label"] == LABEL and not entry["weak"]


def test_n0_requires_all_24_feature_fields_empty():
    # Satu field fitur mana pun yang tidak kosong sudah cukup untuk lolos dari N0.
    cases = [({**dict.fromkeys(FEATURES, ""), field: "x"}, "") for field in FEATURES]
    out = evaluate(frame(cases))
    assert (out.loc[case_ids(cases), "rule_id"] != "N0").all()


def test_vocabulary_from_frequent_non_tool_uas_with_status_200():
    ok = {"response_http_status_code": "200"}
    tool = ({**ok, "request_http_request": "/blog/secret.bak"}, "")  # UA alat uji (BASE)
    rare = ({**ok, "request_user_agent": "Rare/1.0", "request_http_request": "/rare.zip"}, "")
    noise = [tool] * 60 + [rare] * 49
    assert benign_vocabulary(frame(noise)) == POOL_VOCAB
    assert benign_vocabulary(frame(noise, pool_rows=49)) == set()
    # Baris berstatus selain 200 ikut dihitung dalam frekuensi UA, tetapi tidak menyumbang token.
    not_found = [({"request_user_agent": POOL_UA, "request_http_request": "/missing.old"}, "")]
    assert benign_vocabulary(frame(not_found, pool_rows=49)) == POOL_VOCAB


def test_vocabulary_is_derived_from_the_rows_given():
    cases = [({"request_http_request": "/blog/wp-json/oembed/1.0"}, "")]
    assert evaluate(frame(cases)).loc[100, "rule_id"] == "N4"
    assert evaluate(frame(cases, pool_rows=49)).loc[100, "rule_id"] == "N3"


def test_decoded_values_differing_only_after_nul_are_judged_separately():
    # Hash string pandas memotong di NUL; urutan cocok/tidak cocok dibuat dua arah agar kedua akibatnya tertangkap.
    cases = [
        ({"request_http_request": "/blog/a%00"}, "N4"),
        ({"request_http_request": "/blog/a%00%3Cscript%3E"}, "N2"),
        ({"request_user_agent": "x%00%3Cscript%3E"}, "N2"),
        ({"request_user_agent": "x%00"}, "N3"),
    ]
    df = frame(cases)
    assert "\x00" in df.loc[103, "uri_dec"] and "\x00" in df.loc[109, "ua_dec"]
    assert evaluate(df).loc[case_ids(cases), "rule_id"].tolist() == [rule for _, rule in cases]


def test_only_rows_carrying_the_label():
    df = frame(CASES[:3])
    df[LABEL] = pd.array([1] * 50 + [1, 0, 1], dtype="int8")
    assert [i for i in evaluate(df).index if i >= 100] == [100, 106]
    df[LABEL] = "0"
    assert evaluate(df).empty
