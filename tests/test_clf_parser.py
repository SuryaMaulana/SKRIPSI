import pandas as pd
import pytest

from src.data.clf_parser import parse_line, parse_lines, unescape_logitem
from src.data.reconstruct import reconstruct

LINE = (
    '172.26.0.1 - - [17/Jul/2020:19:00:05 +0000] "GET /blog/index.php?p=12&s=a%27+or+1%3D1 HTTP/1.1" 404 276 '
    '"http://test-site.com/blog/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"'
)


def test_parses_all_fields():
    row = parse_line(LINE)
    assert row["ip"] == "172.26.0.1" and row["ident"] == "-" and row["user"] == "-"
    assert row["timestamp"] == pd.Timestamp("2020-07-17 19:00:05", tz="UTC")
    assert (row["method"], row["path"], row["query"], row["protocol"]) == ("GET", "/blog/index.php", "p=12&s=a%27+or+1%3D1", "HTTP/1.1")
    assert (row["status"], row["bytes"]) == (404, 276)
    assert row["referer"] == "http://test-site.com/blog/"
    assert row["user_agent"].startswith("Mozilla/5.0")


def test_dash_fields_and_query_with_extra_question_mark():
    row = parse_line('1.2.3.4 - - [01/Nov/2020:20:59:51 +0000] "HEAD /a?b=1?c HTTP/1.0" 200 - "-" "-"')
    assert (row["path"], row["query"]) == ("/a", "b=1?c")
    assert pd.isna(row["bytes"])
    assert row["referer"] == "" and row["user_agent"] == ""


def test_unescapes_apache_escapes():
    line = '1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET /x\\\\y HTTP/1.1" 200 5 "-" "a \\"quoted\\" \\\\ ua \\x0d\\x0a"'
    row = parse_line(line)
    assert row["path"] == "/x\\y"
    assert row["user_agent"] == 'a "quoted" \\ ua \r\n'
    assert unescape_logitem("\\xe2\\x82\\xac") == "€"


def test_request_line_with_escaped_control_characters_is_parsed():
    row = parse_line('1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET /a\\x0d\\x0aSet-cookie:x HTTP/1.1" 404 276 "-" "-"')
    assert row["path"] == "/a\r\nSet-cookie:x"


@pytest.mark.parametrize(
    "line, reason",
    [
        ("", "format"),
        ("tidak ada format log di sini", "format"),
        ('1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET / HTTP/1.1" 200 5 "-"', "format"),  # UA hilang
        ('1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET / HTTP/1.1" OK 5 "-" "-"', "format"),  # status bukan angka
        ('1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET / HTTP/1.1 200 5 "-" "-"', "format"),  # kutip tak tertutup
        ('- - - [-] "  " - - "-" "-"', "format"),  # baris SR-BH yang semua field-nya kosong
        ('1.2.3.4 - - [32/Foo/2020:19:00:05 +0000] "GET / HTTP/1.1" 200 5 "-" "-"', "time"),
        ('1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET /" 200 5 "-" "-"', "request"),  # tanpa protokol
        ('1.2.3.4 - - [17/Jul/2020:19:00:05 +0000] "GET /a b HTTP/1.1" 200 5 "-" "-"', "request"),  # spasi di target
    ],
)
def test_failures_are_flagged_not_dropped(line, reason):
    assert parse_line(line) is None
    out = parse_lines(pd.Series([line, LINE]))
    assert out["parse_error"].tolist() == [reason, ""]


def test_roundtrip_with_reconstruct():
    raw = pd.DataFrame(
        [{
            "src_ip": "172.26.0.1", "timestamp": "17/Jul/2020:21:00:05 +0200", "request_http_method": "GET",
            "request_http_request": "/p?q=%3Cscript%3E", "request_http_protocol": "HTTP/1.1",
            "response_http_status_code": "200", "response_content_length": "1234",
            "request_referer": 'http://x/"r"', "request_user_agent": 'UA "q" \\ end',
        }]
    )
    row = parse_lines(reconstruct(raw)["raw_log"]).iloc[0]
    assert row["parse_error"] == ""
    assert row["time"] == "17/Jul/2020:21:00:05 +0000"  # jam dinding tetap, offset diganti
    assert (row["path"], row["query"], row["bytes"]) == ("/p", "q=%3Cscript%3E", 1234)
    assert row["referer"] == 'http://x/"r"' and row["user_agent"] == 'UA "q" \\ end'
