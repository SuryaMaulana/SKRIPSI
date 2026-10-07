import pandas as pd

from src.data.reconstruct import escape_logitem, format_utc, mask_log, reconstruct, to_utc, wall_clock


def raw_row(**overrides):
    row = {
        "src_ip": "172.26.0.1", "timestamp": "17/Jul/2020:12:23:34 +0100", "request_http_method": "GET",
        "request_http_request": "/blog/", "request_http_protocol": "HTTP/1.1", "response_http_status_code": "200",
        "response_content_length": "25174", "request_referer": "", "request_user_agent": "Mozilla/5.0",
    }
    row.update(overrides)
    return row


def test_combined_log_format_keeps_wall_clock_with_offset_replaced():
    out = reconstruct(pd.DataFrame([raw_row()]))
    assert out["raw_log"].iat[0] == '172.26.0.1 - - [17/Jul/2020:12:23:34 +0000] "GET /blog/ HTTP/1.1" 200 25174 "-" "Mozilla/5.0"'
    assert out["timestamp_original"].iat[0] == "17/Jul/2020:12:23:34 +0100"


def test_offset_flip_keeps_a_continuous_wall_clock():
    # pola SR-BH: label offset berganti tetapi jam dinding berjalan terus (baris 2919 -> 2920)
    texts = pd.Series(["17/Jul/2020:18:59:58 +0100", "17/Jul/2020:19:00:13 +0200"])
    assert format_utc(wall_clock(texts)).tolist() == ["17/Jul/2020:18:59:58 +0000", "17/Jul/2020:19:00:13 +0000"]
    assert wall_clock(texts).is_monotonic_increasing and not to_utc(texts).is_monotonic_increasing


def test_to_utc_applies_offsets_across_midnight_and_month():
    ts = to_utc(pd.Series(["01/Aug/2020:01:30:00 +0200", "31/Jul/2020:23:30:00 -0100"]))
    assert format_utc(ts).tolist() == ["31/Jul/2020:23:30:00 +0000", "01/Aug/2020:00:30:00 +0000"]


def test_bytes_placeholder_rules():
    rows = [raw_row(response_content_length=v) for v in ["", "0", "512"]] + [raw_row(request_http_method="HEAD")]
    sizes = [line.split('" ')[1].split()[1] for line in reconstruct(pd.DataFrame(rows))["raw_log"]]
    assert sizes == ["-", "-", "512", "-"]


def test_escaping_like_apache():
    assert escape_logitem('a "b" \\ c') == 'a \\"b\\" \\\\ c'
    assert escape_logitem("x\r\ny\x00") == "x\\r\\ny\\x00"
    assert escape_logitem("é") == "\\xc3\\xa9"
    assert escape_logitem("biasa") == "biasa"


def test_empty_row_gets_placeholders():
    empty = {k: "" for k in raw_row()}
    line = reconstruct(pd.DataFrame([empty]))["raw_log"].iat[0]
    assert line == '- - - [-] "  " - - "-" "-"'


def test_mask_log_hides_time_and_protocol_only():
    line = '172.26.0.1 - - [17/Jul/2020:12:23:34 +0000] "TRACK /a?q=HTTP/1.0 HTTP/1.0" 405 - "-" "UA HTTP/1.0\\" x"'
    masked = mask_log(pd.Series([line, '- - - [-] "  " - - "-" "-"']))
    assert masked.iat[0] == '172.26.0.1 - - [01/Jan/2020:00:00:00 +0000] "TRACK /a?q=HTTP/1.0 HTTP/1.1" 405 - "-" "UA HTTP/1.0\\" x"'
    assert masked.iat[1] == '- - - [01/Jan/2020:00:00:00 +0000] "  " - - "-" "-"'
