"""Langkah 4 — rekonstruksi setiap baris SR-BH ke Apache Combined Log Format.

    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"

Sumber setiap field dan placeholder (dicatat juga di reports/data_report.md):
- %h  src_ip; kosong -> "-".
- %l  identd: tidak ada di dataset -> "-".   %u  user autentikasi HTTP: tidak ada di dataset -> "-".
- %t  teks waktu asli dengan offset diganti +0000 (keputusan penulis); jam dinding tidak diubah. Offset SR-BH hanyalah
      label yang berganti (+0100 -> +0200 -> +0100) sementara jam dinding terus berjalan, sehingga konversi per-offset
      akan menciptakan tumpang-tindih 1 jam (17 Jul) dan celah 1 jam (19 Jul) palsu. Teks aslinya disimpan di kolom
      `timestamp_original` yang tidak dipakai metode mana pun.
- %r  "METHOD request_http_request PROTOCOL" apa adanya (masih ter-encode, seperti dicatat Apache).
- %>s response_http_status_code.
- %b  response_content_length; "-" bila kosong, "0", atau metode HEAD (Apache tidak mengirim body untuk HEAD).
- Referer / User-Agent: nilai header; "-" bila kosong.
Isi %r, Referer, dan User-Agent di-escape seperti `ap_escape_logitem` Apache: kutip -> \\", backslash -> \\\\,
karakter kontrol dan non-ASCII -> \\xhh.
"""

from __future__ import annotations

import re

import pandas as pd

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
MASK_TIME = "[01/Jan/2020:00:00:00 +0000]"
MASK_PROTOCOL = "HTTP/1.1"
_TIME = re.compile(r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
_LOG_TIME = re.compile(r"^(\S+ \S+ \S+ )\[[^\]]*\]")
_LOG_PROTOCOL = re.compile(r'^(\S+ \S+ \S+ \[[^\]]*\] "\S+ \S+) HTTP/\d\.\d"')
_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v", "\f": "\\f"}
_NEEDS_ESCAPE = re.compile(r'["\\\x00-\x1f\x7f-\U0010ffff]')


def escape_logitem(text: str) -> str:
    """Escape nilai seperti Apache sebelum ditulis ke log (karakter non-ASCII per byte UTF-8)."""
    if not _NEEDS_ESCAPE.search(text):
        return text
    out = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch < " " or ch >= "\x7f":
            out.extend(f"\\x{b:02x}" for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)


def _parse_time(timestamps: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Teks waktu Apache (dd/Mon/yyyy:HH:MM:SS ±hhmm) -> (jam dinding naif, offset); tidak bergantung pada locale."""
    parts = timestamps.str.extract(_TIME)
    local = pd.to_datetime(
        {
            "year": pd.to_numeric(parts[2]),
            "month": parts[1].map({m: i + 1 for i, m in enumerate(MONTHS)}),
            "day": pd.to_numeric(parts[0]),
            "hour": pd.to_numeric(parts[3]),
            "minute": pd.to_numeric(parts[4]),
            "second": pd.to_numeric(parts[5]),
        },
        errors="coerce",
    )
    sign = parts[6].map({"+": 1, "-": -1})
    offset = pd.to_timedelta(sign * (pd.to_numeric(parts[7]) * 60 + pd.to_numeric(parts[8])), unit="min")
    return local, offset


def to_utc(timestamps: pd.Series) -> pd.Series:
    """Teks waktu Apache -> datetime UTC (jam dinding dikurangi offset baris itu)."""
    local, offset = _parse_time(timestamps)
    return (local - offset).dt.tz_localize("UTC")


def wall_clock(timestamps: pd.Series) -> pd.Series:
    """Teks waktu Apache -> jam dinding apa adanya (offset diabaikan), diberi zona UTC sesuai label +0000."""
    return _parse_time(timestamps)[0].dt.tz_localize("UTC")


def format_utc(ts: pd.Series) -> pd.Series:
    """datetime UTC -> 'dd/Mon/yyyy:HH:MM:SS +0000'; NaT -> '-'."""
    text = (
        ts.dt.strftime("%d/") + ts.dt.month.map(lambda m: MONTHS[int(m) - 1] if m == m else "")
        + ts.dt.strftime("/%Y:%H:%M:%S +0000")
    )
    return text.where(ts.notna(), "-")


def _dash(values: pd.Series) -> pd.Series:
    return values.where(values != "", "-")


def reconstruct(df: pd.DataFrame) -> pd.DataFrame:
    """Kolom `raw_log`, `timestamp_utc` (jam dinding berlabel +0000), dan `timestamp_original` untuk setiap baris."""
    ts = wall_clock(df["timestamp"])
    request = (df["request_http_method"] + " " + df["request_http_request"] + " " + df["request_http_protocol"]).map(escape_logitem)
    size = df["response_content_length"].where(
        ~df["response_content_length"].isin(["", "0"]) & (df["request_http_method"] != "HEAD"), "-"
    )
    referer = df["request_referer"].map(escape_logitem)
    agent = df["request_user_agent"].map(escape_logitem)
    raw_log = (
        _dash(df["src_ip"]) + " - - [" + format_utc(ts) + '] "' + request + '" ' + _dash(df["response_http_status_code"])
        + " " + size + ' "' + _dash(referer) + '" "' + _dash(agent) + '"'
    )
    return pd.DataFrame({"raw_log": raw_log, "timestamp_utc": ts, "timestamp_original": df["timestamp"]}, index=df.index)


def mask_log(raw_log: pd.Series) -> pd.Series:
    """`raw_log_masked`: [%t] diganti MASK_TIME dan protokol request line diseragamkan MASK_PROTOCOL (keputusan penulis).

    Hanya kolom ini (bukan raw_log) yang boleh diterima metode, karena waktu dan protokol menandai kelas di SR-BH.
    """
    masked = raw_log.str.replace(_LOG_TIME, r"\1" + MASK_TIME, n=1, regex=True)
    return masked.str.replace(_LOG_PROTOCOL, r'\1 ' + MASK_PROTOCOL + '"', n=1, regex=True)
