"""Langkah 5 — parser Apache Combined Log Format berbasis regex.

Baris yang gagal diurai tidak dibuang: kolom `parse_error` berisi alasannya
("format", "time", "request") dan field yang tak terurai bernilai kosong/NaN.
"""

from __future__ import annotations

import re

import pandas as pd

from .reconstruct import to_utc

_QUOTED = r'"([^"\\]*(?:\\.[^"\\]*)*)"'  # string berkutip dengan escape, bentuk "unrolled" agar cepat
LINE = re.compile(
    r"^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    + _QUOTED.replace("(", "(?P<request>", 1)
    + r" (?P<status>\d{3}) (?P<bytes>\d+|-) "
    + _QUOTED.replace("(", "(?P<referer>", 1)
    + " "
    + _QUOTED.replace("(", "(?P<user_agent>", 1)
    + "$"
)
REQUEST = re.compile(r"^(?P<method>[A-Za-z][A-Za-z0-9_-]*) (?P<target>\S+) (?P<protocol>HTTP/\d\.\d)$")
_UNESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|.)")
_SIMPLE = {'"': '"', "\\": "\\", "b": "\b", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "f": "\f"}

FIELDS = ["ip", "ident", "user", "time", "timestamp", "method", "path", "query", "protocol", "status", "bytes", "referer", "user_agent"]


def unescape_logitem(text: str) -> str:
    """Kebalikan escape Apache: \\" \\\\ \\n ... dan \\xhh (urutan byte \\xhh di-decode sebagai UTF-8)."""
    if "\\" not in text:
        return text
    raw = bytearray()
    pos = 0
    for m in _UNESCAPE.finditer(text):
        raw += text[pos:m.start()].encode("utf-8")
        esc = m.group(1)
        if esc[0] == "x" and len(esc) == 3:
            raw.append(int(esc[1:], 16))
        else:
            raw += _SIMPLE.get(esc, "\\" + esc).encode("utf-8")
        pos = m.end()
    raw += text[pos:].encode("utf-8")
    return raw.decode("utf-8", errors="replace")


def parse_line(line: str) -> dict | None:
    """Urai satu baris; None bila baris tidak sesuai Combined Log Format."""
    out = parse_lines(pd.Series([line])).iloc[0]
    return None if out["parse_error"] else out.to_dict()


def parse_lines(lines: pd.Series) -> pd.DataFrame:
    """Urai banyak baris sekaligus. Index hasil sama dengan index `lines`."""
    m = lines.str.extract(LINE)
    error = pd.Series("", index=lines.index)
    error[m["ip"].isna()] = "format"

    ok = error == ""
    timestamp = pd.Series(pd.NaT, index=lines.index, dtype="datetime64[ns, UTC]")
    timestamp[ok] = to_utc(m.loc[ok, "time"])
    error[ok & timestamp.isna()] = "time"

    # Request line dicocokkan selagi masih ter-escape (karakter kontrol masih berupa teks \xhh), baru di-unescape.
    r = m["request"].fillna("").str.extract(REQUEST)
    error[(error == "") & r["method"].isna()] = "request"

    target = r["target"].fillna("").map(unescape_logitem)
    path_query = target.str.split("?", n=1, expand=True).reindex(columns=[0, 1])
    out = pd.DataFrame(
        {
            "ip": m["ip"],
            "ident": m["ident"],
            "user": m["user"],
            "time": m["time"],
            "timestamp": timestamp,
            "method": r["method"],
            "path": path_query[0].where(r["method"].notna()),
            "query": path_query[1].fillna("").where(r["method"].notna()),
            "protocol": r["protocol"],
            "status": pd.to_numeric(m["status"], errors="coerce").astype("Int64"),
            "bytes": pd.to_numeric(m["bytes"].where(m["bytes"] != "-"), errors="coerce").astype("Int64"),
            "referer": m["referer"].map(unescape_logitem, na_action="ignore").where(m["referer"] != "-", ""),
            "user_agent": m["user_agent"].map(unescape_logitem, na_action="ignore").where(m["user_agent"] != "-", ""),
            "parse_error": error,
        },
        index=lines.index,
    )
    return out
