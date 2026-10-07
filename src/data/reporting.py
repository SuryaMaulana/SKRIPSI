"""Helper kecil untuk menulis laporan Markdown."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

# Tidak didahului karakter kata/titik, juga bukan token versi produk "Nama/1.2.3.4" (mis. "Chrome/33.0.1750.152");
# "//1.2.3.4" di URL tetap dikenali.
_IPV4 = re.compile(r"(?<![\w.])(?<![\w.-]/)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.])")


def _mask(m: re.Match) -> str:
    if any(int(octet) > 255 for octet in m.groups()):
        return m.group(0)
    return f"{m.group(1)}.{m.group(2)}.x.x"


def mask_ips(text: str) -> str:
    """Samarkan setiap alamat IPv4 di dalam teks: 203.0.113.7 -> 203.0.x.x."""
    return _IPV4.sub(_mask, text)


def truncate(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def cell(value: object, limit: int = 160) -> str:
    """Nilai sel tabel Markdown: dipotong; \\, |, & dan < di-escape (HTML mentah tidak ditafsirkan); kosong ditandai."""
    text = str(value)
    if text == "":
        return "∅"
    text = truncate(text, limit).replace("\\", "\\\\").replace("|", "\\|").replace("&", "\\&").replace("<", "\\<")
    return text.replace("\r", "␍").replace("\n", "⏎")


def md_table(headers: Sequence[str], rows: Iterable[Sequence[object]], limit: int = 160) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(cell(v, limit) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def pct(part: int, whole: int, digits: int = 2) -> str:
    """Persentase dengan koma desimal gaya Indonesia: 57,85%."""
    return f"{100 * part / whole:.{digits}f}%".replace(".", ",") if whole else "–"


def fmt_dec(x: float, digits: int = 2) -> str:
    """Desimal dengan koma gaya Indonesia: 0.93 -> 0,93."""
    return f"{x:.{digits}f}".replace(".", ",")


def fmt_int(n: int) -> str:
    """Format ribuan gaya Indonesia: 907814 -> 907.814."""
    return f"{n:,}".replace(",", ".")
