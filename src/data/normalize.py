"""Langkah 6 — normalisasi path, query, dan User-Agent hasil parser.

Urutan per nilai:
1. URL-decode berlapis, maksimal 3 lapis (berhenti bila tidak berubah). Pada query, lapis pertama memakai
   `unquote_plus` (+ berarti spasi di query string); lapis berikutnya serta path dan UA memakai `unquote`,
   sehingga plus yang sengaja di-encode (%2B) dan plus di UA ("+http://www.google.com/bot.html") tetap plus.
2. Dekode HTML entity: referensi numerik (&#60; &#x3c;, ';' opsional) dan entity bernama yang diakhiri ';' (&lt;).
   Entity bernama tanpa ';' tidak didekode agar parameter seperti "&copy=1" atau "&timestamp=" tidak rusak.
3. Karakter kontrol (termasuk NUL, CR, LF) ditulis sebagai teks \\xhh agar terlihat dan aman untuk operasi hash.
4. Kata kunci (daftar KEYWORDS) dijadikan huruf kecil; bagian lain tidak diubah.
5. UUID dan angka panjang (>= LONG_NUMBER_DIGITS digit, tidak menempel huruf/angka) diganti token <*>.
Versi mentah (path, query, user_agent) tetap disimpan berdampingan dengan versi ternormalisasi.
"""

from __future__ import annotations

import html
import re
from html.entities import html5 as _HTML5
from urllib.parse import unquote, unquote_plus

import pandas as pd

MAX_DECODE_LAYERS = 3
LONG_NUMBER_DIGITS = 6
TOKEN = "<*>"

# Kata kunci SQL, HTML/JavaScript, perintah shell, dan skema URL yang huruf besarnya hanya variasi penulisan.
KEYWORDS = (
    "select union all distinct insert update delete drop from where and or not null order group by having limit offset into "
    "sleep benchmark waitfor delay concat char chr ascii substring cast convert declare case when then else end "
    "like rlike regexp elt floor rand count version database outfile load_file information_schema extractvalue "
    "updatexml pg_sleep exec execute xp_cmdshell "
    "script iframe img svg body onerror onload onmouseover onfocus onclick alert prompt confirm document cookie "
    "javascript vbscript eval expression "
    "cat ls id whoami uname wget curl bash sh ping echo nslookup passwd etc "
    "http https ftp php file data expect phar"
).split()
_KEYWORD = re.compile(r"\b(?:" + "|".join(sorted(KEYWORDS, key=len, reverse=True)) + r")\b", re.IGNORECASE)
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_LONG_NUMBER = re.compile(r"(?<![0-9A-Za-z])\d{%d,}(?![0-9A-Za-z])" % LONG_NUMBER_DIGITS)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ENTITY = re.compile(r"&(#[0-9]+;?|#[xX][0-9A-Fa-f]+;?|[A-Za-z][A-Za-z0-9]*;)")


def unescape_entities(text: str) -> str:
    """Seperti html.unescape, tetapi entity bernama hanya didekode bila namanya utuh dan diakhiri ';'."""
    def repl(m: re.Match) -> str:
        ref = m.group(1)
        if ref[0] == "#":
            return html.unescape(m.group(0))
        return _HTML5.get(ref, m.group(0))

    return _ENTITY.sub(repl, text)


def decode_layers(text: str, plus_as_space: bool = False, layers: int = MAX_DECODE_LAYERS) -> str:
    for layer in range(layers):
        decoded = unquote_plus(text) if plus_as_space and layer == 0 else unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


def normalize_value(text: str, plus_as_space: bool = False) -> str:
    text = unescape_entities(decode_layers(text, plus_as_space))
    text = _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    text = _KEYWORD.sub(lambda m: m.group(0).lower(), text)
    text = _UUID.sub(TOKEN, text)
    return _LONG_NUMBER.sub(TOKEN, text)


def _normalize_column(values: pd.Series, plus_as_space: bool = False) -> pd.Series:
    # Nilai mentah bebas NUL sehingga aman dipakai sebagai kunci cache.
    cache: dict[str, str] = {}
    out = []
    for value in values.tolist():
        if not isinstance(value, str):
            out.append(value)
            continue
        if value not in cache:
            cache[value] = normalize_value(value, plus_as_space)
        out.append(cache[value])
    return pd.Series(out, index=values.index, dtype=object)


def normalize(parsed: pd.DataFrame) -> pd.DataFrame:
    """Kolom path_norm, query_norm, ua_norm dari keluaran `clf_parser.parse_lines`."""
    return pd.DataFrame(
        {
            "path_norm": _normalize_column(parsed["path"]),
            "query_norm": _normalize_column(parsed["query"], plus_as_space=True),
            "ua_norm": _normalize_column(parsed["user_agent"]),
        },
        index=parsed.index,
    )
