"""Gerbang bukti label 194 — Fake the Source of Data.

Nama CAPEC-nya (pemalsuan sumber) tidak cocok dengan isinya: hampir semua baris adalah probe Remote File
Inclusion OWASP ZAP, yaitu URL eksternal www.google.com yang disuntikkan ke satu lokasi per baris. Lokasi
payload menentukan aturan, diperiksa berurutan (pada data nyata tiap baris berpayload hanya punya satu lokasi):

1. URI ter-decode (path/query): F1 bila URI memuat skema http(s):// eksplisit, selain itu F2.
2. User-Agent atau Referer: F3 (terlihat, tetapi bukan inklusi berkas).
3. Body, cookie, atau header yang tidak tercatat di log akses: F4.
4. Tanpa payload: UA Googlebot palsu dari fuzzer UA ZAP (pemalsuan sumber, di luar taksonomi) -> F3,
   sisanya -> F5.

`rfi_template` memberi kunci templat payload baris F1 untuk pembatasan jumlah baris per templat sesudah dedup.
Pola di bawah diambil dari templat ZAP yang teramati pada label ini, bukan dari aturan RFI CRS.
"""

from __future__ import annotations

import re

import pandas as pd

from .common import entries

LABELS = ("194 - Fake the Source of Data",)
RULES = {
    "F1": "templat RFI dengan skema http(s):// eksplisit di path/query ter-decode -> PATH_TRAVERSAL",
    "F2": "templat RFI yang sama tanpa skema -> RFI_SCHEMELESS",
    "F3": "payload di UA/Referer, atau UA Googlebot -> OUT_OF_SCOPE",
    "F4": "bukti hanya di body/cookie/header yang tidak tercatat di log -> HIDDEN_EVIDENCE",
    "F5": "tidak ada bukti -> NO_EVIDENCE",
}

# Lokasi selain URI: terlihat di Combined Log Format (ter-decode) dan tidak tercatat (body/cookie ter-decode,
# header mentah).
_VISIBLE = ("ua_dec", "ref_dec")
_HIDDEN = (
    "body_dec", "cookie_dec", "request_host", "request_origin", "request_content_type", "request_accept",
    "request_accept_language", "request_accept_encoding", "request_connection", "request_do_not_track",
)

# Provenance: templat RFI ZAP di label 194, 4 prefiks ("", "http://", "HTTP://", "https://") x 5 target
# ("www.google.com", "www.google.com/", "www.google.com:80/", "www.google.com/search?q=OWASP <kata>",
# "www.google.com:80/search?q=OWASP <kata>"). Lookaround menolak host yang lebih panjang (www.google.com.xx)
# dan URL info "+http://www.google.com/bot.html" di UA Googlebot.
_RFI_PAYLOAD = re.compile(
    r"(?<![+\w])(?:https?://)?www\.google\.com(?::80)?(?![\w.-])(?!/bot\.html)", re.IGNORECASE
)

# Provenance: templat yang sama dengan prefiks skema eksplisit (http://, HTTP://, https://; masing-masing 12.610
# baris F1). Cocok tepat bila URI memuat "https?://www.google.com" (syarat F1); sisa pola membentuk kunci templat.
# Garis miring payload hanya dibedakan dari pemisah path bila diikuti '/', '?', '&', atau akhir URI (di URI mentah
# garis miring payload ter-encode %2F, pemisah path tidak).
_RFI_URL = re.compile(
    r"https?://www\.google\.com(?::\d+)?(?:/search\?q=OWASP [A-Za-z]+|/(?=[/?&]|$))?", re.IGNORECASE
)

# Provenance: kata pencarian acak setelah "search?q=OWASP " (289 kata berbeda pada baris F1, semuanya alfabetis,
# sehingga cukup [A-Za-z]+ di sini dan di _RFI_URL).
_SEARCH_WORD = re.compile(r"(?<=search\?q=OWASP )[A-Za-z]+", re.IGNORECASE)

# Provenance: UA "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" dari fuzzer UA ZAP
# (berselang-seling dengan UA MSIE 6-8, msnbot, dan Yahoo! Slurp pada URL yang sama), 576 baris tanpa payload.
_GOOGLEBOT_UA = re.compile(r"Googlebot")


def rfi_template(uri_dec: str) -> str:
    """Kunci templat payload RFI berskema di URI ter-decode, mis. "HTTP://www.google.com:80/search?q=OWASP <w>".

    Skema, host, dan port ditulis apa adanya; path payload hanya "", "/", atau "/search?q=OWASP <w>" (kata
    pencarian diganti "<w>"). Hasilnya "" bila URI tidak memuat "http(s)://www.google.com"; kunci hanya bermakna
    untuk baris F1 (pipeline memanggilnya hanya untuk baris F1). Kunci hanya berisi teks yang cocok dengan pola
    sehingga bebas NUL dan aman sebagai kunci groupby.
    """
    match = _RFI_URL.search(uri_dec)
    return _SEARCH_WORD.sub("<w>", match.group()) if match else ""


def _has_payload(rows: pd.DataFrame, columns: tuple[str, ...]) -> pd.Series:
    found = pd.Series(False, index=rows.index)
    for column in columns:
        found |= rows[column].str.contains(_RFI_PAYLOAD)
    return found


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label = LABELS[0]
    rows = df[df[label].astype(int) == 1]
    uri = rows["uri_dec"].str.contains(_RFI_PAYLOAD)
    scheme = rows["uri_dec"].str.contains(_RFI_URL)
    visible = _has_payload(rows, _VISIBLE) & ~uri
    hidden = _has_payload(rows, _HIDDEN) & ~uri & ~visible
    googlebot = rows["request_user_agent"].str.contains(_GOOGLEBOT_UA) & ~(uri | visible | hidden)
    return pd.concat([
        entries(rows.index[uri & scheme], label, candidate="PATH_TRAVERSAL", rule_id="F1"),
        entries(rows.index[uri & ~scheme], label, reason="RFI_SCHEMELESS", rule_id="F2"),
        entries(rows.index[visible | googlebot], label, reason="OUT_OF_SCOPE", rule_id="F3"),
        entries(rows.index[hidden], label, reason="HIDDEN_EVIDENCE", rule_id="F4"),
        entries(rows.index[~(uri | visible | hidden | googlebot)], label, reason="NO_EVIDENCE", rule_id="F5"),
    ])
