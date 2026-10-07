"""Gerbang bukti label 16 — Dictionary-based Password Attack dan 153 — Input Data Manipulation.

Kedua label di luar taksonomi 6 kelas dan tidak pernah menyumbang kandidat; kelas baris hanya bisa datang dari label
pendamping yang payload-nya terlihat. Modul ini hanya memberi kode alasan eksklusi.

16 (1.847 baris) menandai POST formulir login WordPress, bukan perilaku brute force. Sebagian besar barisnya adalah
active scan ZAP yang memutasi satu field dari permintaan login dasar klien Firefox 70. Bila baris log sama persis
dengan permintaan dasar, tetapi Content-Type atau salah satu field body menyimpang dari nilai dasar, payload probe
hanya ada di bagian yang tidak tercatat -> HIDDEN_EVIDENCE (B1, subtipe C2 analisis bukti). Sisanya OUT_OF_SCOPE (B2):
penyimpangan terlihat di metode/URI/UA/Referer (C1), login otomatis tanpa penyimpangan (B), bot brute force lambat
Firefox 62 (A), dan satu login interaktif sah Firefox 73 (E). A dan E sudah gugur karena UA-nya bukan UA permintaan
dasar, jadi aturan khusus analisis (UA Firefox 62, row_id 7164) tidak diperlukan. Subtipe B juga memuat 8 baris yang
pwd-nya berisi penanda ZAP alfanumerik (5) atau 'NULL' (2), atau kosong (1); cek alfabet kata sandi tidak
menangkapnya, jadi baris itu tetap B2 sesuai analisis bukti.

Field body dibaca dari `request_body` mentah dengan templat login, lalu tiap nilai di-decode satu lapis
`unquote_plus` (bukan `body_dec`), sama dengan definisi analisis bukti. Nilai ter-decode bisa memuat NUL, jadi
dibandingkan per sel tanpa operasi hash.

153 (2.272 baris) menandai header Content-Type yang tidak valid; payload-nya ada di header itu, yang tidak tercatat
di log akses -> semua baris HIDDEN_EVIDENCE (I1).
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

import pandas as pd

from .common import entries

LABELS = ("16 - Dictionary-based Password Attack", "153 - Input Data Manipulation")
RULES = {
    "B1": "baris log = permintaan login dasar; payload probe hanya di body POST/Content-Type -> HIDDEN_EVIDENCE",
    "B2": "selain B1: payload terlihat, login otomatis tanpa payload, bot Firefox 62, login sah -> OUT_OF_SCOPE",
    "I1": "header Content-Type tidak valid, tidak tercatat di log akses -> HIDDEN_EVIDENCE",
}

# Permintaan login dasar (field yang tercatat di log akses): nilai pada baris label 16 tanpa penyimpangan.
# Referer kosong dan alur reauth ke about.php (2 baris) termasuk nilai dasar.
_BASE_METHOD = "POST"
_BASE_URI = "/blog/wp-login.php"
_BASE_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
_LOGIN_PAGE = "http://test-site.com/blog/wp-login.php"
_REAUTH = "?reauth=1&redirect_to=http%3A%2F%2Ftest-site.com%2Fblog%2Fwp-admin%2F"
_BASE_REFERERS = (
    "",
    _LOGIN_PAGE,
    _LOGIN_PAGE + "?loggedout=true",
    _LOGIN_PAGE + _REAUTH + "profile.php",
    _LOGIN_PAGE + _REAUTH + "about.php",
)

# Nilai dasar bagian yang tidak tercatat: header Content-Type dan field body login (setelah decode).
_BASE_CONTENT_TYPE = "application/x-www-form-urlencoded"
_ADMIN = "http://test-site.com/blog/wp-admin/"
_BASE_REDIRECTS = (_ADMIN, _ADMIN + "profile.php", _ADMIN + "about.php")

# Provenance: body formulir wp-login.php WordPress (klien Firefox 70 dan replay ZAP-nya, bot Firefox 62, login Firefox
# 73; cocok pada 1.844 dari 1.847 baris label 16; tiga sisanya probe ZAP yang menghapus nama parameter, '&=').
_LOGIN_BODY = re.compile(
    r"^log=(?P<log>.*?)&pwd=(?P<pwd>.*?)&(?:rememberme=(?P<rememberme>.*?)&)?"
    r"wp-submit=(?P<submit>.*?)&redirect_to=(?P<redirect_to>.*?)&testcookie=(?P<testcookie>.*)$",
    re.S,
)
# Provenance: nama pengguna buatan generator lalu lintas (sifat + Hewan/Makanan + digit, mis. 'selfishTruffle9') dan
# satu akun nyata situs ('rafael'); ZAP menempelkan payload pada nilai ini.
_BASE_LOG = re.compile(r"[a-z]+[A-Z][a-z]+\d|rafael")
# Provenance: alfabet kata sandi buatan generator pada login tanpa payload; karakter lain (kutip, spasi, '<', '/',
# '%', ...) berasal dari payload ZAP yang ditempelkan pada kata sandi.
_PWD_FOREIGN = re.compile(r"[^A-Za-z0-9*\-&!_#$]")


def _body_deviates(body: str) -> bool:
    """True bila body bukan templat login atau ada field yang menyimpang dari nilai dasar."""
    match = _LOGIN_BODY.match(body)
    if match is None:
        return True
    field = {key: value if value is None else unquote_plus(value) for key, value in match.groupdict().items()}
    return (
        _BASE_LOG.fullmatch(field["log"]) is None
        or _PWD_FOREIGN.search(field["pwd"]) is not None
        or field["rememberme"] not in (None, "forever")
        or field["submit"] != "Log In"
        or field["redirect_to"] not in _BASE_REDIRECTS
        or field["testcookie"] != "1"
    )


def _hidden_only(rows: pd.DataFrame) -> pd.Series:
    """Baris log = permintaan login dasar, tetapi Content-Type atau body menyimpang (subtipe C2)."""
    base_line = (
        (rows["request_http_method"] == _BASE_METHOD)
        & (rows["request_http_request"] == _BASE_URI)
        & (rows["request_user_agent"] == _BASE_UA)
        & rows["request_referer"].isin(_BASE_REFERERS)
    )
    body = pd.Series([_body_deviates(b) for b in rows["request_body"]], index=rows.index, dtype=bool)
    return base_line & ((rows["request_content_type"] != _BASE_CONTENT_TYPE) | body)


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    login, content_type = LABELS
    rows = df[df[login].astype(int) == 1]
    hidden = _hidden_only(rows)
    return pd.concat([
        entries(rows.index[hidden], login, reason="HIDDEN_EVIDENCE", rule_id="B1"),
        entries(rows.index[~hidden], login, reason="OUT_OF_SCOPE", rule_id="B2"),
        entries(df.index[df[content_type].astype(int) == 1], content_type, reason="HIDDEN_EVIDENCE", rule_id="I1"),
    ])
