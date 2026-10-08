"""Gerbang bukti label 242 — Code Injection.

CAPEC-63 (XSS) adalah anak CAPEC-242, tetapi isi label 242 di SR-BH 2020 hanya 3,2% XSS. Hampir semuanya probe
pemindai: eval PHP print(chr(..)) bertanda 'zap_token' 12.600 baris, aritmetika EL ${a+b} 1.586, argumen PHP-CGI
539, SSI #exec 392, XSS 507, '<!--' polos 163, xmlrpc system.multicall 36, ThinkPHP 3, PHPUnit 1.

Setiap baris diberi satu subtipe utama: subtipe pertama di `_SUBTYPES` yang polanya cocok di salah satu field
ter-decode (URI, UA, Referer, body, cookie). Aturannya ditentukan subtipe utama itu dan apakah polanya terlihat di
URI, UA, atau Referer (field yang tercatat di log akses):
- K1 XSS terlihat -> XSS;
- K2 SSI exec terlihat -> netral, kelasnya dari label 88 (170/170 baris ini berlabel 88);
- K3 subtipe lain terlihat -> OUT_OF_SCOPE;
- K4 argumen PHP-CGI, terlihat atau tidak -> OUT_OF_SCOPE (CMD_INJECTION hanya lewat label 88);
- K5 subtipe utama hanya di body/cookie -> HIDDEN_EVIDENCE. Baris tanpa subtipe sama sekali juga K5 (tidak ada
  di data asli).
"""

from __future__ import annotations

import re

import pandas as pd

from .common import entries

LABELS = ("242 - Code Injection",)
RULES = {
    "K1": "tag <script>, atribut event handler, atau javascript: terlihat di URI/UA/Referer -> XSS",
    "K2": "SSI exec terlihat (selalu berlabel 88 juga) -> netral, kelas lewat label 88 (CMD_INJECTION)",
    "K3": "PHP print(chr()), EL ${..}, '<!--' polos, xmlrpc multicall, ThinkPHP, PHPUnit terlihat -> OUT_OF_SCOPE",
    "K4": "argumen PHP-CGI CVE-2012-1823, terlihat atau tidak -> OUT_OF_SCOPE; CMD_INJECTION hanya lewat label 88",
    "K5": "bukti hanya di body/cookie (termasuk XSS di body) -> HIDDEN_EVIDENCE",
}

_VISIBLE = ("uri_dec", "ua_dec", "ref_dec")
_HIDDEN = ("body_dec", "cookie_dec")

# (aturan bila subtipe utama terlihat, aturan bila hanya di body/cookie, pola), urut prioritas. Subtipe dan urutannya
# dari analisis bukti (skrip c242lib di luar repositori), diturunkan dari templat yang teramati pada label ini, bukan dari
# aturan CRS. Tiga subtipe XSS c242lib digabung; XSS_HTML_TAG (tag tanpa script/event handler) dan
# WP_TEMPLATE_BRACES (teks templat WordPress, bukan payload) dibuang karena tidak pernah menjadi subtipe utama.
# Alternatif c242lib yang tidak pernah muncul di SR-BH 2020 (direktif SSI selain exec, 'vbscript:') juga dibuang.
# Di data asli setiap baris 242 cocok dengan tepat satu subtipe, kecuali 539 baris PHP-CGI yang juga membawa '<?php'
# di body (urutan menjadikannya K4); selebihnya urutan hanya berpengaruh pada baris sintetis.
_SUBTYPES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # Eval PHP ZAP: 5 templat ';print(chr(122).chr(97)..);', "';print(..);$var='", '";print(..);$var="', dan
    # '${@print(chr(..))}' dengan/tanpa '\' di belakangnya (chr() membentuk 'zap_token'); di path, query, atau body.
    ("K3", "K5", re.compile(r"print\s*\(\s*chr\s*\(", re.IGNORECASE)),
    # PHP-CGI CVE-2012-1823: query '?-d allow_url_include=1 -d auto_prepend_file=php://input' (514 baris) atau versi
    # panjang ter-encode penuh dengan -d safe_mode/suhosin/disable_functions/open_basedir/cgi.* dan -n (25 baris).
    ("K4", "K4", re.compile(r"allow_url_include|auto_prepend_file", re.IGNORECASE)),
    # RCE ThinkPHP: '?s=/Index/\think\app/invokefunction&function=call_user_func_array&..'.
    ("K3", "K5", re.compile(r"invokefunction|call_user_func_array", re.IGNORECASE)),
    # Expression language '${n+m}' dengan angka 6 digit acak di segmen path ('+' menjadi spasi setelah decode).
    ("K3", "K5", re.compile(r"\$\{\s*\d+\s*[ +*]\s*\d+\s*\}")),
    # SSI '<!--#EXEC cmd="ls /"-->', polos atau diawali '">' (2 templat); direktif SSI lain tidak muncul di data.
    ("K2", "K5", re.compile(r"<!--\s*#\s*exec", re.IGNORECASE)),
    # XSS: '\'"<script>alert(1);</script>' (segmen path ter-encode ganda, query, UA, Referer, body),
    # '" onMouseOver="alert(1);' dan '<img src=x onerror=alert(1);>', serta '?p=javascript:alert(1);'.
    ("K1", "K5", re.compile(r"<\s*/?\s*script\b|\bon[a-z]{3,20}\s*=|javascript\s*:", re.IGNORECASE)),
    # Pembuka komentar HTML polos sebagai nilai parameter: '?ver=<!--', 'username=<!--'.
    ("K3", "K5", re.compile(r"<!--(?!\s*#)")),
    # Body XML POST /xmlrpc.php WordPress dengan methodName 'system.multicall'.
    ("K3", "K5", re.compile(r"system\.multicall", re.IGNORECASE)),
    # Probe PHPUnit eval-stdin.php (CVE-2017-9841): kode '<?=md5("phpunit")?>' di body (row 2940). Prioritas
    # terakhir agar body php://input baris PHP-CGI tetap K4.
    ("K3", "K5", re.compile(r"<\?(?:php|=)", re.IGNORECASE)),
)
_OUTCOMES: dict[str, dict[str, str]] = {
    "K1": {"candidate": "XSS"},
    "K2": {},
    "K3": {"reason": "OUT_OF_SCOPE"},
    "K4": {"reason": "OUT_OF_SCOPE"},
    "K5": {"reason": "HIDDEN_EVIDENCE"},
}


def _found(rows: pd.DataFrame, columns: tuple[str, ...], pattern: re.Pattern[str]) -> pd.Series:
    """True bila `pattern` cocok di salah satu kolom (regex per sel, aman terhadap NUL)."""
    hit = pd.Series(False, index=rows.index)
    for col in columns:
        hit |= rows[col].str.contains(pattern, regex=True)
    return hit


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label = LABELS[0]
    rows = df[df[label].astype(int) == 1]
    rule = pd.Series("K5", index=rows.index)  # tanpa subtipe sama sekali -> K5
    pending = pd.Series(True, index=rows.index)  # subtipe utama belum ditemukan
    for if_visible, if_hidden, pattern in _SUBTYPES:
        visible = _found(rows, _VISIBLE, pattern)
        primary = pending & (visible | _found(rows, _HIDDEN, pattern))
        rule = rule.mask(primary, if_hidden).mask(primary & visible, if_visible)
        pending &= ~primary
    return pd.concat([
        entries(rule.index[rule == rule_id], label, rule_id=rule_id, **outcome)
        for rule_id, outcome in _OUTCOMES.items()
    ])
