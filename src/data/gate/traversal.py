"""Gerbang bukti label 126 — Path Traversal.

20.951 dari 20.992 baris berasal dari satu pemindai aktif (diduga OWASP ZAP), 41 dari Nmap NSE. Pola dan urutannya
berasal dari aturan R1a–R5 analisis bukti (agents/traversal-126/mapping.py), diturunkan dari templat payload yang
teramati pada label ini, bukan dari aturan CRS. Alternatif pola analisis yang tidak cocok dengan satu baris pun
berlabel 126 dibuang (akhiran '/..', overlong '%c0%ae', perintah selain 'cat /etc/passwd', pemisah '$(',
etc/shadow|group|hosts, system.ini, .bzr, .bzrignore, .cvs, web-inf); hasilnya identik. Keputusan per baris, yang
pertama cocok menang:
- T2 '<pemisah>cat /etc/passwd' di request line -> PATH_TRAVERSAL (935); semua baris ini juga berlabel 88, yang
  menang lewat prioritas sebagai CMD_INJECTION;
- T1 urutan traversal di request line (15.726) atau di UA (534) -> PATH_TRAVERSAL;
- T3 berkas VCS/backup/terlarang di path, tanpa traversal -> WEB_SCANNING (1.356);
- T1 berkas OS di request line tanpa '../' (nilai parameter '/etc/passwd' atau 'etc/passwd') -> PATH_TRAVERSAL (170);
- T4 selain itu -> HIDDEN_EVIDENCE (2.271).
Request line diperiksa mentah dan ter-decode (`uri_dec`); T3 hanya melihat path (sebelum '?' pertama), mentah dan
ter-decode dengan `multi_decode`. Analisis men-decode path dan query terpisah tanpa unescape HTML; hasilnya identik
pada 20.992 baris. Referer tidak memuat bukti pada label ini. Body, cookie, dan header lain tidak tercatat di log
akses sehingga tidak dibaca: T4 berisi 2.265 baris yang buktinya hanya di sana dan 6 baris tanpa bukti sama sekali.
"""

from __future__ import annotations

import re

import pandas as pd

from .common import entries, multi_decode

LABELS = ("126 - Path Traversal",)
RULES = {
    "T1": "urutan traversal di request line/UA, atau nilai parameter berupa path OS absolut -> PATH_TRAVERSAL",
    "T2": "'<pemisah>cat /etc/passwd' (selalu berlabel 88, CMD menang lewat prioritas) -> PATH_TRAVERSAL",
    "T3": "berkas VCS/backup/terlarang tanpa traversal -> WEB_SCANNING",
    "T4": "bukti hanya di body/header, atau tidak ada -> HIDDEN_EVIDENCE",
}

# ZAP Remote OS Command Injection di nilai parameter: 'cat /etc/passwd' setelah pemisah ; & | && || ` atau newline
# (11 varian, termasuk bentuk berkutip "';cat /etc/passwd;'"). Berkasnya bukti PT; perintahnya bukti label 88.
_CAT_PASSWD = re.compile(r"[;&|`\n][\s+]*cat[\s+]+/etc/passwd", re.IGNORECASE)
# ZAP Path Traversal: 16x'../' atau '..\' (..%2F, ..%5C, %252F; dengan/tanpa '/' di depan) di segmen path, nilai
# parameter, dan UA, serta '..%2F<halaman itu sendiri>' (18 baris); probe LFI Nmap NSE (ColdFusion 'locale=..\',
# boot.ini, CuteEditor, Zimbra). '%c0%2e%c0%2e' = titik overlong UTF-8 pada probe boot.ini Nmap (1 baris), yang tidak
# menjadi '..' setelah decode.
_TRAVERSAL = re.compile(r"\.\.[/\\]|%c0%2e%c0%2e", re.IGNORECASE)
# Probe penemuan berkas di web root: ZAP .git/index, .svn/entries, .svn/wc.db, .svn/text-base/*.svn-base, .htaccess;
# Nmap NSE .git/HEAD, .hg/requires, .gitignore, .hgignore, .htpasswd.svn-base, serta cadangan wp-config.php
# (.bak, .old, .save, .swp, '~', '#..#', 'Copy of') dan .htaccess ('#..#', 'Copy of').
_RESTRICTED = re.compile(
    r"(?:^|/)\.(?:git|svn|hg)(?:/|$)|\.(?:git|hg)ignore\b|\.svn-base|wc\.db|\.ht(?:access|passwd)\b|wp-config",
    re.IGNORECASE,
)
# Berkas OS yang diincar di label ini: etc/passwd (ZAP, juga nilai parameter '/etc/passwd' dan 'etc/passwd' tanpa
# '../'), win.ini, boot.ini, web.config, /dev/null, dan password.properties ColdFusion (Nmap NSE).
_OS_FILE = re.compile(r"etc/passwd\b|win\.ini|boot\.ini|web\.config|dev/null|password\.properties", re.IGNORECASE)


def _found(pattern: re.Pattern[str], *texts: pd.Series) -> pd.Series:
    """True bila pola cocok di salah satu teks (regex per sel, aman terhadap NUL)."""
    hit = pd.Series(False, index=texts[0].index)
    for text in texts:
        hit |= text.str.contains(pattern, regex=True)
    return hit


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label = LABELS[0]
    rows = df[df[label].astype(int) == 1]
    request, uri, ua = rows["request_http_request"], rows["uri_dec"], rows["ua_dec"]
    raw_path = request.str.split("?", n=1).str[0]
    path = pd.Series([multi_decode(value) for value in raw_path.tolist()], index=rows.index, dtype=object)
    command = _found(_CAT_PASSWD, uri, request)
    traversal = ~command & _found(_TRAVERSAL, uri, request, ua)
    restricted = ~command & ~traversal & _found(_RESTRICTED, path, raw_path)
    os_file = ~command & ~traversal & ~restricted & _found(_OS_FILE, uri, request)
    hidden = ~(command | traversal | restricted | os_file)
    return pd.concat([
        entries(rows.index[traversal | os_file], label, candidate="PATH_TRAVERSAL", rule_id="T1"),
        entries(rows.index[command], label, candidate="PATH_TRAVERSAL", rule_id="T2"),
        entries(rows.index[restricted], label, candidate="WEB_SCANNING", rule_id="T3"),
        entries(rows.index[hidden], label, reason="HIDDEN_EVIDENCE", rule_id="T4"),
    ])
