"""Gerbang bukti label 88 — OS Command Injection dan 248 — Command Injection.

99,5% baris berlabel 88 berasal dari satu active scan OWASP ZAP; sisanya dropper botnet IoT, probe Nmap, dan satu
probe ThinkPHP. Tiga pola di bawah adalah aturan R1–R3 analisis bukti (skrip di luar repositori), diturunkan
dari templat payload yang teramati pada label ini, bukan dari aturan CRS. Alternatif '$(' dan kutip sebagai
pemisah di R1 dibuang karena tidak muncul di field mana pun di SR-BH 2020 (hasilnya identik). Pola dicari per
field. Kecocokan di URI, UA, atau Referer ter-decode (terlihat di log akses) dinilai berurutan, yang pertama menang:
- C1 perintah shell -> CMD_INJECTION;
- C2 '../' berulang atau /etc/passwd tanpa perintah -> netral, kelasnya dari label 126 (selalu ikut ada);
- C3 probe eval PHP / EL / ThinkPHP -> OUT_OF_SCOPE.
Bila tidak ada yang terlihat, ketiga pola yang sama dicari di body, cookie, dan header lain yang tidak tercatat
di log akses (header dibaca mentah, seperti pada analisis): ada -> HIDDEN_EVIDENCE (C4), tidak ada ->
NO_EVIDENCE (C5).

Label 248 hanya ada di row 4745: probe OGNL Struts2 dari Nmap di header Content-Type. CAPEC-248 adalah kategori
induk tanpa padanan kelas, jadi entrinya selalu netral (C0) dan kelas baris itu ditentukan label 310.
"""

from __future__ import annotations

import re

import pandas as pd

from .common import entries

LABELS = ("88 - OS Command Injection", "248 - Command Injection")
RULES = {
    "C0": "label 248 (kategori induk CAPEC) netral; kelas ditentukan label pendamping (310)",
    "C1": "perintah shell terlihat: pemisah + cat/sleep, Shellshock, SSI exec, dropper IoT, argumen PHP-CGI -> CMD_INJECTION",
    "C2": "hanya /etc/passwd atau ../ tanpa perintah (selalu berlabel 126 juga) -> netral, kelas lewat label 126",
    "C3": "probe eval PHP / EL / ThinkPHP -> OUT_OF_SCOPE",
    "C4": "bukti hanya di body/header -> HIDDEN_EVIDENCE",
    "C5": "tidak ada payload -> NO_EVIDENCE",
}

_VISIBLE = ("uri_dec", "ua_dec", "ref_dec")
_HIDDEN = (
    "body_dec", "cookie_dec", "request_host", "request_origin", "request_content_type", "request_accept",
    "request_accept_language", "request_accept_encoding", "request_connection", "request_do_not_track",
)

_SHELL = re.compile(
    # ZAP Remote OS Command Injection: 'cat /etc/passwd' (11 varian) dan 'sleep 15' (12 varian, termasuk
    # '&sleep$mc 15&') setelah pemisah ; & | && || ` atau newline, juga di dalam kutip: "';cat /etc/passwd;'".
    r"[;&|`\n]\s*(?:cat|sleep)(?:\$[a-z]{1,3})?\s+(?:/etc/passwd|\d+)"
    # ZAP Shell Shock: '() { :;}; echo X-Powered-By: ShellShock-Vulnerable' dan '() { :;}; /bin/sleep 15'.
    r"|\(\)\s*\{\s*:\s*;?\s*\}\s*;"
    # ZAP Server Side Include: '<!--#EXEC cmd="ls /"-->', juga dengan awalan '">'.
    r"|<!--\s*#\s*exec\b"
    # PHP-CGI CVE-2012-1823: '?-d allow_url_include=1 -d auto_prepend_file=php://input'.
    r"|-d\s+allow_url_include|auto_prepend_file"
    # Dropper botnet IoT: Zeroshell 'kerbynet?..;cd /tmp;curl -O http://..' dan ViewLog.asp
    # 'remote_host=;cd /tmp;wget http://..;chmod 777'.
    r"|;\s*cd\s+/tmp\s*;|(?:wget|curl\s+-O)\s+https?://",
    re.IGNORECASE,
)
_TRAVERSAL = re.compile(
    # ZAP Path Traversal 16x'../' (dengan atau tanpa '/' di depan) dan probe LFI Nmap (tiki, zimbra, '?p4yl04d=').
    r"(?:\.\.[/\\]){2,}"
    # ZAP Path Traversal: nilai parameter '/etc/passwd' atau 'etc/passwd' tanpa perintah.
    r"|(?:^|[?&=])/?etc/passwd",
    re.IGNORECASE,
)
_CODE_PROBE = re.compile(
    # ZAP Server Side Code Injection '${@print(chr(122).chr(97)...)}' (= 'zap_token') dan ThinkPHP '${@die(sha1(..))}'.
    r"\$\{\s*@?(?:print|die)\s*\("
    # ZAP Expression Language Injection '${n+m}' dengan angka acak ('+' menjadi spasi setelah decode).
    r"|\$\{\s*\d+[\s+]+\d+\s*\}",
    re.IGNORECASE,
)


def _found(rows: pd.DataFrame, columns: tuple[str, ...], *patterns: re.Pattern[str]) -> pd.Series:
    """True bila salah satu pola cocok di salah satu kolom (regex per sel, aman terhadap NUL)."""
    hit = pd.Series(False, index=rows.index)
    for col in columns:
        for pattern in patterns:
            hit |= rows[col].str.contains(pattern, regex=True)
    return hit


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label, parent = LABELS
    rows = df[df[label].astype(int) == 1]
    shell = _found(rows, _VISIBLE, _SHELL)
    traversal = _found(rows, _VISIBLE, _TRAVERSAL) & ~shell
    probe = _found(rows, _VISIBLE, _CODE_PROBE) & ~shell & ~traversal
    unseen = ~(shell | traversal | probe)
    hidden = unseen & _found(rows, _HIDDEN, _SHELL, _TRAVERSAL, _CODE_PROBE)
    return pd.concat([
        entries(rows.index[shell], label, candidate="CMD_INJECTION", rule_id="C1"),
        entries(rows.index[traversal], label, rule_id="C2"),
        entries(rows.index[probe], label, reason="OUT_OF_SCOPE", rule_id="C3"),
        entries(rows.index[hidden], label, reason="HIDDEN_EVIDENCE", rule_id="C4"),
        entries(rows.index[unseen & ~hidden], label, reason="NO_EVIDENCE", rule_id="C5"),
        entries(df.index[df[parent].astype(int) == 1], parent, rule_id="C0"),
    ])
