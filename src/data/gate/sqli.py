"""Gerbang bukti label 66 — SQL Injection.

Isi label 66 adalah active scan sqlmap dan OWASP ZAP yang menyuntikkan payload terutama ke segmen path.
Famili payload diperiksa pada URI, User-Agent, dan Referer ter-decode (field Combined Log Format) menurut
urutan `_VISIBLE`; famili pertama yang cocok menentukan aturan, jadi sintaks SQL menang atas payload lain dan
probe metakarakter (S2, hanya di URI) baru dihitung bila tidak ada famili lain. Baris tanpa famili terlihat
menjadi S5 bila famili yang sama ada di body, cookie, atau header lain (redirect: hanya probe ZAP; ditambah
nilai parameter berupa metakarakter di body/cookie), S7 bila UA Nmap (label 66 netral, kelasnya dari label
310), selain itu S6.

Famili, urutan, dan hasilnya sama dengan analisis bukti 2026-10-07 (skrip di luar repositori: fam.py,
m8_families2.py, m13_hidden.py, m25_mapping.py). Setiap alternatif regex adalah templat yang teramati pada baris
label 66; alternatif analisis yang tidak pernah cocok di field mana pun (mis. pg_sleep, waitfor delay, phpinfo,
famili format string) atau yang tercakup alternatif lain (mis. select..from, information_schema, tautologi
generik) tidak dibawa. Hasil pada data asli: S1 187.338, S2 28.625, S3 22.847, S4 5.529, S5 5.340, S6 629,
S7 3 baris.
"""

from __future__ import annotations

import re

import numpy as np
import pandas as pd

from .common import entries

LABELS = ("66 - SQL Injection",)
RULES = {
    "S1": "sintaks SQL (templat sqlmap/ZAP) terlihat di URI/UA/Referer -> SQLI",
    "S2": "hanya probe metakarakter 1-2 karakter tanpa sintaks SQL (', \", (, ), ;, %, |, NULL, atau pasangan kutip "
    "'\"/\"') di segmen path/nilai parameter URI -> SQLI, bukti lemah",
    "S3": "payload CMD/XSS/PT terlihat tanpa sintaks SQL -> LABEL_MISMATCH",
    "S4": "probe XPath/XML, open redirect, PHP, CRLF, SSI, EL, atau penanda ZAP -> OUT_OF_SCOPE",
    "S5": "bukti hanya di body/cookie/header -> HIDDEN_EVIDENCE",
    "S6": "tidak ada bukti -> NO_EVIDENCE",
    "S7": "enumerasi path Nmap tanpa payload (UA Nmap; kelas dari label 310) -> netral",
}
_OUTCOME = {
    "S1": {"candidate": "SQLI"},
    "S2": {"candidate": "SQLI", "weak": True},
    "S3": {"reason": "LABEL_MISMATCH"},
    "S4": {"reason": "OUT_OF_SCOPE"},
    "S5": {"reason": "HIDDEN_EVIDENCE"},
    "S6": {"reason": "NO_EVIDENCE"},
    "S7": {},
}


def _any(*templates: str) -> re.Pattern[str]:
    """Satu regex (tanpa beda huruf besar/kecil) dari templat-templat alternatif."""
    return re.compile("|".join(templates), re.IGNORECASE)


# Provenans tiap alternatif: templat yang teramati pada baris label 66 (angka/huruf acak ditulis 1234, abcd).
# sqlmap — payload di segmen path, sering didahului ', ') atau ").
_SQLMAP = _any(
    r"union all select null(?:,null)*(?:#|-- -)",  # UNION: "UNION ALL SELECT NULL,NULL-- -"
    r"\b(?:and|or)\s+\d{4}=\d{4}\b",  # boolean-blind: "AND 1234=1234"
    r"\b(?:and|or) '[a-z]{4}'='[a-z]{4}",  # boolean-blind string: "AND 'abcd'='abcd"
    r"rlike \(select \(case when",  # "RLIKE (SELECT (CASE WHEN (1234=1234) THEN 0x.. ELSE 0x28 END))"
    r"\(select \(case when \(\d+=\d+\)",  # "(SELECT (CASE WHEN (1234=1234) THEN 1234 ELSE 1234*(SELECT ..."
    r"sleep\(5\)",  # time-based: "AND SLEEP(5)", "THEN SLEEP(5)"
    r"concat\(0x",  # error-based: "CONCAT(0x3a..3a,(SELECT (ELT(1234=1234,1))),0x3a..3a,FLOOR(..))", "CONCAT(0x5c,..)"
    r"\belt\(",  # "(SELECT (ELT(1234=1234,1)))"
    r"extractvalue\(",  # "AND EXTRACTVALUE(1234,CONCAT(0x5c,..))"
    r"procedure analyse",  # "PROCEDURE ANALYSE(EXTRACTVALUE(..),1)"
    r"information_schema\.character_sets",  # "(SELECT 1234 FROM INFORMATION_SCHEMA.CHARACTER_SETS)"
    r"order by \d+\s*(?:-- -|#)",  # "ORDER BY 1-- -"
    r"-- -$|-- -/",  # penutup komentar "-- -" di akhir URI atau sebelum segmen path berikutnya
    r"updatexml\(",  # probe Joomla "list[fullordering]=updatexml(1,concat(1,user()),1)" (1 baris)
)
# OWASP ZAP — SQL Injection active scan.
_ZAP_SQL = _any(
    r"' or '1'='1|\" or \"1\"=\"1|\bor 1=1\b",  # "' OR '1'='1' -- " dan varian kutip ganda/numerik
    r"\band 1=[12]\b|' and '1'='[12]|\" and \"1\"=\"[12]",  # boolean: "AND 1=1 -- " / "AND 1=2 -- "
    r"union all select null --",  # "UNION ALL select NULL -- "
    r"0 in \(select sleep\(15\) \)",  # time-based: "and 0 in (select sleep(15) ) -- "
    r"/ sleep\(15\) /",  # "' / sleep(15) / '"
    r"%'\s+--|%\"\s+--",  # "%'  -- "
    r" (?:asc|desc)\s+--(?:\s|$|/|\?|&)",  # ORDER BY: " ASC  -- ", " DESC  -- "
)
# Varian sintaks SQL di luar dua templat di atas (128 baris hanya tertangkap di sini; juga dipakai di body/header).
_SQL_OTHER = _any(
    r"union[\s/*+()]+(?:all[\s/*+()]+)?select",  # probe Nmap "?p4yl04d2=1 UNION ALL SELECT 1,2,3,table_name ..."
    r"sleep\s*\(",  # ZAP "/ sleep(15) " tanpa '/' penutup, sqlmap "AND SLEEP(5" terpotong
    r"['\")]\s*(?:--(?!>)|#|/\*)",  # komentar setelah kutip: ZAP "XYZABCDEFGHIJ'  -- "
)
# Probe perintah OS ZAP (S3).
_CMD = _any(
    r"(?:;|&|\||`|\n)\s*sleep 15|sleep 15\s*(?:;|&|\||#|`)",  # ";sleep 15;", "&sleep 15&", "`sleep 15`", "\nsleep 15\n"
    r"&&sleep|\|\|sleep",  # "&&sleep 15", "||sleep 15"
    r"sleep\$\w*\s*15",  # "&sleep$mc 15&"
    r"/bin/sleep",  # "() { :;}; /bin/sleep 15"
    r"(?:;|&|\||`|\n)\s*cat /etc/passwd|cat /etc/passwd\s*(?:;|&|\||#)",  # ";cat /etc/passwd;", "&cat /etc/passwd&"
    r"cat\$\w+|\$\w+/etc\$\w+/passwd",  # "&cat$jj $jj/etc$jj/passwd&"
)
_SHELLSHOCK = _any(r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;")  # ZAP "() { :;}; echo 'X-Powered-By: ShellShock-Vulnerable'"
# XSS ZAP (S3).
_XSS = _any(
    r"<\s*/?\s*script\b",  # "'\"<script>alert(1);</script>"
    r"\balert\s*\(",  # alert(1) pada ketiga templat
    r"\bon(?:error|load|mouseover|focus|click)\s*=",  # "\" onMouseOver=\"alert(1);"
    r"javascript\s*:",  # "javascript:alert(1);"
)
# Injeksi kode PHP ZAP (S4): "${@print(chr(122).chr(97)..)}", ";print(chr(..));$var=\"".
_PHP = _any(r"print\(chr\(", r"\$var=")
_SSI = _any(r"<!--\s*#\s*(?:exec|include|echo)")  # SSI ZAP (S4): '<!--#EXEC cmd="ls /"-->'
# Traversal ZAP (S3): segmen path "/etc/passwd", "c:\" atau "c:/"; satu "load[]=../load-styles.php".
_PATH = _any(r"\.\.[/\\]", r"/etc/passwd", r"c:[/\\]")
_CRLF = _any(r"set-cookie:\s*tamper", r"[\r\n]")  # CRLF ZAP (S4): "\r\nSet-cookie: Tamper=<uuid>"
# Open redirect ZAP (S4): "http://1234.owasp.org" dan "0;URL='http://1234.owasp.org'" di segmen path.
# Hanya bagian probe ini yang dipakai untuk bukti tersembunyi (URL biasa di body form tidak dihitung).
_REDIRECT_PROBE = r"owasp\.org|url='https?://"
_REDIRECT = _any(
    _REDIRECT_PROBE,
    r"=\s*(?:https?|ftp)://(?!test-site\.com)",  # URL host lain di nilai parameter: "url=http://www.example.com"
    r"^/[^?]*(?:https?|ftp):/+(?!test-site\.com)",  # URL di segmen path: "/URL='http://1234.owasp.org'"
)
_XML = _any(r"\]\]>|<!--")  # XPath/XML ZAP (S4): segmen path "]]>" dan "<!--"
_EL = _any(r"\$\{[^}]{1,80}\}")  # EL ZAP (S4): "${1234+5678}" ('+' ter-decode menjadi spasi)
_MARKER = _any(r"0w45pz4p|zappx\d+ss")  # token penanda ZAP (S4): "0W45pz4p", "zApPX123sS"
# Probe metakarakter ZAP (S2, hanya di URI): segmen path/nilai parameter yang seluruhnya metakarakter atau "null" ...
_META_ONLY = re.compile(r"(?:^|/|=)(?:['\"();%|]+|null)(?:/|$|&|\?)", re.IGNORECASE)
# ... atau diakhiri metakarakter/"NULL" (mode 'append' ZAP; NULL huruf besar seperti payload-nya).
_META_APPENDED = re.compile(r"[^/=&?](?:['\"();%|]+|NULL)(?:/|$|&|\?)")
# Probe yang sama pada nilai parameter body/cookie (S5).
_META_VALUE = re.compile(r"(?:=|[a-z0-9])(?:['\"();%|]+|null)(?:&|$)", re.IGNORECASE)

_CLF = ("uri_dec", "ua_dec", "ref_dec")
# (aturan, famili, field) dalam urutan analisis bukti: famili pertama yang cocok menentukan aturan.
_VISIBLE = (
    ("S1", _SQLMAP, _CLF), ("S1", _ZAP_SQL, _CLF), ("S1", _SQL_OTHER, _CLF),
    ("S3", _CMD, _CLF), ("S3", _SHELLSHOCK, _CLF), ("S3", _XSS, _CLF),
    ("S4", _PHP, _CLF), ("S4", _SSI, _CLF),
    ("S3", _PATH, _CLF),
    ("S4", _CRLF, _CLF), ("S4", _REDIRECT, _CLF), ("S4", _XML, _CLF), ("S4", _EL, _CLF), ("S4", _MARKER, _CLF),
    ("S2", _META_ONLY, ("uri_dec",)), ("S2", _META_APPENDED, ("uri_dec",)),
)
# Famili yang sama untuk bukti di luar log akses (S5), dengan redirect dipersempit ke probe ZAP.
_HIDDEN = _any(_REDIRECT_PROBE, *(p.pattern for p in (
    _SQLMAP, _ZAP_SQL, _SQL_OTHER, _CMD, _SHELLSHOCK, _XSS, _PHP, _SSI, _PATH, _CRLF, _XML, _EL, _MARKER,
)))
_HEADERS = (
    "request_host", "request_origin", "request_content_type", "request_accept",
    "request_accept_language", "request_accept_encoding", "request_connection", "request_do_not_track",
)


def _contains(texts: list[pd.Series], pattern: re.Pattern[str]) -> np.ndarray:
    """True bila `pattern` cocok di salah satu teks (regex per sel, aman terhadap NUL)."""
    return np.logical_or.reduce([t.str.contains(pattern, na=False).to_numpy(dtype=bool) for t in texts])


def _without_visible(rows: pd.DataFrame) -> np.ndarray:
    """S5 bila famili ada di body/cookie/header lain, S7 bila UA Nmap Scripting Engine, selain itu S6."""
    # Header digabung dengan \x1f seperti analisis bukti (\s juga cocok dengan \x1f).
    headers = rows[_HEADERS[0]].str.cat([rows[c] for c in _HEADERS[1:]], sep="\x1f")
    hidden = _contains([rows["body_dec"], rows["cookie_dec"], headers], _HIDDEN)
    hidden |= _contains([rows["body_dec"], rows["cookie_dec"]], _META_VALUE)
    nmap = rows["request_user_agent"].str.contains("Nmap", regex=False, na=False).to_numpy(dtype=bool)
    return np.select([hidden, nmap], ["S5", "S7"], default="S6")


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label = LABELS[0]
    rows = df[df[label].astype(int) == 1]
    rule = np.full(len(rows), "", dtype=object)
    for rule_id, pattern, fields in _VISIBLE:  # hanya baris yang belum cocok dengan famili sebelumnya
        todo = np.flatnonzero(rule == "")
        rule[todo[_contains([rows[f].iloc[todo] for f in fields], pattern)]] = rule_id
    rest = np.flatnonzero(rule == "")
    rule[rest] = _without_visible(rows.iloc[rest])
    return pd.concat([entries(rows.index[rule == rid], label, rule_id=rid, **_OUTCOME[rid]) for rid in RULES])
