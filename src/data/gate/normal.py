"""Gerbang bukti label 000 — Normal.

Label normal SR-BH dipakai apa adanya, kecuali baris yang labelnya tidak informatif atau jelas bukan lalu lintas sah
(keputusan K2a): di SR-BH 2020 118.793 dari 525.195 baris (22,6%), ditambah 2 baris kosong, sebagian besar lalu lintas
active scan OWASP ZAP. Aturan diperiksa berurutan, yang pertama menang:
- N0 EMPTY_ROW: ke-24 field fitur kosong.
- N1 LABELER_BLIND: path mentah sebelum '?' pertama memuat %2F (huruf besar/kecil sama), atau metode TRACE. Apache
  menjawab 404 untuk semua 125.868 permintaan ber-%2F (125.707 dengan halaman 276 byte) dan 405 untuk semua 2.340
  TRACE. 56.729 permintaan ber-%2F dan 48 TRACE berlabel serangan, sementara keluarga payload yang sama dilabeli tidak
  konsisten ('<script>' di path: 2.335 dari 2.385 baris ber-%2F berlabel normal, 0 dari 124 baris tanpa %2F), jadi
  label normal pada kelompok ini tidak andal. Karena itu aturan ini mengecualikannya tanpa melihat isi payload.
- N2 INSPECTED_VISIBLE_PAYLOAD: payload serangan eksplisit (`_PAYLOAD`, URL eksternal) di path, query, UA, atau Referer.
- N3 SCANNER_PROBE: sidik jari pemindai tanpa payload eksploit: penanda probe XSS ZAP, query '-s' PHP-CGI, segmen path
  hasil tampering atau nama berkas backup/tersembunyi di luar kosakata benign, UA pemindai, atau nilai fuzz di
  UA/Referer.
- N4 NORMAL: selain itu. Segmen kosong '//', URL templat crawler '{{ data.* }}', metode OPTIONS, payload yang hanya ada
  di body/cookie, dan UA alat uji tanpa payload bukan sidik jari (revisi reviewer), jadi tetap NORMAL.

Path dan query dipisah pada '?' pertama URI mentah lalu di-decode sendiri-sendiri dengan `multi_decode`, agar '%3F'
di path tidak terbaca sebagai awal query. Payload di UA/Referer dicari pada ua_dec/ref_dec; bentuk UA/Referer (nilai
fuzz) dinilai dari nilai mentah. Nilai ter-decode bisa memuat NUL, jadi pola dievaluasi sekali per nilai berbeda lewat
set/dict Python (membandingkan string utuh), bukan operasi hash pandas.

Kosakata benign (`benign_vocabulary`) diturunkan dari baris yang diberikan, sehingga `evaluate` harus menerima seluruh
baris berlabel normal sekaligus, seperti pada pipeline. Pola diambil dari pengklasifikasi sub-tipe analisis bukti
(agents/normal-audit/classify.py dan assign.py, templat ZAP hasil review manual baris normal), bukan dari aturan CRS.
Cabang alternasi dan anggota himpunan yang tidak cocok dengan satu pun baris normal dibuang (antara lain 'union select',
'whoami', 'javascript:', '.htaccess', dan nama pemindai selain Nmap/python-requests); hasil per baris tetap sama
persis dengan analisis. Jumlah di komentar pola = baris normal yang cocok, sebelum prioritas.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import numpy as np
import pandas as pd

from .common import entries, multi_decode

LABELS = ("000 - Normal",)
RULES = {
    "N0": "semua field kosong -> EMPTY_ROW",
    "N1": "path mentah sebelum '?' mengandung %2F, atau metode TRACE -> LABELER_BLIND",
    "N2": "payload serangan eksplisit terlihat di URI/UA/Referer -> INSPECTED_VISIBLE_PAYLOAD",
    "N3": "sidik jari pemindai tanpa payload -> SCANNER_PROBE",
    "N4": "selain di atas -> NORMAL",
}
_REASONS = {"N0": "EMPTY_ROW", "N1": "LABELER_BLIND", "N2": "INSPECTED_VISIBLE_PAYLOAD", "N3": "SCANNER_PROBE"}

# 24 field fitur SR-BH 2020 (semua kolom selain 14 label).
_FEATURES = [
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "request_http_method", "request_http_request",
    "request_http_protocol", "request_user_agent", "request_referer", "request_host", "request_origin",
    "request_cookie", "request_content_type", "request_accept", "request_accept_language", "request_accept_encoding",
    "request_do_not_track", "request_connection", "request_body", "response_http_protocol",
    "response_http_status_code", "response_http_status_message", "response_content_length",
]

# UA alat uji (pembawa 94,1% dan 2,9% baris serangan), tidak masuk pool kosakata. Pool = UA mentah lain yang tidak
# kosong dan muncul minimal 50 kali (frekuensi saja, bukan penyaring benign; lihat `benign_vocabulary`); ambang ada di
# celah distribusi (UA pool terjarang 60 baris, UA lain maks. 20).
_FIREFOX70 = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
_FIREFOX73 = "Mozilla/5.0 (X11; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0"
_POOL_MIN_ROWS = 50

# Provenance: templat payload active scan ZAP (dan dua probe Nmap/ThinkPHP) yang terlihat pada baris normal, sub-tipe
# A1-A10 analisis.
_PAYLOAD = re.compile(
    # Remote OS Command Injection: ';cat /etc/passwd;', '&cat$jj $jj/etc$jj/passwd&', 'sleep 15' setelah ; & | `
    # (dengan atau tanpa kutip), dan 'echo' pada varian ShellShock '() { :;}; echo ...' (25.449 baris).
    r"[;&|`\n]\s*(?:cat|sleep|echo)(?:\$\w+)*\s+[^\s&=]"
    # Shell Shock '() { :;}; /bin/sleep 15' sebagai segmen path (2.287).
    r"|\(\)\s*\{\s*:?\s*;?\s*\}\s*;"
    # Server Side Include '<!--#EXEC cmd="ls /"-->', juga berawalan '">' (4.740).
    r"|<!--\s*#\s*exec"
    # SQL Injection MySQL: "' / sleep(15) / '", '" / sleep(15) / "', "%';SELECT SLEEP(5)#", "%' ORDER BY 1#" (7.385).
    r"|sleep\s*\(\s*\d+\s*\)|order\s+by\s+\d+\s*#|select\s+sleep"
    # Cross Site Scripting '\'"<script>alert(1);</script>' (2.335).
    r"|<\s*/?\s*script\b|\balert\s*\("
    # Path Traversal: '/etc/passwd' (28.098, sebagian besar argumen 'cat'), '../../boot.ini' (9), Nmap VMware
    # '/sdk/../etc/vmware/hostd/vmInventory.xml' (2), '../' atau '..\' (351), 'c:/' atau 'c:\' di awal nilai, segmen
    # path, atau nilai parameter (5.169), dan penanda berkas ZAP (989).
    r"|etc/passwd|boot\.ini|etc/vmware|\.\.[/\\]|[/\\]\.\.(?:$|[/\\])|(?:^|[/=\\])c:[/\\]"
    r"|thishouldnotexistandhopefullyitwillnot"
    # External Redirect: '<angka acak>.owasp.org' (http://, HtTpS://, \\, http:\\) dan "5;URL='http://..'" (26.787).
    r"|\d{6,}\.owasp\.org|;\s*url\s*=\s*'?(?:https?:)?//"
    # CRLF Injection 'Set-cookie: Tamper=<UUID>' sebagai segmen path atau nilai, tanpa CR/LF (1.262).
    r"|set-cookie:\s*tamper="
    # Expression Language Injection '${n m}' dengan angka acak ('+' menjadi spasi setelah decode) (131).
    r"|\$\{\s*\d+\s*[+* ]\s*\d+\s*\}"
    # Server Side Code Injection '${@print(chr(122).chr(97)...)}' / ';print(chr(122)...)' dan ThinkPHP
    # '${@die(sha1(xyzt))}' (265).
    r"|\$\{@print\(|;\s*print\(chr\(|\$\{@die\(",
    re.IGNORECASE,
)

# Provenance: probe External Redirect ZAP yang sama ditulis sebagai URL eksternal utuh di segmen path atau nilai
# parameter (16.684 baris); host situs uji dikecualikan. Di path semua kecocokan juga tertangkap `_PAYLOAD`
# (<angka>.owasp.org); di query hanya row 543685 yang tidak: URL gravatar pada permintaan parameter pollution ZAP
# ('zap=zaproxy').
_EXTERNAL_URL = r"(?:https?:(?://|\\\\)|\\\\)(?!test-site\.com|www\.test-site\.com|172\.26\.)[a-z0-9.-]+\.[a-z]{2,}"
_EXTERNAL_IN_PATH = re.compile(r"(?:^|/)" + _EXTERNAL_URL, re.IGNORECASE)
_EXTERNAL_IN_QUERY = re.compile(r"(?:^|[&?=])" + _EXTERNAL_URL, re.IGNORECASE)

# Provenance: penanda probe XSS ZAP '0W45pz4p' dan 'zApPX<n>sS' tanpa tag atau skrip (6.368).
_XSS_MARKER = re.compile(r"0W45pz4p|zApPX\d+sS", re.IGNORECASE)
# Provenance: probe PHP-CGI CVE-2012-1823 ZAP, query '-s' (348 baris, semuanya persis '-s'; varian '-d' tidak muncul
# di baris normal).
_PHP_CGI_QUERY = re.compile(r"^-[sd](?:$|\s)", re.IGNORECASE)
# Provenance: UA pemindai yang teramati, Nmap Scripting Engine (20) dan python-requests/2.24.0 (1).
_SCANNER_UA = re.compile(r"nmap|python-requests", re.IGNORECASE)
# Provenance: awalan UA pool selain 37 UA fuzz ZAP: 'Mozilla/' (1.032 UA di baris normal, 1.019 di pool), msnbot/1.1,
# dan URL useragentstring.com. UA lain yang tidak kosong (2.649 baris) adalah nilai fuzz header ZAP: 'any?', '<!--',
# ']]>', kutip, kurung, string acak, kecuali satu python-requests.
_BROWSER_UA = re.compile(r"Mozilla/|msnbot|http://www\.useragentstring\.com/")
# Provenance: Referer situs uji. Referer lain adalah nilai fuzz ZAP ('<!--', ']]>', 'any?', urutan traversal) atau
# 'https://172.26.0.1/' dari alat uji Firefox 73 (1.476 baris).
_TEST_SITE_REFERER = re.compile(r"https?://(?:www\.)?test-site\.com(?:/|$)")
# Provenance: segmen path ter-decode dari probe Parameter Tampering ZAP: '%2B' (menjadi spasi setelah dua lapis
# decode), '%40', '%7C', '%00' (1.221-1.934 baris per segmen).
_TAMPER_SEGMENTS = frozenset({" ", "@", "|", "\x00"})
# Provenance: probe Backup Files ZAP pada segmen path ('blog.7z', 'blog~', 'blog - Copy', 'Copy of blog',
# 'blog_backup', 'backupblog', '1.bak.0', ...); kosakata benign mencegah 'oembed/1.0' terkena '.<angka>'.
_BACKUP_FILE = re.compile(
    r"(?:\.(?:bak|bac|backup|old|orig|tmp|swp|~bk|zip|tar|gz|bz2|7z|jar|exe|\d)|~| - Copy(?: \(\d+\))?|_backup|-backup"
    r"|backup)(?:\.[a-z0-9]{1,4})?$|^Copy (?:\(\d+\) )?of |^Copy of Copy of |^backup",
    re.IGNORECASE,
)
# Provenance: probe Hidden File ZAP, segmen '.git' dan '.svn' (masing-masing 23 baris).
_HIDDEN_FILE = re.compile(r"^(?:\.git|\.svn)$", re.IGNORECASE)


def benign_vocabulary(rows: pd.DataFrame) -> frozenset[str]:
    """Token URI baris pool UA berstatus 200: segmen '/' path dan token '&'/'=' query uri_dec (dipisah pada '?'
    pertama). Pool = UA mentah yang muncul >= 50 kali di `rows` (frekuensi saja, sama dengan tokens.py analisis),
    selain UA kosong dan dua UA alat uji. Pada seluruh baris normal SR-BH 2020 hasilnya 332 token dari 304 URI; pool
    ini juga memuat 37 UA fuzz ZAP (2.452 baris) yang menyumbang 9 dari 332 token dan menentukan 23 baris (N3).
    """
    ua = rows["request_user_agent"]  # kolom mentah bebas NUL, aman sebagai kunci hash
    pool = ua.map(ua.value_counts()).ge(_POOL_MIN_ROWS) & ~ua.isin(["", _FIREFOX70, _FIREFOX73])
    vocab: set[str] = set()
    for uri in set(rows.loc[pool & rows["response_http_status_code"].eq("200"), "uri_dec"].tolist()):
        path, _, query = uri.partition("?")
        vocab.update(path.split("/"))
        if query:
            vocab.update(re.split(r"[&=]", query))
    return frozenset(vocab)


def _per_value(values: list[str], test: Callable[[str], object]) -> np.ndarray:
    """`test` sekali per nilai berbeda; set/dict Python membandingkan string utuh sehingga aman terhadap NUL."""
    result = {value: bool(test(value)) for value in set(values)}
    return np.array([result[value] for value in values], dtype=bool)


def _probe_segment(path: str, vocab: frozenset[str]) -> bool:
    """Segmen path ter-decode hasil tampering ZAP, atau nama berkas backup/tersembunyi di luar kosakata benign."""
    for segment in path.split("/")[1:]:
        if (
            segment in _TAMPER_SEGMENTS
            or (len(segment) > 1 and segment.startswith("\\"))
            or (len(segment) > 1 and segment.endswith("%") and segment[:-1] in vocab)
            or _HIDDEN_FILE.match(segment)
            or (segment not in vocab and _BACKUP_FILE.search(segment))
        ):
            return True
    return False


def _fuzzed_ua(ua: str) -> bool:
    """Nilai fuzz UA ZAP: UA tidak kosong yang bukan UA browser, atau UA Firefox 70 alat uji yang diberi akhiran."""
    return (ua != "" and not _BROWSER_UA.match(ua)) or (ua.startswith(_FIREFOX70) and ua != _FIREFOX70)


def _rule(rows: pd.DataFrame, vocab: frozenset[str]) -> np.ndarray:
    """rule_id per baris; urutan kondisi = prioritas N0 > N1 > N2 > N3, sisanya N4."""
    parts = rows["request_http_request"].str.split("?", n=1)
    raw_path, raw_query = parts.str[0], parts.str[1].fillna("")
    decoded = {value: multi_decode(value) for value in set(raw_path) | set(raw_query)}
    path = [decoded[value] for value in raw_path]
    query = [decoded[value] for value in raw_query]
    ua, ref = rows["ua_dec"].tolist(), rows["ref_dec"].tolist()

    empty = rows[_FEATURES].eq("").all(axis=1).to_numpy()
    blind = (raw_path.str.contains("%2F", case=False, regex=False) | rows["request_http_method"].eq("TRACE")).to_numpy()
    payload = (
        _per_value(path, lambda v: _PAYLOAD.search(v) or _EXTERNAL_IN_PATH.search(v))
        | _per_value(query, lambda v: _PAYLOAD.search(v) or _EXTERNAL_IN_QUERY.search(v))
        | _per_value(ua, _PAYLOAD.search)
        | _per_value(ref, _PAYLOAD.search)
    )
    probe = (
        _per_value(path, lambda v: _XSS_MARKER.search(v) or _probe_segment(v, vocab))
        | _per_value(query, lambda v: _XSS_MARKER.search(v) or _PHP_CGI_QUERY.search(v))
        | _per_value(ua, lambda v: _XSS_MARKER.search(v) or _SCANNER_UA.search(v))
        | _per_value(ref, _XSS_MARKER.search)
        | _per_value(rows["request_user_agent"].tolist(), _fuzzed_ua)
        | _per_value(rows["request_referer"].tolist(), lambda v: v != "" and not _TEST_SITE_REFERER.match(v))
    )
    return np.select([empty, blind, payload, probe], ["N0", "N1", "N2", "N3"], "N4")


def rule_ids(rows: pd.DataFrame, vocab: frozenset[str]) -> np.ndarray:
    """rule_id N0–N4 per baris tanpa memeriksa label; dipakai audit laporan untuk mengukur efek seleksi gerbang."""
    return _rule(rows, vocab)


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label = LABELS[0]
    rows = df[df[label].astype(int) == 1]
    rule = _rule(rows, benign_vocabulary(rows))
    excluded = [
        entries(rows.index[rule == rule_id], label, reason=reason, rule_id=rule_id)
        for rule_id, reason in _REASONS.items()
    ]
    return pd.concat([*excluded, entries(rows.index[rule == "N4"], label, candidate="NORMAL", rule_id="N4")])
