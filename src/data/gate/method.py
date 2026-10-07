"""Gerbang bukti label 272 — Protocol Manipulation dan 274 — HTTP Verb Tampering.

274 identik dengan "metode tidak kosong di luar GET/POST/HEAD/OPTIONS/TRACE" (5.437/5.437 baris, tidak ada baris
lain): sapuan metode otomatis 19 Jul (WebDAV, PUT/PATCH, TRACK, CONNECT) ditambah satu metode acak Nmap. Metode
tercatat di baris log, jadi seluruh label menjadi WEB_SCANNING (V1).

272 menandai anomali protokol yang dideteksi WAF pelabel, bukan satu jenis serangan, sehingga pemicunya dicari per
baris dengan urutan P1 > P4 > P3 > P2: probe penemuan yang terlihat di baris log -> WEB_SCANNING; pemicu terlihat
di luar taksonomi -> OUT_OF_SCOPE; anomali hanya di header Host atau body -> HIDDEN_EVIDENCE; sisanya NO_EVIDENCE.

Basename dan ekstensi dibaca dari path mentah sebelum '?' setelah satu lapis `unquote` (bukan dari `uri_dec`),
sama dengan definisi analisis bukti.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

import pandas as pd

from .common import entries

LABELS = ("272 - Protocol Manipulation", "274 - HTTP Verb Tampering")
RULES = {
    "P1": (
        "metode non-standar, ekstensi backup/terlarang (kecuali .com), akhiran '~', atau target tanpa '/' di depan"
        " -> WEB_SCANNING"
    ),
    "P2": "tidak ada pemicu di field mana pun -> NO_EVIDENCE",
    "P3": "anomali hanya di header Host/body -> HIDDEN_EVIDENCE",
    "P4": "path '.com' tanpa skema atau byte NUL di URI -> OUT_OF_SCOPE",
    "V1": "seluruh label 274 (metode non-standar terlihat di log) -> WEB_SCANNING",
}

# Metode baku SR-BH; metode lain (termasuk kosong) dihitung non-standar.
_STANDARD_METHODS = ("GET", "POST", "HEAD", "OPTIONS", "TRACE")

# Ekstensi = teks setelah titik terakhir basename, dibandingkan dalam huruf kecil.
_EXT = re.compile(r"\.([^.]+)$")

# Provenance: ekstensi probe berkas cadangan/terlarang pada baris 272 — sapuan cadangan ZAP 19 Jul
# (<berkas>.bak/.swp/.old/.backup/.log, 389 baris per sufiks), probe cadangan berkas konfigurasi Nmap 17 Jul
# (mis. wp-config.php, LocalSettings.php, mt-config.cgi dengan .bak/.swp/.old; 40 baris), .svn/wc.db (257), dan
# probe Nmap 17 Jul (*.sql, boot.ini, _vti_pvt/*.pwd, _vti_bin/*.dll, *.mdb). Label 272 hadir pada 2.279/2.286 baris
# berekstensi ini di SR-BH; sufiks lain dari sapuan yang sama (mis. .orig, .tmp, .bac, .~bk, .zip, .tar, .gz, .7z)
# berlabel NORMAL pada >=99% barisnya, jadi tidak dipakai. Daftar = 11 ekstensi dari daftar analisis bukti yang
# benar-benar muncul di SR-BH, selain 'com' (P4); penandanya identik dengan daftar analisis pada seluruh 907.815
# baris. Daftar analisis itu berasal dari restricted_extensions CRS 3.3.0 (aturan 920440), jadi ada tumpang-tindih
# parsial dengan CRS yang dinyatakan di laporan.
_BACKUP_EXT = re.compile(r"bak|swp|old|backup|log|db|sql|ini|pwd|dll|mdb")

# Provenance: templat RFI ZAP tanpa skema yang disisipkan sebagai segmen path ("/<dir>/www.google.com", 509 baris).
_SCHEMELESS_URL_EXT = "com"

# Host sah testbed SR-BH; nilai lain (IP literal, kosong, nama asing) adalah anomali header yang tidak tercatat di CLF.
_SITE_HOST = "test-site.com"


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    protocol, verb = LABELS
    rows = df[df[protocol].astype(int) == 1]
    uri = rows["request_http_request"]
    base = pd.Series([unquote(u.split("?", 1)[0]).rsplit("/", 1)[-1] for u in uri], index=rows.index, dtype=object)
    ext = base.str.extract(_EXT, expand=False).str.lower()
    # '~': sapuan cadangan ZAP 19 Jul (262) dan probe cadangan berkas konfigurasi Nmap 17 Jul (8). Target tanpa '/':
    # CONNECT www.google.com:80 (453), absolute-form 'http://<IP>:41200/pass' (6, 18 Jul), '?feed=' Nmap (3).
    probe = (
        ~rows["request_http_method"].isin(_STANDARD_METHODS)
        | ext.str.fullmatch(_BACKUP_EXT, na=False)
        | base.str.endswith("~")
        | ~uri.str.startswith("/")
    )
    # Byte NUL di URI: %00 di query pada probe Nmap (ColdFusion locale, tiki, PluginController, Zimbra skin) dan
    # ZAP 18 Jul.
    out_of_scope = ~probe & ((ext == _SCHEMELESS_URL_EXT) | rows["uri_dec"].str.contains("\x00", regex=False))
    content_type = rows["request_content_type"].str.split(";").str[0].str.strip()
    hidden_only = ~probe & ~out_of_scope & (
        rows["body_dec"].str.contains("\x00", regex=False)
        | (rows["request_host"] != _SITE_HOST)
        | ((rows["request_body"] != "") & (content_type == ""))
    )
    return pd.concat([
        entries(df.index[df[verb].astype(int) == 1], verb, candidate="WEB_SCANNING", rule_id="V1"),
        entries(rows.index[probe], protocol, candidate="WEB_SCANNING", rule_id="P1"),
        entries(rows.index[~(probe | out_of_scope | hidden_only)], protocol, reason="NO_EVIDENCE", rule_id="P2"),
        entries(rows.index[hidden_only], protocol, reason="HIDDEN_EVIDENCE", rule_id="P3"),
        entries(rows.index[out_of_scope], protocol, reason="OUT_OF_SCOPE", rule_id="P4"),
    ])
