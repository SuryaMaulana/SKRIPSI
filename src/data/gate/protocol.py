"""Gerbang bukti label 34 — HTTP Response Splitting dan 33 — HTTP Request Smuggling.

Tidak ada kelas CRLF di Tabel 2.1, jadi kedua label tidak pernah memberi kandidat kelas; aturan yang sama berlaku
untuk keduanya. Label 34 identik dengan aturan lokasi CR/LF analisis (CR/LF di path ter-decode sekali, atau CR/LF +
nama header respons di query/body): 19.738/19.738 baris, 0 baris lain; 33 tidak pernah muncul sendirian. Isi 20.263
barisnya hanya tiga templat ZAP:
- probe CRLF 'any%3F%0D%0ASet-cookie%3A+Tamper%3D<UUID>' di path, query, atau body POST (15.114 baris);
- probe perintah OS berpemisah newline '%0Acat+%2Fetc%2Fpasswd%0A' / '%0Asleep+15%0A' di path (4.624 baris) atau
  body (12 baris berlabel 88(+126)+33); probe perintah ZAP yang sama di path (bentuk newline: 142 baris label 66;
  pemisah lain: NORMAL/66, serta 40 baris 16/272) tidak pernah berlabel 88 (D4);
- probe PHP-CGI CVE-2012-1823 berlabel 242+88+33 (513 baris): body terpotong di LF payload PHP (dugaan pemicu 33),
  sehingga tidak ada CR/LF di field mana pun dan kelasnya ditentukan label pendamping.
Pola memakai templat yang teramati, bukan CR/LF polos yang menjadi pemicu aturan CRS itu sendiri; pada SR-BH lokasi
templat sama persis dengan lokasi CR/LF ter-decode. CR/LF tidak pernah muncul di UA, Referer, atau cookie di seluruh
dataset, jadi bukti terlihat cukup dicari di URI. Penanda 'Set-cookie: Tamper=' tanpa CR/LF tepat di depannya
sengaja netral (R0, bukan R1/R3): di SR-BH ada 1.286 baris seperti itu di URI dan 21 di body, tidak satu pun
berlabel 34/33.
"""

from __future__ import annotations

import re

import numpy as np
import pandas as pd

from .common import entries, multi_decode

LABELS = ("34 - HTTP Response Splitting", "33 - HTTP Request Smuggling")
RULES = {
    "R0": "selain R1-R3 (di SR-BH: probe PHP-CGI berlabel 242+88, tanpa CR/LF) -> netral, kelas dari label lain",
    "R1": "probe CRLF terlihat di URI -> OUT_OF_SCOPE",
    "R2": "probe perintah OS dipisah newline di path -> LABEL_MISMATCH",
    "R3": "probe CRLF/perintah hanya di body -> HIDDEN_EVIDENCE",
}
_REASONS = {"R0": "", "R1": "OUT_OF_SCOPE", "R2": "LABEL_MISMATCH", "R3": "HIDDEN_EVIDENCE"}

# Provenance: probe CRLF ZAP, header sisipan 'Set-cookie: Tamper=<UUID>' tepat setelah CR/LF
# (varian any / any? x \r\n / \n; path 13.938, query 510, body 666 baris).
_CRLF_PROBE = re.compile(r"[\r\n]set-cookie:\s*tamper=", re.IGNORECASE)
# Provenance: probe perintah OS ZAP berpemisah newline, '\ncat /etc/passwd\n' dan '\nsleep 15\n'
# (masing-masing 2.312 baris di path; 12 baris di body).
_NEWLINE_CMD = re.compile(r"[\r\n](?:cat\s+/etc/passwd|sleep\s+\d+)", re.IGNORECASE)


def _decoded_path(raw_uri: pd.Series) -> pd.Series:
    """Path mentah sebelum '?' pertama, di-decode tersendiri agar '%3F' di path tidak terbaca sebagai awal query."""
    paths = [multi_decode(uri.split("?", 1)[0]) for uri in raw_uri.tolist()]
    return pd.Series(paths, index=raw_uri.index, dtype=object)


def _rule(rows: pd.DataFrame) -> np.ndarray:
    """rule_id per baris; urutan kondisi = prioritas (perintah di path, probe CRLF di URI, hanya di body)."""
    body = rows["body_dec"]
    conditions = [
        _decoded_path(rows["request_http_request"]).str.contains(_NEWLINE_CMD),
        rows["uri_dec"].str.contains(_CRLF_PROBE),
        body.str.contains(_CRLF_PROBE) | body.str.contains(_NEWLINE_CMD),
    ]
    return np.select([c.to_numpy(dtype=bool) for c in conditions], ["R2", "R1", "R3"], "R0")


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    active = np.column_stack([df[label].astype(int).to_numpy() == 1 for label in LABELS])
    keep = active.any(axis=1)
    rows, active = df[keep], active[keep]
    rule = _rule(rows)
    return pd.concat([
        entries(rows.index[active[:, i] & (rule == rule_id)], label, reason=reason, rule_id=rule_id)
        for i, label in enumerate(LABELS)
        for rule_id, reason in _REASONS.items()
    ])
