"""Utilitas bersama gerbang bukti (Langkah 3).

Kontrak modul aturan (satu modul per kelompok label):
- `LABELS`: tuple nama kolom label yang dievaluasi modul.
- `RULES`: dict rule_id -> deskripsi singkat (harus cocok dengan configs/label_mapping.yaml).
- `evaluate(df) -> DataFrame`: `df` berisi baris yang membawa salah satu `LABELS` (kolom string mentah
  hasil `read_raw` + kolom ter-decode dari `add_decoded`, index = index baris asal). Hasilnya format panjang,
  satu entri per (baris, label aktif), index = index baris asal, kolom: `label`, `candidate` (kelas serangan
  atau ""), `reason` (kode alasan eksklusi atau ""), `rule_id`, `weak` (bool).
  Entri dengan `candidate` dan `reason` kosong berarti label itu netral (kelas ditentukan label lain).

Semua pola regex gerbang diturunkan dari templat payload yang teramati di SR-BH 2020 (analisis bukti
2026-10-07, data/evidence/label_evidence_20261007/), BUKAN dari aturan OWASP CRS yang menjadi dasar baseline
regex di §3.5. Baseline tidak boleh mengimpor modul-modul di paket ini.

Catatan NUL: hasil decode bisa memuat '\\x00'. Jangan memakai operasi hash pandas (`unique`, `map(dict)`,
`groupby`, `factorize`) pada kolom ter-decode; pakai kolom mentah (bebas NUL) sebagai kunci.
"""

from __future__ import annotations

import html
from urllib.parse import unquote_plus

import pandas as pd

ATTACK_CLASSES = ("SQLI", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "WEB_SCANNING")

# Kode alasan eksklusi, urut dari yang paling diutamakan ketika satu baris punya beberapa alasan.
REASON_PRECEDENCE = ("LABEL_MISMATCH", "OUT_OF_SCOPE", "RFI_SCHEMELESS", "HIDDEN_EVIDENCE", "NO_EVIDENCE")
NORMAL_REASONS = ("EMPTY_ROW", "LABELER_BLIND", "INSPECTED_VISIBLE_PAYLOAD", "SCANNER_PROBE")

OUTPUT_COLUMNS = ["label", "candidate", "reason", "rule_id", "weak"]

# Kolom mentah -> kolom ter-decode (konvensi yang sama dengan analisis bukti).
DECODED = {
    "request_http_request": "uri_dec",
    "request_user_agent": "ua_dec",
    "request_referer": "ref_dec",
    "request_cookie": "cookie_dec",
    "request_body": "body_dec",
}


def multi_decode(text: str, layers: int = 3) -> str:
    """URL-decode (plus -> spasi) lalu unescape HTML, diulang hingga `layers` kali atau sampai tidak berubah."""
    for _ in range(layers):
        decoded = html.unescape(unquote_plus(text, errors="replace"))
        if decoded == text:
            break
        text = decoded
    return text


def add_decoded(df: pd.DataFrame) -> pd.DataFrame:
    """Salinan `df` dengan kolom *_dec. Decode per sel (bukan via hash) agar aman terhadap NUL."""
    out = df.copy()
    for src, dst in DECODED.items():
        out[dst] = [multi_decode(value) for value in df[src].tolist()]
    return out


def entries(index, label: str, candidate: str = "", reason: str = "", rule_id: str = "", weak: bool = False) -> pd.DataFrame:
    """Bangun potongan keluaran `evaluate` untuk sekumpulan index baris dengan hasil yang sama."""
    out = pd.DataFrame(index=pd.Index(index))
    out["label"], out["candidate"], out["reason"], out["rule_id"], out["weak"] = label, candidate, reason, rule_id, weak
    return out
