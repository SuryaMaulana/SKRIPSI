"""Gerbang bukti label 310 — Scanning for Vulnerable Software.

Seluruh baris berlabel 310 membawa UA pemindai yang tercatat di log akses: "Nmap Scripting Engine"
(2.714 baris, satu sesi 17 Jul 2020) dan "zgrab" (4 baris). Pola UA di bawah diambil dari dua UA yang
teramati pada label ini, bukan dari daftar pemindai CRS. Payload lain yang terlihat menang lewat prioritas.
"""

from __future__ import annotations

import re

import pandas as pd

from .common import entries

LABELS = ("310 - Scanning for Vulnerable Software",)
RULES = {
    "W1": "UA pemindai (Nmap Scripting Engine / zgrab) terlihat di log -> WEB_SCANNING",
    "W2": "UA pemindai tidak terlihat -> NO_EVIDENCE",
}

# Provenance: dua UA yang muncul pada 2.718/2.718 baris label 310 di SR-BH 2020.
_SCANNER_UA = re.compile(r"Nmap Scripting Engine|zgrab", re.IGNORECASE)


def evaluate(df: pd.DataFrame) -> pd.DataFrame:
    label = LABELS[0]
    rows = df[df[label].astype(int) == 1]
    seen = rows["request_user_agent"].str.contains(_SCANNER_UA, regex=True)
    return pd.concat([
        entries(rows.index[seen], label, candidate="WEB_SCANNING", rule_id="W1"),
        entries(rows.index[~seen], label, reason="NO_EVIDENCE", rule_id="W2"),
    ])
