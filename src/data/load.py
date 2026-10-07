"""Pemuatan SR-BH 2020 mentah tanpa mengandaikan nama kolom.

Semua sel dibaca sebagai string apa adanya (`keep_default_na=False`) agar payload seperti
"null", "NA", atau "-" tidak berubah menjadi NaN. Kolom label dikenali dari isinya
(hanya bernilai 0/1), bukan dari namanya.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd

from .config import SRBH_CSV

BINARY_VALUES = {"0", "1"}


def sniff_delimiter(path: Path) -> str:
    with open(path, newline="", encoding="utf-8") as fh:
        header = fh.readline()
    return csv.Sniffer().sniff(header, delimiters=",;\t|").delimiter


def read_raw(path: Path = SRBH_CSV) -> pd.DataFrame:
    return pd.read_csv(
        path,
        sep=sniff_delimiter(path),
        dtype=str,
        keep_default_na=False,
        na_filter=False,
        encoding="utf-8",
    )


def detect_label_columns(df: pd.DataFrame) -> list[str]:
    """Kolom yang seluruh nilainya 0/1, dalam urutan aslinya di berkas."""
    return [c for c in df.columns if set(df[c].unique()) <= BINARY_VALUES]
