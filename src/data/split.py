"""Langkah 8 — dedup isi, batas per templat RFI (label 194), lalu split stratified 70/15/15.

Urutan: dedup berdasarkan `raw_log_masked` = baris log tanpa stempel waktu dan tanpa protokol (keputusan penulis;
kemunculan pertama di berkas dipertahankan) -> batasi baris PATH_TRAVERSAL dari label 194 (aturan F1) maksimal `cap`
baris per templat payload -> split stratified per kelas tanpa pengelompokan IP (keputusan penulis).
"""

from __future__ import annotations

import pandas as pd
from sklearn.model_selection import train_test_split

from .config import RANDOM_STATE

RFI_RULE = "F1"


def dedup(df: pd.DataFrame, key: str = "raw_log_masked") -> tuple[pd.DataFrame, dict]:
    """Buang baris yang `key`-nya sudah muncul (pertahankan yang pertama). Isi identik berlabel berbeda dibuang semua."""
    n_labels = df.groupby(key)["label"].transform("nunique")  # teks log bebas NUL (sudah di-escape)
    conflict = n_labels > 1
    clean = df[~conflict]
    dup = clean.duplicated(key, keep="first")
    kept = clean[~dup]
    stats = {
        "key": key,
        "rows_in": len(df),
        "conflict_rows_dropped": int(conflict.sum()),
        "conflict_lines": int(df.loc[conflict, key].nunique()),
        "duplicates_dropped": int(dup.sum()),
        "duplicates_dropped_by_class": {k: int(v) for k, v in clean.loc[dup, "label"].value_counts().items()},
        "rows_out": len(kept),
    }
    return kept, stats


def cap_rfi_templates(df: pd.DataFrame, cap: int, random_state: int = RANDOM_STATE) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Sisakan maksimal `cap` baris per `rfi_template` di antara baris aturan F1 (acak dengan seed tetap).

    Mengembalikan (data setelah dibatasi, tabel jumlah sebelum/sesudah per templat, baris yang dibuang).
    """
    rfi = df[df["label_rule"] == RFI_RULE]
    keep_idx = []
    rows = []
    for template, group in rfi.groupby("rfi_template", sort=True):
        chosen = group if len(group) <= cap else group.sample(n=cap, random_state=random_state)
        keep_idx.extend(chosen.index)
        rows.append({"rfi_template": template, "before": len(group), "after": len(chosen)})
    dropped = rfi.index.difference(pd.Index(keep_idx))
    table = pd.DataFrame(rows, columns=["rfi_template", "before", "after"])
    return df.drop(index=dropped), table, df.loc[dropped]


def stratified_split(df: pd.DataFrame, random_state: int = RANDOM_STATE) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """70/15/15 stratified berdasarkan kolom `label`; setiap bagian diurutkan menurut row_id."""
    train, rest = train_test_split(df, test_size=0.30, stratify=df["label"], random_state=random_state)
    val, test = train_test_split(rest, test_size=0.50, stratify=rest["label"], random_state=random_state)
    return tuple(part.sort_values("row_id") for part in (train, val, test))
