"""Langkah 9 — sampel uji 500 baris dari srbh_test untuk eksperimen LLM.

Kuota (keputusan penulis K3b): XSS = seluruh baris XSS di split uji (±57). Sisa kuota dibagi rata ke lima kelas
lain; bila tidak habis dibagi, kelebihannya diberikan berurutan menurut CLASSES.
- SQLI: opsi `sample_weak_sqli` di configs/label_mapping.yaml. "exclude" (bawaan): pool hanya baris berbukti kuat;
  "include": baris berbukti lemah ikut diambil acak sesuai porsinya. Porsi ini menunggu konfirmasi penulis (D9).
- NORMAL: maksimal NORMAL_PER_TEMPLATE baris per templat (method, path tanpa query), dengan slot setiap templat dibagi
  proporsional antara baris ber-query dan tanpa query serta dibulatkan ke atas untuk baris ber-query; kuota NORMAL
  lalu diambil acak dari pool hasil batas itu (keputusan penulis).
Kelas lain diambil acak langsung dari pool-nya. Semua pengambilan memakai random_state tetap.
JSONL hanya memuat id, kolom evaluasi (label, template_key), dan masukan metode: raw_log_masked + hasil parsing tanpa
time/timestamp/protocol + hasil normalisasi. raw_log asli, waktu, protokol, dan fitur sesi hanya ada di parquet.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd
from pandas.api.types import is_scalar

from .config import CLASSES, RANDOM_STATE

SAMPLE_SIZE = 500
NORMAL_PER_TEMPLATE = 5
# Kolom evaluasi (jangan diberikan ke metode): label dan template_key (kunci klaster untuk bootstrap).
EVAL_COLUMNS = ["label", "template_key"]
# Masukan metode (keputusan penulis): raw_log_masked + hasil parsing tanpa time/timestamp/protocol + hasil normalisasi.
INPUT_COLUMNS = [
    "raw_log_masked", "ip", "ident", "user", "method", "path", "query", "status", "bytes", "referer", "user_agent",
    "path_norm", "query_norm", "ua_norm",
]
SAMPLE_COLUMNS = ["id", *EVAL_COLUMNS, *INPUT_COLUMNS]


def quotas(test: pd.DataFrame, size: int = SAMPLE_SIZE) -> dict[str, int]:
    n_xss = int((test["label"] == "XSS").sum())
    others = [c for c in CLASSES if c != "XSS"]
    base, extra = divmod(size - n_xss, len(others))
    out = {c: base + (1 if i < extra else 0) for i, c in enumerate(others)}
    out["XSS"] = n_xss
    return {c: out[c] for c in CLASSES}


def cap_normal_templates(pool: pd.DataFrame, per_template: int = NORMAL_PER_TEMPLATE, random_state: int = RANDOM_STATE) -> pd.DataFrame:
    """Maksimal `per_template` baris per (method, path); slot dibagi proporsional, baris ber-query dibulatkan ke atas."""
    has_query = pool["query"].fillna("") != ""
    keep = []
    for _, group in pool.groupby(["method", "path"], sort=True):  # path mentah bebas NUL
        slots = min(per_template, len(group))
        with_q, without_q = group[has_query[group.index]], group[~has_query[group.index]]
        n_q = min(len(with_q), math.ceil(slots * len(with_q) / len(group)))
        n_plain = min(len(without_q), slots - n_q)
        n_q = min(len(with_q), slots - n_plain)  # isi slot sisa bila baris tanpa query kurang
        for part, n in ((with_q, n_q), (without_q, n_plain)):
            keep.append(part if n == len(part) else part.sample(n=n, random_state=random_state))
    return pd.concat(keep)


WEAK_SQLI_OPTIONS = ("exclude", "include")


def draw_sample(
    test: pd.DataFrame, size: int = SAMPLE_SIZE, random_state: int = RANDOM_STATE, weak_sqli: str = "exclude"
) -> tuple[pd.DataFrame, dict]:
    """Sampel uji dan statistik pool per kelas (untuk laporan)."""
    if weak_sqli not in WEAK_SQLI_OPTIONS:
        raise ValueError(f"sample_weak_sqli harus salah satu {WEAK_SQLI_OPTIONS}, bukan {weak_sqli!r}")
    parts, pools = [], {}
    for cls, n in quotas(test, size).items():
        pool = test[test["label"] == cls]
        if cls == "SQLI" and weak_sqli == "exclude":
            pool = pool[~pool["weak_evidence"]]
        if cls == "NORMAL":
            pools["NORMAL_before_template_cap"] = len(pool)
            pool = cap_normal_templates(pool, random_state=random_state)
        pools[cls] = len(pool)
        if len(pool) < n:
            raise ValueError(f"Pool {cls} hanya {len(pool)} baris, kurang dari kuota {n}")
        parts.append(pool if n == len(pool) else pool.sample(n=n, random_state=random_state))
    return pd.concat(parts).sort_values("row_id"), pools


def _json_value(value):
    if is_scalar(value) and pd.isna(value):  # None, NaN, pd.NA, NaT
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if hasattr(value, "item"):  # skalar numpy
        return value.item()
    return value


def write_jsonl(sample: pd.DataFrame, path: Path, random_state: int = RANDOM_STATE) -> None:
    """Tulis dalam urutan acak (seed tetap): urutan row_id sama dengan urutan waktu sehingga mengelompokkan kelas."""
    path.parent.mkdir(parents=True, exist_ok=True)
    shuffled = sample.sample(frac=1, random_state=random_state)
    with open(path, "w", encoding="utf-8") as fh:
        for record in shuffled[SAMPLE_COLUMNS].to_dict("records"):
            fh.write(json.dumps({k: _json_value(v) for k, v in record.items()}, ensure_ascii=False) + "\n")
