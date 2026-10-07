"""Audit untuk laporan (Langkah 10): artefak dataset, kebocoran, dan keragaman sampel uji.

Semua angka di sini hanya untuk pengungkapan di reports/data_report.md; tidak ada yang mengubah label atau split.
Kunci templat di bawah dipakai untuk mengukur konsentrasi payload, bukan untuk menentukan kebenaran dasar.
"""

from __future__ import annotations

import re

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

from .config import CLASSES
from .gate import normal
from .gate.common import add_decoded, multi_decode
from .sample import cap_normal_templates

SPLITS = ("train", "val", "test")
SCAN_END = pd.Timestamp("2020-07-20", tz="UTC")  # semua baris serangan bertanggal 17–19 Jul (tabel §10)
_TIME_FIELD = re.compile(r" \[[^\]]*\] ")


def content_key(raw_log: pd.Series) -> pd.Series:
    """Baris log tanpa stempel waktu [%t]: dua permintaan identik pada detik berbeda punya kunci yang sama."""
    return raw_log.str.replace(_TIME_FIELD, " ", n=1, regex=True)


def content_overlap(splits: dict[str, pd.DataFrame], sample: pd.DataFrame) -> dict:
    """Berapa baris val/test/sampel yang isi permintaannya (tanpa waktu) juga ada di train, per kelas."""
    keys = {name: content_key(part["raw_log"]) for name, part in splits.items()}
    in_train = set(keys["train"])
    out = {"distinct_contents": int(pd.concat(keys.values()).nunique()), "rows": sum(len(p) for p in splits.values())}
    for name in ("val", "test"):
        part = splits[name]
        twin = keys[name].isin(in_train)
        out[name] = {c: (int(twin[part["label"] == c].sum()), int((part["label"] == c).sum())) for c in CLASSES}
        out[name]["_total"] = (int(twin.sum()), len(part))
    twin = content_key(sample["raw_log"]).isin(in_train)
    out["sample"] = {c: (int(twin[sample["label"] == c].sum()), int((sample["label"] == c).sum())) for c in CLASSES}
    out["sample"]["_total"] = (int(twin.sum()), len(sample))
    return out


def time_proxy(train: pd.DataFrame, sample: pd.DataFrame) -> dict:
    """Tebakan kelas sampel hanya dari waktu: label mayoritas baris train pada menit (jam dinding) yang sama."""
    minute = train["timestamp"].dt.floor("min")
    majority = train.groupby(minute)["label"].agg(lambda s: s.value_counts().index[0])
    guess = sample["timestamp"].dt.floor("min").map(majority).fillna("(tanpa tetangga)")
    days = pd.crosstab(sample["label"], sample["timestamp"].dt.normalize()).reindex(CLASSES).fillna(0).astype(int)
    days = days.sort_index(axis=1).rename(columns=lambda d: d.strftime("%d %b"))
    return {
        "accuracy": float((guess == sample["label"]).mean()),
        "macro_f1": float(f1_score(sample["label"], guess, labels=list(CLASSES), average="macro", zero_division=0)),
        "days": days,
    }


def normal_windows(test: pd.DataFrame) -> dict:
    """Pool NORMAL uji sebelum/sesudah batas templat: baris dan templat (method, path) di jendela 17–19 Jul vs hari lain."""
    pool = test[test["label"] == "NORMAL"]
    out = {}
    for name, part in (("pool", pool), ("capped", cap_normal_templates(pool))):
        scan = part["timestamp"] < SCAN_END
        out[name] = {
            "rows": len(part),
            "scan_rows": int(scan.sum()),
            "scan_templates": len(part.loc[scan, ["method", "path"]].drop_duplicates()),
            "other_templates": len(part.loc[~scan, ["method", "path"]].drop_duplicates()),
        }
    return out


def selection_effect(raw: pd.DataFrame, sample: pd.DataFrame) -> pd.DataFrame:
    """Aturan pembersih NORMAL (N1–N3) dijalankan tanpa label pada baris sampel: berapa yang akan ditandai per kelas."""
    normal_rows = add_decoded(raw[raw[normal.LABELS[0]].astype(int) == 1])
    vocab = normal.benign_vocabulary(normal_rows)
    rule = normal.rule_ids(add_decoded(raw.loc[sample["row_id"]]), vocab)
    flagged = pd.Series(np.isin(rule, ["N1", "N2", "N3"]), index=sample.index)
    return pd.DataFrame(
        {"ditandai": flagged.groupby(sample["label"]).sum(), "baris": sample.groupby("label").size()}
    ).reindex(CLASSES).fillna(0).astype(int)


def offset_runs(raw: pd.DataFrame) -> dict:
    """Rangkaian offset zona waktu menurut urutan berkas, dan blok bertanggal 01/Nov/2020."""
    ts = raw["timestamp"]
    valid = ts != ""
    offset = ts[valid].str[-5:]
    run_id = (offset != offset.shift()).cumsum()
    runs = [
        {"offset": grp.iat[0], "first_row": int(grp.index[0]), "last_row": int(grp.index[-1]), "rows": len(grp)}
        for _, grp in offset.groupby(run_id)
    ]
    merged = []  # baris kosong memutus rangkaian; gabungkan rangkaian berurutan dengan offset sama
    for run in runs:
        if merged and merged[-1]["offset"] == run["offset"]:
            merged[-1].update(last_row=run["last_row"], rows=merged[-1]["rows"] + run["rows"])
        else:
            merged.append(run)
    nov = raw.index[ts.str.startswith("01/Nov/2020")]
    head = raw.iloc[: len(nov)]
    block = raw.loc[nov]
    copies = (
        (head["timestamp"].str[11:20].to_numpy() == block["timestamp"].str[11:20].to_numpy())
        & (head["request_http_request"].to_numpy() == block["request_http_request"].to_numpy())
        & (head["request_user_agent"].to_numpy() == block["request_user_agent"].to_numpy())
    )
    first_mismatch = int(np.argmin(copies)) if not copies.all() else len(copies)
    return {"runs": merged, "nov_rows": len(nov), "nov_first_row": int(nov.min()), "nov_last_row": int(nov.max()),
            "nov_copies_of_first_rows": first_mismatch}


def multi_candidates(labeled: pd.DataFrame) -> dict[str, int]:
    multi = labeled["candidates"][labeled["candidates"].str.contains("+", regex=False)]
    return {k: int(v) for k, v in multi.value_counts().items()}


# --- konsentrasi templat payload di sampel ------------------------------------------------------------------------
_XSS = re.compile(r"""['"]*>?<script>.*?</script>(?:<")?|['"]\s*on\w+=['"]?alert\(1\);|<img[^>]*onerror=[^>]*>""", re.I)
_TRAVERSAL = re.compile(r"(?:(?:\.\.|%2e%2e)(?:%252f|%255c|%2f|%5c|/|\\)){2,}", re.I)
_TRAVERSAL_SEP = re.compile(r"%252f|%255c|%2f|%5c|/|\\", re.I)
_SHELL = re.compile(r"(?:[;&|`\n]|\$\()\s*(?:cat|sleep)\b|\(\)\s*\{|<!--\s*#\s*exec|allow_url_include|\b(?:wget|curl)\b", re.I)
_SQL_START = re.compile(
    r"""['"()]|\b(?:and|or|union|select|sleep|benchmark|waitfor|order\s+by|null|having|extractvalue|updatexml|rlike|xor)\b""",
    re.I,
)


def _carriers(row) -> dict[str, str]:
    target = row["path"] + ("?" + row["query"] if row["query"] else "")
    return {"uri": multi_decode(target), "ua": multi_decode(row["user_agent"]), "ref": multi_decode(row["referer"])}


def _xss_key(row) -> str:
    for carrier, value in _carriers(row).items():
        if m := _XSS.search(value):
            return f"{carrier}:{m.group()}"
    return "lainnya"


def _pt_key(row) -> str:
    if row["label_rule"] == "F1":
        return "RFI:" + row["rfi_template"]
    target = row["path"] + ("?" + row["query"] if row["query"] else "")
    for carrier, value in (("uri", target), ("ua", row["user_agent"]), ("ref", row["referer"])):
        if m := _TRAVERSAL.search(value):
            sep = _TRAVERSAL_SEP.findall(m.group())
            return f"{carrier}:{len(sep)}x..{sep[0].upper()}{'+passwd' if 'passwd' in value.lower() else ''}"
    return "lainnya"


def _cmd_key(row) -> str:
    for carrier, value in _carriers(row).items():
        if m := _SHELL.search(value):
            return f"{carrier}:" + re.sub(r"\d+", "0", value[max(0, m.start() - 2): m.end() + 12])
    return "lainnya"


def _ws_key(row) -> str:
    rule = row["label_rule"]
    if rule == "V1":
        return "V1:" + row["method"]
    if rule == "W1":
        return "W1:" + ("Nmap" if "Nmap" in row["user_agent"] else row["user_agent"][:20])
    if rule == "P1":
        m = re.search(r"\.[A-Za-z0-9~]+$", row["path"])
        return "P1:" + (m.group() if m else "?")
    if rule == "T3":
        return "T3:" + (".git" if ".git" in row["path"] else ".svn" if ".svn" in row["path"] else "lainnya")
    return rule


def _sqli_key(row) -> str:
    value = _carriers(row)["uri"]
    m = _SQL_START.search(value)
    if not m:
        return "lainnya"
    span = re.sub(r"\d+", "0", value[m.start(): m.start() + 40])
    return re.sub(r"\b[A-Za-z]{4}\b(?=$|[\s\-#/])", "W", span).split("/")[0]  # token acak 4 huruf sqlmap


_KEY = {
    "XSS": _xss_key, "PATH_TRAVERSAL": _pt_key, "CMD_INJECTION": _cmd_key, "WEB_SCANNING": _ws_key,
    "SQLI": _sqli_key, "NORMAL": lambda row: row["method"] + " " + row["path"],
}


def template_keys(df: pd.DataFrame) -> pd.Series:
    """Kunci templat payload per baris (kunci yang sama dengan laporan §6; dipakai bootstrap klaster saat evaluasi)."""
    return df.apply(lambda row: _KEY[row["label"]](row), axis=1).astype(str)


def template_concentration(sample: pd.DataFrame) -> pd.DataFrame:
    """Per kelas: jumlah templat, templat terbesar, porsi 3 teratas, dan n efektif Kish (n² / Σ m²)."""
    keys = template_keys(sample)
    rows = []
    for cls in CLASSES:
        counts = keys[sample["label"] == cls].value_counts()
        n = int(counts.sum())
        rows.append({
            "kelas": cls, "baris": n, "templat": len(counts), "terbesar": counts.index[0], "terbesar_n": int(counts.iloc[0]),
            "top3_n": int(counts.head(3).sum()), "n_eff": n * n / float((counts**2).sum()),
        })
    return pd.DataFrame(rows)
