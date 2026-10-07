"""Aturan pemindaian Baş Seyyar, Çatak, Gül (2018) yang dapat diputuskan dari satu baris log akses.

Sumber: M. Baş Seyyar, F. Ö. Çatak, E. Gül, "Detection of attack-targeted scans from the Apache HTTP Server access logs",
Applied Computing and Informatics 14(1):28-36, 2018, doi:10.1016/j.aci.2017.04.002. Aturan (daftar, pola, poin) ditulis
sebagai data di configs/regex_baseline.yaml (blok `bas_seyyar`) beserta rujukan bagian makalahnya; modul ini hanya
penafsirnya. Algorithm 1 makalah adalah rantai if/else, sehingga aturan dievaluasi berurutan dan berhenti pada aturan
pertama yang cocok: aturan `whitelist` (crawler) menghentikan evaluasi tanpa hit. Syarat makalah yang memerlukan agregasi
lintas baris (per IP) tidak dipakai karena klasifikasi penelitian ini murni per baris (keputusan penulis).
"""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import unquote_to_bytes

FIELDS = ("method", "path", "query", "uri", "user_agent", "referer", "status")


def field_value(row: dict, name: str) -> str:
    """Nilai satu kolom masukan; path/query/uri di-URL-decode sekali (byte -> latin-1) agar sama dengan aturan CRS."""
    if name in ("path", "query"):
        return unquote_to_bytes(row.get(name) or "").decode("latin-1")
    if name == "uri":
        query = row.get("query") or ""
        return field_value(row, "path") + ("?" + field_value(row, "query") if query else "")
    if name == "status":
        return str(row.get("status", ""))
    value = row.get(name) or ""
    return "" if value == "-" else value


@lru_cache(maxsize=None)
def _compiled(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def _match(rule: dict, value: str) -> str | None:
    kind = rule["match"]
    if kind == "is_empty":
        return "-" if value == "" else None
    if kind == "contains_any":
        low = value.lower()
        return next((v for v in rule["values"] if v.lower() in low), None)
    if kind == "equals_any":
        return next((v for v in rule["values"] if v.lower() == value.lower()), None)
    if kind == "endswith_any":
        low = value.lower()
        return next((v for v in rule["values"] if low.endswith(v.lower())), None)
    if kind == "regex":
        m = _compiled(rule["pattern"]).search(value)
        return m.group(0) if m else None
    raise ValueError(f"jenis pencocokan tidak dikenal: {kind}")


def _conditions(rule: dict) -> list[dict]:
    return rule["all"] if "all" in rule else [rule]


def rule_match(row: dict, rule: dict) -> tuple[str, str] | None:
    """(field, potongan cocok) bila semua syarat aturan terpenuhi pada baris ini, selain itu None."""
    found = []
    for cond in _conditions(rule):
        if cond["field"] not in FIELDS:
            raise ValueError(f"{rule['id']}: field tidak dikenal {cond['field']}")
        hit = _match(cond, field_value(row, cond["field"]))
        if hit is None:
            return None
        found.append((cond["field"], hit))
    return "+".join(f for f, _ in found), " & ".join(h for _, h in found)


def evaluate(row: dict, config: dict) -> list[dict]:
    """Rantai keputusan per baris: hit pertama [{rule, points, variable, matched}], atau [] (tidak ada / whitelist)."""
    for rule in config.get("rules", []):
        found = rule_match(row, rule)
        if found is None:
            continue
        if rule.get("action") == "whitelist":
            return []
        field, matched = found
        return [{"rule": rule["id"], "points": int(rule["points"]), "variable": field, "matched": matched[:120]}]
    return []
