"""Langkah B — pembanding regex (§3.5 skripsi): aturan OWASP CRS + aturan pemindaian Baş Seyyar dkk.

Aturan CRS dibaca langsung dari berkas resmi versi terpatok (configs/regex_baseline.yaml) dan dievaluasi dengan emulasi
ModSecurity di modsec.py (mesin acuan di blok `engine`: ModSecurity 2.9.15 pada Apache httpd 2.4); aturan Baş Seyyar
dkk. ada di bas_seyyar.py. Tidak ada yang diimpor atau disalin dari src/data/gate/. Masukan hanya kolom masukan
test_sample_500.jsonl (tanpa label/template_key).

Keluaran per baris (results/regex.jsonl): label, skor per kelas, dan aturan yang cocok. Skor kelas = jumlah poin
severity aturan yang cocok, dihitung sekali per aturan (keputusan implementasi); ini bukan akumulasi skor anomali CRS, yang
di ModSecurity v2 bertambah setiap kali aturan cocok pada satu variabel (setvar dijalankan per kecocokan). Kelas = skor
tertinggi; seri dipecah urutan `tie_break`; NORMAL bila tidak ada aturan yang cocok. Metadata run (tanggal, commit,
versi aturan, mesin acuan) di results/regex.run.json.
Varian sekunder (configs/regex_full.yaml, `inherits` + semua kategori CRS) memakai kode yang sama; keluarannya
results/<name>.jsonl dengan `post_hoc: true`. Opsi --split val menjalankan konfigurasi pada srbh_val (penyesuaian
pemetaan) dan menulis ke results/tuning/.
Jalankan: make regex | make regex-full-val | make regex-full
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..common.inputs import SAMPLE_PATH, load_inputs, load_split_inputs, split_path
from ..common.runinfo import run_info, sha256_file
from ..data.clf_parser import LINE, REQUEST, unescape_logitem
from ..data.config import CONFIGS_DIR, ROOT
from . import bas_seyyar
from .crs import (Rule, available_categories, ensure_crs, ensure_unicode_mapping, load_data_file, load_rules, tree_digest,
                  tx_defaults)
from .modsec import Evaluator, Request, collections, compile_pcre, is_applicable, load_unicode_map, to_bytes_str

CONFIG_PATH = CONFIGS_DIR / "regex_baseline.yaml"
RESULTS_DIR = ROOT / "results"
ATTACK_CLASSES = ("SQLI", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "WEB_SCANNING")
MATCH_PREVIEW = 120


@dataclass
class RuleSet:
    rules: list[Rule]
    evaluator: Evaluator
    summary: dict


def load_config(path: Path = CONFIG_PATH) -> dict:
    """Konfigurasi YAML; `inherits` memuat konfigurasi induk lalu kunci anak menimpa (blok dict digabung satu tingkat)."""
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    parent_path = config.pop("inherits", None)
    if parent_path is None:
        return config
    merged = deepcopy(load_config(ROOT / parent_path))
    for key, value in config.items():
        merged[key] = {**merged[key], **value} if isinstance(value, dict) and isinstance(merged.get(key), dict) else value
    return merged


def engine_unicode_map(config: dict) -> list[int]:
    """Tabel SecUnicodeMapFile mesin acuan (blok `engine.unicode_mapping`): unduh terpatok, verifikasi, lalu muat."""
    mapping = config["engine"]["unicode_mapping"]
    path = ensure_unicode_mapping(mapping["url"], mapping["sha256"])
    return load_unicode_map(path.read_bytes().decode("latin-1"), int(mapping["codepage"]))


def build_ruleset(config: dict) -> RuleSet:
    """Muat aturan CRS terpatok, saring PL/operator/keterterapan, kompilasi regex, dan hitung ringkasannya."""
    crs = config["crs"]
    root = ensure_crs(crs["version"], crs["url"], crs["sha256"])
    categories = available_categories(root / "rules") if crs["categories"] == "all" else [str(c) for c in crs["categories"]]
    rules, report = load_rules(root / "rules", categories)
    excluded_ops = set(crs["excluded_operators"])
    summary = {"engine": config["engine"], "categories": categories, "loaded": len(rules), "by_category_pl": {},
               "above_pl": 0, "ignored_no_class": {}, "excluded_operator": [], "not_applicable": [], "used": 0}
    used = []
    for rule in rules:
        key = f"{rule.category}/PL{rule.paranoia}"
        summary["by_category_pl"][key] = summary["by_category_pl"].get(key, 0) + 1
        if rule.paranoia > int(crs["paranoia_level"]):
            summary["above_pl"] += 1
        elif mapped_class(rule, config) is None:  # kategori tanpa padanan kelas: tidak dievaluasi, dicatat
            summary["ignored_no_class"][rule.category] = summary["ignored_no_class"].get(rule.category, 0) + 1
        elif any(link.operator in excluded_ops for link in rule.links):
            summary["excluded_operator"].append(rule.id)
        elif not all(is_applicable(link) for link in rule.links):
            summary["not_applicable"].append(rule.id)
        else:
            for link in rule.links:
                if link.operator == "rx":
                    compile_pcre(link.argument)  # gagal kompilasi = galat, bukan dilewati diam-diam
            used.append(rule)
    summary["used"] = len(used)
    summary["used_by_category"] = {c: n for c in categories if (n := sum(r.category == c for r in used))}
    files = {f for r in used for link in r.links if link.operator in ("pmFromFile", "pmf") for f in link.argument.split()}
    defaults = tx_defaults(root / "rules")
    evaluator = Evaluator({f: load_data_file(root / "rules", f) for f in sorted(files)}, report.removals,
                          engine_unicode_map(config), defaults)
    summary["tx_defaults_used"] = sorted({m.lower() for r in used for link in r.links
                                          for m in re.findall(r"%\{tx\.(\w+)\}", link.argument, flags=re.IGNORECASE)
                                          if m.lower() in defaults})
    summary["control_rules_applied"] = sorted({r.rule_id for r in report.removals})
    summary["rules_dir_sha256"] = tree_digest(root / "rules")  # isi aturan yang benar-benar dimuat
    return RuleSet(used, evaluator, summary)


def request_from_row(row: dict) -> Request:
    """Request line dari raw_log_masked (URI persis seperti dikirim) + header yang tercatat (User-Agent, Referer)."""
    m = LINE.match(row["raw_log_masked"])
    r = REQUEST.match(m.group("request")) if m else None
    if r is None:
        raise ValueError(f"{row['id']}: raw_log_masked tidak dapat diurai")
    headers = {}
    for name, column in (("User-Agent", "user_agent"), ("Referer", "referer")):
        value = row.get(column) or ""
        if value and value != "-":
            headers[name] = to_bytes_str(value)
    return Request(r.group("method"), to_bytes_str(unescape_logitem(r.group("target"))), r.group("protocol"), headers)


def mapped_class(rule: Rule, config: dict) -> str | None:
    """Kelas bawaan sebuah aturan: `rule_class_map` per id, lalu `class_map` per kategori; None = tanpa padanan kelas."""
    by_rule = config.get("rule_class_map") or {}
    return by_rule.get(str(rule.id)) or config["class_map"].get(rule.category)


def rule_class(rule: Rule, hit_ids: set[int], config: dict) -> str:
    """Pemetaan hit -> kelas pada satu baris, termasuk berkas terlarang tanpa urutan traversal -> WEB_SCANNING."""
    special = config["restricted_files"]
    if rule.id in special["rules"] and not hit_ids & set(special["traversal_rules"]):
        return special["class_without_traversal"]
    return mapped_class(rule, config)


def _text(value: str) -> str:
    """str byte (latin-1) -> teks yang bisa dibaca untuk keluaran JSON."""
    return value.encode("latin-1").decode("utf-8", "backslashreplace")[:MATCH_PREVIEW]


def classify(row: dict, ruleset: RuleSet, config: dict) -> dict:
    coll = collections(request_from_row(row))
    removals = ruleset.evaluator.active_removals(coll)
    crs_hits = [(rule, m) for rule in ruleset.rules if (m := ruleset.evaluator.evaluate(rule, coll, removals))]
    hit_ids = {rule.id for rule, _ in crs_hits}
    points = config["scoring"]["severity_points"]
    matched = [
        {"rule": str(rule.id), "source": f"CRS {config['crs']['version']}", "class": rule_class(rule, hit_ids, config),
         "points": points[rule.severity], "variable": _text(m.variable), "matched": _text(m.data or m.value)}
        for rule, m in crs_hits
    ]
    bs = config["bas_seyyar"]
    # Algorithm 1: Set1 (XSS/SQLi) diperiksa lebih dulu; aturan pemindaian hanya bila Set1 kosong (diwakili CRS 941/942)
    if not any(rule.category in set(bs.get("phase1_crs_categories", [])) for rule, _ in crs_hits):
        for hit in bas_seyyar.evaluate(row, bs):
            same = bs.get("dedup_with_crs", {}).get(hit["rule"])
            if same is not None and int(same) in hit_ids:
                hit = {**hit, "points": 0, "note": f"bukti sama dengan CRS {same}, dihitung sekali"}
            matched.append({**hit, "source": "Baş Seyyar dkk. 2018", "class": config["class_map"]["bas_seyyar"]})
    scores = {c: 0 for c in ATTACK_CLASSES}
    for hit in matched:
        scores[hit["class"]] += hit["points"]
    label = "NORMAL"
    if any(scores.values()):
        order = config["scoring"]["tie_break"]
        label = max(ATTACK_CLASSES, key=lambda c: (scores[c], -order.index(c)))
    return {"id": row["id"], "label": label, "scores": scores, "matched_rules": matched}


def run(config_path: Path = CONFIG_PATH, inputs_path: Path = SAMPLE_PATH, out_dir: Path = RESULTS_DIR,
        split: str | None = None) -> dict:
    """Jalankan satu konfigurasi pada sampel uji (bawaan) atau pada split (`split="val"`, untuk penyesuaian pemetaan)."""
    config = load_config(config_path)
    name = config.get("name", "regex")
    ruleset = build_ruleset(config)
    if split is None:
        rows, source = load_inputs(inputs_path), inputs_path
    else:
        rows, source, out_dir = load_split_inputs(split), split_path(split), out_dir / "tuning"
    info = run_info(
        name, None,
        rules=f"OWASP CRS {config['crs']['version']} (PL{config['crs']['paranoia_level']}) + Baş Seyyar dkk. 2018",
        config_file=str(config_path.relative_to(ROOT)) if config_path.is_relative_to(ROOT) else str(config_path),
        post_hoc=bool(config.get("post_hoc", False)),
        input_file=str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else str(source),
        input_sha256=sha256_file(source),
        config_sha256=sha256_file(config_path),
        ruleset=ruleset.summary,
        rows=len(rows),
    )
    stem = name if split is None else f"{name}_{split}"
    extra = {"post_hoc": True} if config.get("post_hoc") else {}
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"{stem}.jsonl", "w", encoding="utf-8") as f:
        for row in rows:
            record = {**classify(row, ruleset, config), **extra, "run_id": info["run_id"]}
            f.write(json.dumps(record, ensure_ascii=True) + "\n")
    (out_dir / f"{stem}.run.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out = out_dir / f"{stem}.jsonl"
    info["output"] = str(out.relative_to(ROOT)) if out.is_relative_to(ROOT) else str(out)
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pembanding regex (CRS + Baş Seyyar dkk.)")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--split", choices=["train", "val", "test"], default=None,
                        help="jalankan pada srbh_<split>.parquet (penyesuaian pemetaan), bukan pada test_sample_500")
    args = parser.parse_args(argv)
    info = run(args.config.resolve(), split=args.split)
    s = info["ruleset"]
    print(f"[{info['method']}] {info['rows']} baris -> {info['output']} | aturan CRS dipakai {s['used']} "
          f"({s['used_by_category']}) | run {info['run_id']} (dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
