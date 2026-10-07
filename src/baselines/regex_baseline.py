"""Langkah B — pembanding regex (§3.5 skripsi): aturan OWASP CRS + aturan pemindaian Baş Seyyar dkk.

Aturan CRS dibaca langsung dari berkas resmi versi terpatok (configs/regex_baseline.yaml) dan dievaluasi dengan emulasi
ModSecurity di modsec.py (mesin acuan di blok `engine`: ModSecurity 2.9.15 pada Apache httpd 2.4); aturan Baş Seyyar
dkk. ada di bas_seyyar.py. Tidak ada yang diimpor atau disalin dari src/data/gate/. Masukan hanya kolom masukan
test_sample_500.jsonl (tanpa label/template_key).

Keluaran per baris (results/regex.jsonl): label, skor per kelas, dan aturan yang cocok. Skor kelas = jumlah poin
severity aturan yang cocok, dihitung sekali per aturan (keputusan asisten); ini bukan akumulasi skor anomali CRS, yang
di ModSecurity v2 bertambah setiap kali aturan cocok pada satu variabel (setvar dijalankan per kecocokan). Kelas = skor
tertinggi; seri dipecah urutan `tie_break`; NORMAL bila tidak ada aturan yang cocok. Metadata run (tanggal, commit,
versi aturan, mesin acuan) di results/regex.run.json.
Jalankan: make regex
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..common.inputs import SAMPLE_PATH, load_inputs
from ..common.runinfo import run_info, sha256_file
from ..data.clf_parser import LINE, REQUEST, unescape_logitem
from ..data.config import CONFIGS_DIR, ROOT
from . import bas_seyyar
from .crs import Rule, ensure_crs, ensure_unicode_mapping, load_data_file, load_rules, tree_digest
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
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def engine_unicode_map(config: dict) -> list[int]:
    """Tabel SecUnicodeMapFile mesin acuan (blok `engine.unicode_mapping`): unduh terpatok, verifikasi, lalu muat."""
    mapping = config["engine"]["unicode_mapping"]
    path = ensure_unicode_mapping(mapping["url"], mapping["sha256"])
    return load_unicode_map(path.read_bytes().decode("latin-1"), int(mapping["codepage"]))


def build_ruleset(config: dict) -> RuleSet:
    """Muat aturan CRS terpatok, saring PL/operator/keterterapan, kompilasi regex, dan hitung ringkasannya."""
    crs = config["crs"]
    root = ensure_crs(crs["version"], crs["url"], crs["sha256"])
    rules, report = load_rules(root / "rules", [str(c) for c in crs["categories"]])
    excluded_ops = set(crs["excluded_operators"])
    summary = {"engine": config["engine"], "loaded": len(rules), "by_category_pl": {}, "above_pl": 0,
               "excluded_operator": [], "not_applicable": [], "used": 0}
    used = []
    for rule in rules:
        key = f"{rule.category}/PL{rule.paranoia}"
        summary["by_category_pl"][key] = summary["by_category_pl"].get(key, 0) + 1
        if rule.paranoia > int(crs["paranoia_level"]):
            summary["above_pl"] += 1
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
    summary["used_by_category"] = {c: sum(r.category == c for r in used) for c in map(str, crs["categories"])}
    files = {f for r in used for link in r.links if link.operator in ("pmFromFile", "pmf") for f in link.argument.split()}
    evaluator = Evaluator({f: load_data_file(root / "rules", f) for f in sorted(files)}, report.removals,
                          engine_unicode_map(config))
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


def rule_class(rule_id: int, category: str, hit_ids: set[int], config: dict) -> str:
    """Pemetaan hit -> kelas (configs/regex_baseline.yaml), termasuk berkas terlarang tanpa urutan traversal."""
    special = config["restricted_files"]
    if rule_id in special["rules"] and not hit_ids & set(special["traversal_rules"]):
        return special["class_without_traversal"]
    return config["class_map"][category]


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
        {"rule": str(rule.id), "source": f"CRS {config['crs']['version']}", "class": rule_class(rule.id, rule.category, hit_ids, config),
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


def run(config_path: Path = CONFIG_PATH, inputs_path: Path = SAMPLE_PATH, out_dir: Path = RESULTS_DIR) -> dict:
    config = load_config(config_path)
    ruleset = build_ruleset(config)
    rows = load_inputs(inputs_path)
    info = run_info(
        "regex", None,
        rules=f"OWASP CRS {config['crs']['version']} (PL{config['crs']['paranoia_level']}) + Baş Seyyar dkk. 2018",
        input_file=str(inputs_path.relative_to(ROOT)) if inputs_path.is_relative_to(ROOT) else str(inputs_path),
        input_sha256=sha256_file(inputs_path),
        config_sha256=sha256_file(config_path),
        ruleset=ruleset.summary,
        rows=len(rows),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "regex.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps({**classify(row, ruleset, config), "run_id": info["run_id"]}, ensure_ascii=True) + "\n")
    (out_dir / "regex.run.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return info


def main() -> int:
    info = run()
    s = info["ruleset"]
    print(f"[regex] {info['rows']} baris -> results/regex.jsonl | aturan CRS dipakai {s['used']} "
          f"({s['used_by_category']}) | run {info['run_id']} (dirty={info['git_dirty']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
