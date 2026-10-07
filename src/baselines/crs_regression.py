"""Verifikasi fidelitas emulasi CRS terhadap uji regresi resmi CRS (format go-ftw YAML di tests/regression/tests/).

Hanya uji yang muatannya terlihat di log akses yang dipakai: tanpa body, tanpa permintaan mentah/ter-encode, dan tanpa
header selain User-Agent/Referer (header umum seperti Host/Accept diabaikan). Aturan libinjection dan aturan yang tidak
berlaku untuk data log dilewati. Setiap uji membandingkan apakah aturan yang diuji cocok (expect_ids / log_contains)
atau tidak (no_expect_ids / no_log_contains). Jalankan: make verify-crs -> results/crs_regression.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

from ..common.runinfo import run_info
from ..data.config import ROOT
from .crs import available_categories, ensure_crs, load_data_file, load_rules, tree_digest, tx_defaults
from .modsec import Evaluator, Request, collections, compile_pcre, is_applicable, to_bytes_str
from .regex_baseline import CONFIG_PATH, engine_unicode_map, load_config, mapped_class

LOGGED = {"user-agent", "referer"}
IGNORED_HEADERS = {"host", "accept", "connection", "accept-encoding", "accept-language", "accept-charset",
                   "cache-control", "content-length", "pragma", "upgrade-insecure-requests", "keep-alive", "te",
                   "proxy-connection"}


def _expected(rule_id: int, output: dict) -> bool | None:
    log = output.get("log") or {}
    expect = set(log.get("expect_ids") or [])
    no_expect = set(log.get("no_expect_ids") or [])
    expect |= {int(x) for x in re.findall(r"\d{6}", str(output.get("log_contains", "")))}
    no_expect |= {int(x) for x in re.findall(r"\d{6}", str(output.get("no_log_contains", "")))}
    return True if rule_id in expect else False if rule_id in no_expect else None


def verify(root: Path, categories: list[str], excluded_operators: set[str], max_pl: int = 4,
           unicode_map: list[int] | None = None, keep=None) -> dict:
    """`keep(rule)` membatasi aturan yang diuji (mis. hanya aturan yang dipetakan ke kelas oleh varian regex_full)."""
    rules, report = load_rules(root / "rules", categories)
    if keep is not None:
        rules = [r for r in rules if keep(r)]
    by_id = {r.id: r for r in rules}
    files = {f for r in rules for link in r.links if link.operator in ("pmFromFile", "pmf") for f in link.argument.split()}
    evaluator = Evaluator({f: load_data_file(root / "rules", f) for f in sorted(files)}, report.removals, unicode_map,
                          tx_defaults(root / "rules"))
    stats: Counter = Counter()
    mismatched: list[dict] = []
    per_rule: dict[int, list[int]] = {}
    disagreements = []
    test_files = [p for c in categories for p in sorted((root / "tests" / "regression" / "tests").glob(f"REQUEST-{c}-*/*.yaml"))]
    for path in test_files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rule_id = str(doc.get("rule_id") or path.stem)
        if rule_id != path.stem and path.stem.isdigit() and int(path.stem) in by_id and not (
                rule_id.isdigit() and int(rule_id) in by_id):
            mismatched.append({"file": path.name, "rule_id": rule_id})  # mis. 933200.yaml berisi rule_id 9331200
            rule_id = path.stem
        rule = by_id.get(int(rule_id)) if rule_id.isdigit() else None
        if rule is None or rule.paranoia > max_pl:
            continue
        if any(link.operator in excluded_operators for link in rule.links):
            stats["skip_excluded_operator"] += len(doc["tests"])
            continue
        if not all(is_applicable(link) for link in rule.links):
            stats["skip_rule_not_applicable"] += len(doc["tests"])
            continue
        for link in rule.links:
            if link.operator == "rx":
                compile_pcre(link.argument)
        for test in doc["tests"]:
            for stage in test["stages"]:
                stage = stage.get("stage", stage)
                inp, out = stage.get("input") or {}, stage.get("output") or {}
                expect = _expected(rule.id, out)
                if expect is None:
                    continue
                if inp.get("data") or inp.get("encoded_request") or inp.get("raw_request"):
                    stats["skip_body_or_raw_request"] += 1
                    continue
                headers = {str(k): str(v) for k, v in (inp.get("headers") or {}).items()}
                if any(k.lower() not in LOGGED | IGNORED_HEADERS for k in headers):
                    stats["skip_unlogged_header"] += 1
                    continue
                req = Request(str(inp.get("method", "GET")), to_bytes_str(str(inp.get("uri", "/"))),
                              str(inp.get("version", "HTTP/1.1")),
                              {k: to_bytes_str(v) for k, v in headers.items() if k.lower() in LOGGED})
                coll = collections(req)
                got = evaluator.evaluate(rule, coll, evaluator.active_removals(coll)) is not None
                stats["tested"] += 1
                stats["agree" if got == expect else "disagree"] += 1
                per_rule.setdefault(rule.id, [0, 0])[got == expect] += 1
                if got != expect:
                    disagreements.append({"rule": rule.id, "test_id": test.get("test_id"), "expected_match": expect,
                                          "uri": str(inp.get("uri"))[:200]})
    candidates = [r for r in rules if r.paranoia <= max_pl and not any(link.operator in excluded_operators for link in r.links)
                  and all(is_applicable(link) for link in r.links)]
    return {"stats": dict(stats), "rules_tested": len(per_rule), "disagreements": disagreements,
            "tests_per_rule": {str(k): sum(v) for k, v in sorted(per_rule.items())},
            "rules_without_runnable_tests": sorted(str(r.id) for r in candidates if r.id not in per_rule),
            "test_rule_id_mismatch": mismatched}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cocokkan emulasi CRS dengan uji regresi resmi CRS")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    args = parser.parse_args(argv)
    config = load_config(args.config.resolve())
    name = config.get("name", "regex")
    crs = config["crs"]
    root = ensure_crs(crs["version"], crs["url"], crs["sha256"])
    categories = available_categories(root / "rules") if crs["categories"] == "all" else [str(c) for c in crs["categories"]]
    result = verify(root, categories, set(crs["excluded_operators"]), unicode_map=engine_unicode_map(config),
                    keep=lambda rule: mapped_class(rule, config) is not None)
    info = run_info("crs_regression", None, config_file=str(args.config), engine=config["engine"],
                    crs_version=crs["version"], crs_sha256=crs["sha256"], rules_dir_sha256=tree_digest(root / "rules"),
                    **result)
    out = ROOT / "results" / ("crs_regression.json" if name == "regex" else f"crs_regression_{name}.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    s = result["stats"]
    print(f"[verify-crs] {name}, CRS {crs['version']}: {s.get('agree', 0)}/{s.get('tested', 0)} uji cocok "
          f"({result['rules_tested']} aturan, semua PL); dilewati: "
          f"{ {k: v for k, v in s.items() if k.startswith('skip')} } -> {out.relative_to(ROOT)}")
    return 0 if not result["disagreements"] else 1


if __name__ == "__main__":
    sys.exit(main())
