import ast
from pathlib import Path

from src.baselines import bas_seyyar, regex_baseline as rb
from src.baselines.crs import Link, Rule, Target
from src.baselines.modsec import Evaluator

BASELINE_DIR = Path(__file__).resolve().parents[2] / "src" / "baselines"
CONFIG = {
    "crs": {"version": "test"},
    "scoring": {"severity_points": {"CRITICAL": 5, "WARNING": 3}, "tie_break": ["CMD_INJECTION", "SQLI", "XSS", "PATH_TRAVERSAL", "WEB_SCANNING"]},
    "class_map": {"930": "PATH_TRAVERSAL", "932": "CMD_INJECTION", "942": "SQLI", "913": "WEB_SCANNING", "bas_seyyar": "WEB_SCANNING"},
    "restricted_files": {"rules": [930130], "traversal_rules": [930100, 930110], "class_without_traversal": "WEB_SCANNING"},
    "bas_seyyar": {"phase1_crs_categories": ["941", "942"], "dedup_with_crs": {"BS-UA": 913100},
                   "rules": [{"id": "BS-UA", "field": "user_agent", "match": "contains_any", "values": ["nikto"], "points": 3}]},
}


def _row(request: str, ua: str = "Mozilla/5.0", referer: str = "") -> dict:
    method, target = request.split(" ", 1)
    path, _, query = target.partition("?")
    return {"id": "x", "raw_log_masked": f'1.2.3.4 - - [01/Jan/2020:00:00:00 +0000] "{request} HTTP/1.1" 200 1 "-" "{ua}"',
            "method": method, "path": path, "query": query, "status": 200, "user_agent": ua, "referer": referer}


def _rule(rule_id, operator, argument, targets=("ARGS",), severity="CRITICAL"):
    link = Link(tuple(Target(t) for t in targets), operator, argument, False, ("urlDecodeUni",), False, False)
    return Rule(rule_id, "f.conf", str(rule_id)[:3], 1, severity, "", (link,), 2, ())


def _ruleset(*rules):
    return rb.RuleSet(list(rules), Evaluator({}), {})


def test_baselines_never_import_the_evidence_gate():
    for path in BASELINE_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            assert not any("gate" in n.split(".") for n in names), f"{path.name} mengimpor modul gerbang bukti"


def test_request_from_row_keeps_raw_target_and_logged_headers():
    req = rb.request_from_row(_row("GET /a%20b?x=%27&y", ua="sqlmap/1.0", referer="-"))
    assert (req.method, req.target, req.protocol) == ("GET", "/a%20b?x=%27&y", "HTTP/1.1")
    assert req.headers == {"User-Agent": "sqlmap/1.0"}


def test_restricted_file_without_traversal_maps_to_web_scanning():
    restricted, os_file = _rule(930130, "rx", "x"), _rule(930120, "rx", "x")
    assert rb.rule_class(restricted, {930130}, CONFIG) == "WEB_SCANNING"
    assert rb.rule_class(restricted, {930130, 930110}, CONFIG) == "PATH_TRAVERSAL"
    assert rb.rule_class(os_file, {930120}, CONFIG) == "PATH_TRAVERSAL"


def test_rule_class_map_overrides_category_and_unmapped_rules_are_ignored():
    config = {**CONFIG, "rule_class_map": {"920440": "WEB_SCANNING"}}
    assert rb.mapped_class(_rule(920440, "rx", "x"), config) == "WEB_SCANNING"
    assert rb.mapped_class(_rule(920270, "rx", "x"), config) is None  # kategori 920 lain: tanpa padanan kelas
    assert rb.mapped_class(_rule(942100, "rx", "x"), config) == "SQLI"


def test_child_config_inherits_and_overrides(tmp_path, monkeypatch):
    (tmp_path / "parent.yaml").write_text("a: {x: 1, y: 2}\nb: [1]\nname: p\n", encoding="utf-8")
    (tmp_path / "child.yaml").write_text("inherits: parent.yaml\na: {y: 3}\nname: c\n", encoding="utf-8")
    monkeypatch.setattr(rb, "ROOT", tmp_path)
    assert rb.load_config(tmp_path / "child.yaml") == {"a": {"x": 1, "y": 3}, "b": [1], "name": "c"}


def test_classify_sums_points_per_class_and_breaks_ties_by_priority():
    rules = _ruleset(_rule(942001, "rx", "(?i)union"), _rule(942002, "rx", "(?i)select"), _rule(932001, "rx", "(?i)sleep"))
    out = rb.classify(_row("GET /p?q=1%20union%20select%20sleep(1)"), rules, CONFIG)
    assert out["scores"]["SQLI"] == 10 and out["scores"]["CMD_INJECTION"] == 5 and out["label"] == "SQLI"
    tie = rb.classify(_row("GET /p?q=union%20sleep"), rules, CONFIG)
    assert tie["scores"]["SQLI"] == tie["scores"]["CMD_INJECTION"] == 5 and tie["label"] == "CMD_INJECTION"
    assert {h["rule"] for h in tie["matched_rules"]} == {"942001", "932001"}


def test_classify_normal_without_hits_and_counts_bas_seyyar_rules():
    rules = _ruleset(_rule(942001, "rx", "(?i)union"))
    assert rb.classify(_row("GET /index.php?p=1"), rules, CONFIG) | {"matched_rules": []} == {
        "id": "x", "label": "NORMAL", "scores": dict.fromkeys(rb.ATTACK_CLASSES, 0), "matched_rules": []}
    scan = rb.classify(_row("GET /index.php", ua="Mozilla/5.00 (Nikto/2.1.6)"), rules, CONFIG)
    assert scan["label"] == "WEB_SCANNING" and scan["scores"]["WEB_SCANNING"] == 3
    assert scan["matched_rules"][0]["source"].startswith("Baş Seyyar")


def test_bas_seyyar_field_values_and_match_kinds():
    row = _row("PROPFIND /a%2Ebak?x=%3C", ua="-")
    assert bas_seyyar.field_value(row, "path") == "/a.bak" and bas_seyyar.field_value(row, "uri") == "/a.bak?x=<"
    assert bas_seyyar.field_value(row, "user_agent") == ""
    rules = [{"id": "M", "field": "method", "match": "equals_any", "values": ["propfind"], "points": 2},
             {"id": "E", "field": "path", "match": "endswith_any", "values": [".BAK"], "points": 2},
             {"id": "R", "field": "uri", "match": "regex", "pattern": r"x=<", "points": 2}]
    for rule in rules:
        assert bas_seyyar.rule_match(row, rule) is not None
    assert [h["rule"] for h in bas_seyyar.evaluate(row, {"rules": rules})] == ["M"]  # rantai if/else: berhenti di hit pertama


def test_bas_seyyar_whitelist_stops_the_chain():
    bot = {"id": "BOT", "action": "whitelist", "all": [
        {"field": "path", "match": "equals_any", "values": ["/robots.txt"]},
        {"field": "user_agent", "match": "contains_any", "values": ["bot"]},
        {"field": "referer", "match": "is_empty"},
        {"field": "status", "match": "equals_any", "values": ["400", "404"]}]}
    scan = {"id": "UA", "field": "user_agent", "match": "contains_any", "values": ["bot"], "points": 5}
    row = _row("GET /robots.txt", ua="Googlebot/2.1") | {"status": 404}
    assert bas_seyyar.evaluate(row, {"rules": [bot, scan]}) == []
    assert [h["rule"] for h in bas_seyyar.evaluate(row | {"status": 200}, {"rules": [bot, scan]})] == ["UA"]


def test_scanner_rules_yield_to_xss_sqli_and_count_ua_evidence_once():
    sqli = _rule(942001, "rx", "(?i)union")
    ua = _rule(913100, "pm", "nikto", targets=("REQUEST_HEADERS",))
    out = rb.classify(_row("GET /p?q=union", ua="Nikto/2.1"), _ruleset(sqli, ua), CONFIG)
    assert out["label"] == "SQLI" and not any(h["source"].startswith("Baş") for h in out["matched_rules"])
    scan = rb.classify(_row("GET /p", ua="Nikto/2.1"), _ruleset(sqli, ua), CONFIG)
    bs = [h for h in scan["matched_rules"] if h["rule"] == "BS-UA"]
    assert scan["scores"]["WEB_SCANNING"] == 5 and bs[0]["points"] == 0 and "913100" in bs[0]["note"]
