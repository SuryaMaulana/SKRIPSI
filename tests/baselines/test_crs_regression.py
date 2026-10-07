import pytest

from src.baselines import modsec as m
from src.baselines.crs import ensure_crs
from src.baselines.crs_regression import verify
from src.baselines.regex_baseline import build_ruleset, engine_unicode_map, load_config


@pytest.mark.slow
def test_emulation_agrees_with_every_applicable_official_crs_regression_test():
    config = load_config()
    crs = config["crs"]
    root = ensure_crs(crs["version"], crs["url"], crs["sha256"])  # unduh sekali ke data/external/crs/
    result = verify(root, [str(c) for c in crs["categories"]], set(crs["excluded_operators"]),
                    unicode_map=engine_unicode_map(config))
    assert result["stats"]["tested"] > 900
    assert result["disagreements"] == []


@pytest.fixture(scope="module")
def ruleset():
    return build_ruleset(load_config())


@pytest.mark.slow
@pytest.mark.parametrize("target, hits, misses", [
    # temuan reviewer pada mesin acuan ModSecurity 2.9.15 + Apache 2.4 (aturan CRS 4.30.0 PL1 asli)
    ("/%2ehtaccess", {930130}, set()),
    ("/%252ehtaccess", set(), {930130}),  # 930130 fase 1 melihat path mentah: urlDecodeUni hanya men-decode sekali
    ("/document%2ecookie", {941180}, set()),  # 941010 (fase 1) melihat '%', aturan fase 2 melihat "/document.cookie"
    ("/document.cookie", set(), {941180}),  # 941010 menghapus REQUEST_FILENAME dari aturan 941
    ("/%3Cscript%3E/../index.php", {930100}, {941110, 941160}),  # fase 2: path ternormalisasi "/index.php"
    ("/config/parameters.yml", {930130}, set()),
    ("/app/config/parameters.yml", set(), {930130}),  # tautan gagal satu langkah acmp.c
    ("/search?q=%00%3Cscript%3Ex%3C/script%3E", set(), {941110, 941160}),  # utf8toUnicode memotong di NUL
    ("/?id=%u2039script%u203ax%u2039/script%u203a", {941110, 941160}, set()),  # unicode.mapping 20127
    ("/search?q=alert%26lpar%3Bdocument%26period%3Bcookie%26rpar%3B", {941180, 941390}, set()),  # entitas 2.9.15
])
def test_reviewer_examples_on_the_pinned_crs_rules(ruleset, target, hits, misses):
    coll = m.collections(m.Request("GET", target, "HTTP/1.1", {"User-Agent": "Mozilla/5.0"}))
    removals = ruleset.evaluator.active_removals(coll)
    found = {r.id for r in ruleset.rules if ruleset.evaluator.evaluate(r, coll, removals)}
    assert hits <= found and not misses & found, found
