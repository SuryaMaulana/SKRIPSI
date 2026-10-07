import pytest
import io
import tarfile

import pytest

from src.baselines.crs import (Target, _matches_archive, ensure_unicode_mapping, load_data_file, load_rules,
                               logical_lines, parse_actions, parse_operator, parse_pm_content, parse_targets,
                               pm_phrases, sha256_file, split_words, tree_digest)

CONF = r'''
# komentar
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,skipAfter:END-942"
SecRule REQUEST_FILENAME "!@validateByteRange 45-47,97-122" \
    "id:942010,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=perf;REQUEST_FILENAME"
SecRule ARGS|!ARGS:skip|&REQUEST_HEADERS "@rx (?i)union\s+select\x5c\\" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'SQL Injection, contoh: a,b',\
    tag:'paranoia-level/1',\
    tag:'perf',\
    severity:'CRITICAL',\
    multiMatch,\
    chain"
    SecRule MATCHED_VARS "!@pmFromFile words.data" "t:none"
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942013,phase:2,pass,nolog,skipAfter:END-942"
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto" "id:942200,phase:1,block,tag:'paranoia-level/2',severity:'WARNING'"
SecMarker "END-942"
'''


def test_split_words_follows_apache_quoting():
    assert split_words(r'SecRule ARGS "@rx a\"b\\c\x5c" "id:1"') == ["SecRule", "ARGS", '@rx a"b\\c\\x5c', "id:1"]


def test_logical_lines_join_continuations_and_drop_comments():
    lines = logical_lines(CONF)
    assert not any(line.startswith("#") for line in lines)
    assert any("id:942100" in line and "chain" in line for line in lines)


def test_parse_actions_keeps_commas_inside_quotes():
    acts = parse_actions("id:1, msg:'a, b', t:none,t:lowercase,chain, tag:'it\\'s'")
    assert acts == [("id", "1"), ("msg", "a, b"), ("t", "none"), ("t", "lowercase"), ("chain", None), ("tag", "it's")]


def test_parse_targets_and_operator():
    targets = parse_targets("ARGS|!REQUEST_COOKIES:/__utm/|&ARGS|REQUEST_HEADERS:User-Agent")
    assert targets == (Target("ARGS"), Target("REQUEST_COOKIES", "__utm", True, exclude=True), Target("ARGS", count=True),
                       Target("REQUEST_HEADERS", "User-Agent"))
    assert parse_operator("!@pmFromFile a.data") == ("pmFromFile", "a.data", True)
    assert parse_operator("^foo$") == ("rx", "^foo$", False)


def test_load_rules_reads_pl_phase_chain_and_target_removals(tmp_path):
    (tmp_path / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf").write_text(CONF, encoding="utf-8")
    (tmp_path / "words.data").write_text("# c\nfoo\n\nbar\n", encoding="utf-8")
    rules, report = load_rules(tmp_path, ["942"])
    assert [r.id for r in rules] == [942100, 942200]
    r = rules[0]
    assert (r.paranoia, r.phase, r.severity, r.category, r.msg) == (1, 2, "CRITICAL", "942", "SQL Injection, contoh: a,b")
    assert len(r.links) == 2 and r.links[0].transforms == ("urlDecodeUni", "lowercase")
    assert r.links[0].multi_match and r.links[0].capture and r.links[0].argument == "(?i)union\\s+select\\x5c\\"
    assert r.links[1].negated and r.links[1].operator == "pmFromFile" and r.links[1].targets == (Target("MATCHED_VARS"),)
    assert rules[1].paranoia == 2 and report.pl_tag_mismatch == []
    (removal,) = report.removals
    assert (removal.rule_id, removal.by, removal.selector, removal.target) == (942010, "tag", "perf", Target("REQUEST_FILENAME"))
    assert removal.phase == 1  # kondisi ctl dievaluasi dengan variabel fase aturan kontrolnya
    assert load_data_file(tmp_path, "words.data") == ["foo", "bar"]


def test_pm_parameters_follow_parse_pm_content_of_modsecurity():
    assert parse_pm_content('"a\\"b c"') == 'a"b c'  # kutip pembungkus dibuang, \" -> "
    assert parse_pm_content("|41 42|C") == "ABC"  # |heksa| -> byte, spasi di dalamnya diabaikan
    assert parse_pm_content("|4|x|1|") == "xA"  # digit heksa yang tertunda tidak di-reset oleh '|'
    assert parse_pm_content("a|b|c") == "acb|c"  # tanpa konversi: hasil in-place C mempertahankan panjang asli
    assert parse_pm_content("C:\\Windows") is None and parse_pm_content("  ") is None  # escape tak dikenal / kosong
    assert pm_phrases("foo |41|bar  baz") == ["foo", "Abar", "baz"]
    assert pm_phrases("x|00|y z") == ["x"]  # apr_pstrdup memotong di NUL


def test_data_file_phrases_follow_pmfromfile_param_init(tmp_path):
    (tmp_path / "w.data").write_bytes(b'x\nab\n  cd  \r\n#c\n  # d\n|41 42|\nC:\\dir\n"q"\na\x0cb\n\xe9t\xe9\n"last"')
    # frasa satu karakter dilewati (awal == akhir), \f bukan pemisah baris, kutip hanya dibuang bila baris diakhiri '"'
    assert load_data_file(tmp_path, "w.data") == ["ab", "cd", "AB", "C:\\dir", '"q"', "a\x0cb", "\xe9t\xe9", "last"]


def test_extracted_tree_is_checked_against_the_archive(tmp_path):
    archive = tmp_path / "crs.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        data = b"SecRule ARGS \"@rx x\" \"id:1\"\n"
        info = tarfile.TarInfo("coreruleset-x/rules/a.conf")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    root = tmp_path / "coreruleset-x"
    (root / "rules").mkdir(parents=True)
    (root / "rules" / "a.conf").write_bytes(b'SecRule ARGS "@rx x" "id:1"\n')
    before = tree_digest(root / "rules")
    assert _matches_archive(archive, root)
    (root / "rules" / "a.conf").write_bytes(b'SecRule ARGS "@rx y" "id:1"\n')  # aturan diubah setelah ekstraksi
    assert not _matches_archive(archive, root) and tree_digest(root / "rules") != before


def test_unicode_mapping_is_verified_against_the_pinned_sha256(tmp_path):
    (tmp_path / "unicode.mapping").write_bytes(b"20127 (US-ASCII)\r\n2039:3c\r\n")  # sudah ada: tidak diunduh ulang
    url, digest = "https://invalid.example/unicode.mapping", sha256_file(tmp_path / "unicode.mapping")
    assert ensure_unicode_mapping(url, digest, tmp_path) == tmp_path / "unicode.mapping"
    with pytest.raises(RuntimeError):
        ensure_unicode_mapping(url, "0" * 64, tmp_path)


@pytest.mark.slow
def test_pm_phrases_match_the_harness_raw_line_handling():
    """Harness pm_main.c memakai baris mentah tanpa parse_pm_content. Untuk berkas .data yang dipakai aturan PL1,
    frasa hasil load_data_file (dengan parse_pm_content) harus sama dengan penanganan baris mentah itu."""
    from src.baselines.crs import ensure_crs
    from src.baselines.regex_baseline import build_ruleset, load_config
    config = load_config()
    crs = config["crs"]
    rules_dir = ensure_crs(crs["version"], crs["url"], crs["sha256"]) / "rules"
    used = {f for r in build_ruleset(config).rules for link in r.links if link.operator == "pmFromFile"
            for f in link.argument.split()}
    assert used
    space = " \t\n\v\f\r"
    for name in sorted(used):
        raw = []
        for line in (rules_dir / name).read_bytes().decode("latin-1").splitlines():
            line = line.strip(space)
            if len(line) > 1 and not line.startswith("#"):
                raw.append(line)
        assert load_data_file(rules_dir, name) == raw, name
