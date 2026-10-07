import pytest

from src.baselines import modsec as m
from src.baselines.crs import Link, Rule, Target, TargetRemoval

# potongan unicode.mapping bergaya berkas asli: hanya bagian codepage 20127 yang dimuat (bagian 20261 sesudahnya tidak)
MAPPING = ("1252 (ANSI - Latin I)\r\n2039:3f\r\n\r\n20127 (US-ASCII)\r\n2039:3c 203a:3e\r\n\r\n"
           "20261 (T.61)\r\nff1c:21\r\n")


@pytest.mark.parametrize("fn, given, expected", [
    (m.t_url_decode_uni, "a%27b+c%zz%4", "a'b c%zz%4"),
    (m.t_url_decode_uni, "%u0027%uFF1C%u12", "'<%u12"),  # tanpa unicode map: %uFF1C (< lebar penuh) -> '<'
    (m.t_url_decode, "%2541+", "%41 "),
    (m.t_html_entity_decode, "&lt;a&#x3C;&#60&quot&foo;&#;", '<a<<"&foo;&#;'),
    (m.t_html_entity_decode, "&#1000;", chr(1000 & 0xFF)),
    # 2.9.15: 44 entitas bernama, tanpa membedakan huruf besar/kecil; strtol jenuh di LONG_MAX -> byte 0xFF
    (m.t_html_entity_decode, "alert&lpar;1&rpar;&NewLine;&Colon;&ltx;", "alert(1)\n:&ltx;"),
    (m.t_html_entity_decode, "&#99999999999999999999;", "\xff"),
    (m.t_js_decode, "\\x3c\\u003c\\uff1c\\074\\n\\q", "<<<<\nq"),
    (m.t_css_decode, "\\3c \\00003c\\ff1c\\a", "<<<\n"),
    (m.t_cmd_line, "C^A\"T  /ETC,PASSWD;x", "cat/etc passwd x"),
    (m.t_replace_comments, "a/*x*/b/*y", "a b "),
    (m.t_remove_comments_char, "a/*b*/c--d#e<!--f-->", "abcdef"),
    (m.t_compress_whitespace, "a \t\n\xa0b", "a b"),
    (m.t_remove_whitespace, "a \tb\xa0c", "abc"),
    (m.t_escape_seq_decode, r"\x41\101\n\z", "AA\nz"),
    (m.t_utf8_to_unicode, "é".encode("utf-8").decode("latin-1") + "a", "%u00e9a"),
    # utf8toUnicode 2.9.15: hasil dipotong strlen di NUL; NUL + byte >= 0x80 -> %u00XX; >= U+10000 hanya 4 digit heksa
    (m.t_utf8_to_unicode, "\x00<script>", ""),
    (m.t_utf8_to_unicode, "\x00\xe9", "%u00e9"),
    (m.t_utf8_to_unicode, "\xf0\x9f\x98\x80", "%u1f60"),
    (m.t_lowercase, "ABC\xc0", "abc\xc0"),
])
def test_transformations_follow_modsecurity_v2(fn, given, expected):
    assert fn(given) == expected


@pytest.mark.parametrize("given, win, expected, changed", [
    ("/a/b/../c", False, "/a/c", True), ("//a/./b", False, "/a/b", True),
    ("/../../etc/passwd", False, "/etc/passwd", True),
    ("a/../../b", False, "../b", True), ("/a/b/", False, "/a/b/", False), ("/..", False, "", False),
    ("/a/..", False, "", False),  # referensi balik di ujung masukan tidak menyalakan changed (seperti C)
    ("..\\..\\windows\\win.ini", True, "../../windows/win.ini", True), ("/a\\..\\b", True, "/b", True),
])
def test_normalize_path(given, win, expected, changed):
    assert m.normalize_path(given, win) == (expected, changed)


def test_unicode_map_follows_msc_unicode_and_url_decode_uni_uses_it():
    table = m.load_unicode_map(MAPPING, 20127)
    assert (table[0x2039], table[0x203A], table[0xFF1C], table[0x0041]) == (0x3C, 0x3E, -1, -1)
    assert table[0x3002] == table[0xFF61] == table[0xFF0E] == table[0x002E] == 0x2E  # entri '.' bawaan
    assert m.t_url_decode_uni("%u2039script%u203a%u3002", table) == "<script>."
    assert m.t_url_decode_uni("%u2039script%u203a%u3002") == "9script:\x02"  # tanpa peta: byte rendah saja
    assert m.t_url_decode_uni("%uFF1C", table) == "<"  # tidak dipetakan: kembali ke byte rendah + lebar penuh


def test_transform_steps_follow_the_c_buffer_and_changed_flags():
    # removeNulls tidak menulis NUL penutup; cmdLine membaca buffer sampai NUL sehingga ikut membaca sisa byte lama
    assert m.transform_steps("a\x00b", ("removeNulls", "cmdLine")) == [("ab", True), ("abb", True)]
    assert m.transform_steps("a\tb", ("compressWhitespace",)) == [("a b", False)]  # satu spasi: changed tetap 0
    assert m.utf8_to_unicode("ab\xc3", tail="\xa9") == ("ab%u00e9", True)  # byte lanjutan dibaca dari sisa buffer


def test_translate_pcre_handles_constructs_python_lacks():
    assert m.translate_pcre(r"\x{bc}[[:digit:]]a$") == r"\xbc[0-9]a\Z"
    assert m.translate_pcre(r"(?<n>x)\h\z") == r"(?P<n>x)[\t \xa0]\Z"
    assert m.compile_pcre(r"(?i)a$").search("A\n") is None  # PCRE_DOLLAR_ENDONLY
    assert m.compile_pcre(r"\w").search("\xe9") is None  # \w hanya ASCII seperti PCRE non-UTF
    # karakter non-ASCII literal di pola = byte UTF-8-nya (PCRE non-UTF), mis. kelas [´] berisi byte C2 dan B4
    assert m.compile_pcre("[´]").fullmatch("\xc2") and m.compile_pcre("[´]").fullmatch("\xb4")


def test_query_args_and_collections_per_phase():
    # Dulu REQUEST_FILENAME di-URL-decode untuk semua fase dan URI absolut tanpa path diberi "/". ModSecurity v2 di
    # Apache membaca r->parsed_uri.path saat aturan berjalan: mentah di fase 1, sudah dinormalisasi/di-decode di fase 2,
    # dan NULL (variabel tidak ada) bila request-target tidak punya path.
    assert m.parse_query_args("a=1+2&b&=c&d=%27") == [("a", "1 2"), ("b", ""), ("", "c"), ("d", "'")]
    coll = m.collections(m.Request("GET", "/x/%3Cy%3E.php?q=%27#frag", "HTTP/1.1", {"User-Agent": "UA"}))
    assert coll[1]["REQUEST_FILENAME"] == [("REQUEST_FILENAME", "/x/%3Cy%3E.php")]
    assert coll[2]["REQUEST_FILENAME"] == [("REQUEST_FILENAME", "/x/<y>.php")]
    assert coll[1]["REQUEST_URI"] == [("REQUEST_URI", "/x/%3Cy%3E.php?q=%27")]
    assert coll[2]["REQUEST_URI"] == [("REQUEST_URI", "/x/<y>.php?q=%27")]
    for phase in (1, 2):
        assert coll[phase]["REQUEST_URI_RAW"] == [("REQUEST_URI_RAW", "/x/%3Cy%3E.php?q=%27#frag")]
        assert coll[phase]["ARGS"] == [("q", "'")] and coll[phase]["QUERY_STRING"] == [("QUERY_STRING", "q=%27")]
        assert coll[phase]["REQUEST_HEADERS"] == [("User-Agent", "UA")]
    absolute = m.collections(m.Request("GET", "http://h?id=1#f", "HTTP/1.1", {}))  # otoritas berakhir di '?'
    for phase in (1, 2):
        assert absolute[phase]["REQUEST_FILENAME"] == [] and absolute[phase]["REQUEST_BASENAME"] == []
        assert absolute[phase]["REQUEST_URI"] == [("REQUEST_URI", "")]  # apr_pstrcat(NULL, "?", query) = ""
        assert absolute[phase]["ARGS"] == [("id", "1")]


@pytest.mark.parametrize("target, phase1, phase2, basename2", [
    # %25 bukan karakter unreserved: hanya di-decode sekali (ap_unescape_url_ex) di fase 2
    ("/%252ehtaccess", "/%252ehtaccess", "/%2ehtaccess", "%2ehtaccess"),
    ("/document%2ecookie", "/document%2ecookie", "/document.cookie", "document.cookie"),
    ("/%3Cscript%3E/../index.php", "/%3Cscript%3E/../index.php", "/index.php", "index.php"),
    ("/app/config/parameters.yml", "/app/config/parameters.yml", "/app/config/parameters.yml", "parameters.yml"),
    ("/?q=%00<script>", "/", "/", ""),
    ("//etc/./passwd", "/etc/./passwd", "/etc/passwd", "passwd"),  # ap_parse_uri menciutkan // di awal
    ("/a/%2e%2E/b//c", "/a/%2e%2E/b//c", "/b/c", "c"),
    ("/a/b/..%2f..%2fetc", "/a/b/..%2f..%2fetc", "/a/b/../../etc", "etc"),  # %2F di-decode setelah normalisasi (404)
    ("/x%2fy%00z", "/x%2fy%00z", "/x/y", "y"),  # %00 memotong string C
    ("/%41%2541", "/%41%2541", "/A%41", "A%41"),
    ("/..%5c..%5cwin.ini", "/..%5c..%5cwin.ini", "/..\\..\\win.ini", "win.ini"),  # file_basename juga memotong di '\'
])
def test_request_filename_per_phase_follows_apache(target, phase1, phase2, basename2):
    coll = m.collections(m.Request("GET", target, "HTTP/1.1", {}))
    assert coll[1]["REQUEST_FILENAME"] == [("REQUEST_FILENAME", phase1)]
    assert coll[2]["REQUEST_FILENAME"] == [("REQUEST_FILENAME", phase2)]
    assert coll[2]["REQUEST_BASENAME"] == [("REQUEST_BASENAME", basename2)]


@pytest.mark.parametrize("method, target, expected", [
    ("GET", "/a?b#c", ("/a", "b")),
    ("GET", "///a", ("/a", None)),
    ("GET", "http://h", (None, None)),
    ("GET", "http://u:p@h:80/p?q", ("/p", "q")),
    ("GET", "HTTP://[::1]:8080/x", ("/x", None)),
    ("OPTIONS", "*", ("*", None)),
    ("GET", "mailto:x?y", ("x", "y")),
    ("GET", "?x", (None, "x")),
    ("GET", "1a:b/c?x", ("1a:b/c", "x")),  # apr_uri_parse gagal (400, tidak diemulasi): diurai longgar
    ("GET", "http://h:8o/x?y", ("http://h:8o/x", "y")),  # port tidak valid: idem
    ("CONNECT", "h:443", (None, None)),
])
def test_apache_parse_uri(method, target, expected):
    assert m.apache_parse_uri(method, target) == expected


def test_apache_normalize_and_unescape():
    assert m.ap_normalize_path("/a/./b//c/../d") == "/a/b/d"
    assert m.ap_normalize_path("/%41%2e%2F") == "/A.%2F"  # hanya escape karakter unreserved yang di-decode
    assert m.ap_normalize_path("/../x") == m.ap_normalize_path("/.%2e/x") == "/x"
    assert m.ap_normalize_path("*") == "*"
    assert m.ap_unescape_url_ex("/%2541%41%2f%3c%zz") == "/%41%41/<%zz"  # KEEP_UNRESERVED; %2F tetap di-decode
    assert m.apache_phase2_path(None) is None


def _rule(*links, tags=(), rule_id=1, phase=2):
    return Rule(rule_id, "f.conf", "942", 1, "CRITICAL", "", tuple(links), phase, tags)


def _link(targets, op, arg, **kw):
    return Link(tuple(targets), op, arg, kw.get("negated", False), tuple(kw.get("t", ())), kw.get("multi", False),
                kw.get("capture", False))


def test_evaluator_chain_capture_negation_and_phrase_files():
    ev = m.Evaluator({"w.data": ["UNION"]})
    coll = m.collections(m.Request("GET", "/p?id=1%20union%20select&x=ok", "HTTP/1.1", {}))
    chained = _rule(_link([Target("ARGS")], "rx", r"(\w+)\s+select", capture=True),
                    _link([Target("TX", "1")], "pmFromFile", "w.data"))
    hit = ev.evaluate(chained, coll)
    assert hit.variable == "ARGS:id" and hit.data == "union select"
    neg = _rule(_link([Target("ARGS", "x")], "rx", "^[a-z]+$", negated=True))
    assert ev.evaluate(neg, coll) is None
    excluded = _rule(_link([Target("ARGS"), Target("ARGS", "id", exclude=True)], "rx", "union"))
    assert ev.evaluate(excluded, coll) is None


def test_pm_reports_acmp_node_text_and_sets_tx_like_re_operators():
    # acmp.c: tautan gagal satu langkah -> "cq" di dalam "abcq" terlewat; kecocokan lewat o_match melaporkan teks simpul
    assert m.Acmp(["abcz", "bd", "cq"]).find("abcq") is None
    assert m.Acmp(["abcd", "bc"]).find("xabcx") == "abc"
    assert m.Acmp(["Document.Cookie", "document.cookiE"]).find("xDOCUMENT.COOKIEx") == "Document.Cookie"
    ev = m.Evaluator({})
    coll = m.collections(m.Request("GET", "/p?a=1%20b&c=XDOCUMENT.COOKIE", "HTTP/1.1", {}))
    rule = _rule(_link([Target("ARGS", "a")], "rx", r"(\d) (b)", capture=True),
                 _link([Target("ARGS", "c")], "pm", "document.cookie", capture=True),
                 _link([Target("TX", "^[0-9]$", True)], "rx", "."))
    hit = ev.evaluate(rule, coll)
    assert hit is not None and hit.data == "1 b"
    state = m._State()
    ev._link(rule.links[0], coll[2], state)
    ev._link(rule.links[1], coll[2], state)
    assert state.tx == {"0": "document.cookie"}  # TX:0 = frasa; TX:1-9 dari tangkapan sebelumnya dihapus
    assert ev.evaluate(_rule(_link([Target("ARGS", "a")], "pm", "x y", negated=True)),
                       m.collections(m.Request("GET", "/p?a=", "HTTP/1.1", {}))) is not None  # kosong: @pm tidak cocok
    negated = m._State()
    ev._link(_link([Target("ARGS", "a")], "rx", r"(\d)", negated=True, capture=True), coll[2], negated)
    assert negated.tx == {"0": "1", "1": "1"}  # tangkapan diisi operator sebelum negasi diterapkan


def test_multimatch_follows_changed_flags_of_re_c():
    coll = m.collections(m.Request("GET", "/p?a=%253Cscript&b=x%09y", "HTTP/1.1", {}))
    ev = m.Evaluator({})
    rule = _rule(_link([Target("ARGS", "a")], "rx", "%3C", t=["urlDecodeUni"], multi=True))
    single = _rule(_link([Target("ARGS", "a")], "rx", "%3C", t=["urlDecodeUni"]))
    assert ev.evaluate(rule, coll) is not None and ev.evaluate(single, coll) is None
    # compressWhitespace mengganti satu tab tanpa melaporkan perubahan: multiMatch tidak memeriksa "x y" sama sekali
    multi_ws = _rule(_link([Target("ARGS", "b")], "rx", "x y", t=["compressWhitespace"], multi=True))
    single_ws = _rule(_link([Target("ARGS", "b")], "rx", "x y", t=["compressWhitespace"]))
    assert ev.evaluate(multi_ws, coll) is None and ev.evaluate(single_ws, coll) is not None


def test_target_removal_is_decided_with_the_phase_of_the_control_rule():
    # 941010 (fase 1) memeriksa path mentah, aturan 941 (fase 2) memeriksa path yang sudah di-decode
    control = TargetRemoval(941010, _link([Target("REQUEST_FILENAME")], "validateByteRange", "45-47,97-122", negated=True),
                            "tag", "perf", Target("REQUEST_FILENAME"), phase=1)
    ev = m.Evaluator({}, [control])
    rule = _rule(_link([Target("REQUEST_FILENAME")], "pm", "cookie"), tags=("perf",))
    safe = m.collections(m.Request("GET", "/a/document.cookie", "HTTP/1.1", {}))
    unsafe = m.collections(m.Request("GET", "/a/<x>.cookie", "HTTP/1.1", {}))
    encoded = m.collections(m.Request("GET", "/a/document%2ecookie", "HTTP/1.1", {}))  # '%' di fase 1: tidak dihapus
    assert ev.evaluate(rule, safe, ev.active_removals(safe)) is None
    assert ev.evaluate(rule, unsafe, ev.active_removals(unsafe)) is not None
    assert ev.active_removals(encoded) == [] and ev.evaluate(rule, encoded).value == "/a/document.cookie"


def test_reviewer_examples_with_crs_like_rules():
    xss_chain = ["utf8toUnicode", "urlDecodeUni", "htmlEntityDecode", "jsDecode", "cssDecode", "removeNulls"]
    xss = _rule(_link([Target("ARGS")], "rx", r"(?i)<script|alert\(", t=xss_chain))
    restricted = _rule(_link([Target("REQUEST_FILENAME")], "pmFromFile", "restricted-files.data",
                             t=["utf8toUnicode", "urlDecodeUni", "normalizePathWin"]), phase=1)
    # frasa minimal dari restricted-files.data CRS 4.30.0 yang memutus rantai gagal "/app/" (diperiksa dengan acmp.c)
    phrases = [".htaccess", "/config/parameters.yml", "/app/etc/local.xml", "anaconda3/", "perl/bin"]
    ev = m.Evaluator({"restricted-files.data": phrases}, unicode_map=m.load_unicode_map(MAPPING, 20127))

    def hit(rule, target):
        return ev.evaluate(rule, m.collections(m.Request("GET", target, "HTTP/1.1", {}))) is not None

    assert hit(xss, "/s?q=<script>") and not hit(xss, "/s?q=%00<script>")  # utf8toUnicode memotong di NUL
    assert hit(xss, "/s?q=%u2039script%u203a")  # unicode.mapping 20127: U+2039 -> '<'
    assert hit(xss, "/s?q=alert%26lpar%3B1%26rpar%3B")  # &lpar; dikenal htmlEntityDecode 2.9.15
    assert hit(restricted, "/%2ehtaccess") and not hit(restricted, "/%252ehtaccess")  # fase 1: path mentah
    assert hit(restricted, "/config/parameters.yml") and not hit(restricted, "/app/config/parameters.yml")  # acmp


def test_applicability_ignores_unlogged_data():
    assert not m.is_applicable(_link([Target("REQUEST_COOKIES"), Target("XML", "/*")], "rx", "x"))
    assert not m.is_applicable(_link([Target("TX", "x")], "endsWith", "%{request_headers.host}"))
    assert m.is_applicable(_link([Target("REQUEST_HEADERS", "User-Agent")], "rx", "x"))
    assert not m.is_applicable(_link([Target("REQUEST_HEADERS", "X-Filename")], "rx", "x"))


def test_setvar_in_chain_starter_feeds_the_chained_link():
    """Pola CRS 920440: link pertama menangkap ekstensi dan setvar tx.extension, link berantai memeriksa TX:EXTENSION."""
    first = Link((Target("REQUEST_BASENAME"),), "rx", r"\.([^.]+)$", False, ("urlDecodeUni",), False, True,
                 ("tx.extension=.%{tx.1}/",))
    second = Link((Target("TX", "EXTENSION"),), "within", "%{tx.restricted_extensions}", False, ("lowercase",), False,
                  False)
    rule = _rule(first, second, rule_id=920440)
    ev = m.Evaluator({}, tx_defaults={"restricted_extensions": ".bak/ .swp/ .log/"})
    hit = lambda target: ev.evaluate(rule, m.collections(m.Request("GET", target, "HTTP/1.1", {}))) is not None
    assert hit("/x/index.php.BAK") and hit("/blog.log") and not hit("/index.php") and not hit("/noext")


def test_unresolved_macros_expand_to_empty_like_modsecurity():
    rule = _rule(_link([Target("ARGS")], "streq", "%{tx.tidak_ada}", negated=True))
    coll = m.collections(m.Request("GET", "/p?a=x&b=", "HTTP/1.1", {}))
    hit = m.Evaluator({}).evaluate(rule, coll)  # makro kosong: a="x" != "" cocok (negasi), b="" tidak
    assert hit is not None and hit.variable == "ARGS:a"


def test_target_removal_keeps_setvars_of_the_rebuilt_link():
    first = Link((Target("REQUEST_BASENAME"), Target("REQUEST_FILENAME")), "rx", r"\.([^.]+)$", False, (), False, True,
                 ("tx.extension=.%{tx.1}/",))
    second = Link((Target("TX", "EXTENSION"),), "within", "%{tx.restricted_extensions}", False, (), False, False)
    rule = _rule(first, second, rule_id=920440)
    removal = TargetRemoval(1, _link([Target("REQUEST_METHOD")], "rx", "."), "id", "920440", Target("REQUEST_FILENAME"))
    ev = m.Evaluator({}, [removal], tx_defaults={"restricted_extensions": ".bak/"})
    coll = m.collections(m.Request("GET", "/get/foo.bak", "HTTP/1.1", {}))
    assert ev.evaluate(rule, coll, ev.active_removals(coll)) is not None  # setvar tetap jalan meski target dibuang
