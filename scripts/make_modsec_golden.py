"""Vektor emas untuk port ModSecurity 2.9.15 di src/baselines/modsec.py -> tests/fixtures/modsec_v2915_golden.json.

Vektor dihasilkan dengan menjalankan harness C yang dikompilasi dari sumber ModSecurity v2.9.15 (tag v2.9.15, commit
151074a; fungsi C disalin apa adanya, hanya APR yang diganti stub):
  tfns_map  fungsi transformasi re_tfns.c/msc_util.c dengan tabel unicode.mapping 20127; nilai disalin sekali
            (apr_pstrmemdup) lalu rantai transformasi berjalan in-place seperti re.c, dengan bendera changed per
            langkah;
  pm        acmp.c (acmp_create(0), acmp_add_pattern, acmp_process_quick) dengan frasa @pm atau berkas @pmFromFile.
Masukan: kasus tepi tulisan tangan + string byte acak ber-seed. tests/baselines/test_modsec_golden.py memastikan port
Python mereproduksi setiap vektor. escapeSeqDecode, parse_pm_content, dan langkah path Apache tidak ada di harness
sehingga tidak punya vektor emas (diuji dengan kasus tangan yang diturunkan dari kode C).

Sumber harness ada di tools/modsec_harness/ (asal tiap berkas dan lisensinya di README di sana). Jalankan dari akar
proyek (berkas CRS dan unicode.mapping diunduh bila belum ada):
    make golden-check                                               # bangun harness sementara + --check
    .venv/bin/python scripts/make_modsec_golden.py --check HARNESS_DIR  # bandingkan dengan fixture yang ada
    .venv/bin/python scripts/make_modsec_golden.py HARNESS_DIR          # tulis ulang fixture
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.baselines.crs import ensure_crs, ensure_unicode_mapping, load_data_file, load_rules  # noqa: E402
from src.baselines.modsec import Acmp  # noqa: E402
from src.baselines.regex_baseline import load_config  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "modsec_v2915_golden.json"
SEED = 20261007
HARNESS_TFNS = ("lowercase", "urlDecode", "urlDecodeUni", "utf8toUnicode", "htmlEntityDecode", "jsDecode", "cssDecode",
                "removeNulls", "removeWhitespace", "compressWhitespace", "replaceComments", "removeCommentsChar",
                "cmdLine", "normalizePath", "normalizePathWin")
PM_FILES = ("restricted-files.data", "lfi-os-files.data", "unix-shell.data", "scanners-user-agents.data",
            "windows-powershell-commands.data", "ai-critical-artifacts.data")
ENTITY_NAMES = ("amp", "apos", "ast", "bsol", "colon", "comma", "commat", "diacriticalgrave", "dollar", "equals",
                "excl", "grave", "gt", "hat", "lbrace", "lbrack", "lcub", "lowbar", "lpar", "lsqb", "lt", "midast",
                "nbsp", "newline", "nonbreakingspace", "num", "percnt", "period", "plus", "quest", "quot", "rbrace",
                "rbrack", "rcub", "rpar", "rsqb", "semi", "shy", "sol", "tab", "underbar", "verbar", "vert",
                "verticalline")  # 44 entitas msc_html_named_entities 2.9.15

# token per transformasi untuk string acak (str latin-1 = byte)
TOKENS = {
    "lowercase": ["A", "Z", "a", "z", "@", "[", "`", "{", "\xc0", "\xde", "\xff", "\x00"],
    "urlDecode": ["%", "%2", "%20", "%3c", "%3C", "%zz", "%g1", "%00", "%2b", "%%", "+", "a", "%u003c", "\x00", "\xe9"],
    "urlDecodeUni": ["%", "%u", "%U", "%u00", "%u003c", "%U003C", "%uff1c", "%uFF1C", "%uFF0e", "%u2039", "%u203a",
                     "%u3002", "%uff61", "%u002e", "%u0000", "%uffff", "%u12g4", "%uD800", "%u00e9", "%u0130", "%u2215",
                     "%uff0f", "%u2044", "%u02bc", "%u2018", "%20", "%3c", "%00", "%zz", "%2", "+", "a", "/", "\x00"],
    "utf8toUnicode": ["a", "\x00", "\x00\xe9", "\x00a", "\xc3\xa9", "\xc3", "\xc3(", "\xe2\x80\xb9", "\xe2\x80",
                      "\xf0\x9f\x98\x80", "\xf4\x8f\xbf\xbf", "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xed\xa0\x80",
                      "\xc0\x80", "\xc1\xbf", "\xe0\x80\x80", "\xe0\x9f\xbf", "\xf0\x80\x80\x80", "\xf0\x8f\xbf\xbf",
                      "\x80", "\xbf", "\xff", "\xf8\x88\x80\x80\x80", "\xef\xbc\x9c", "%", "<"],
    "htmlEntityDecode": ["&", "&#", "&#x", "&#X", ";", "&lt;", "&LT", "&lpar;", "&Rpar", "&colon;", "&Colon;", "&nbsp",
                         "&NewLine;", "&shy;", "&Tab;", "&verticalline;", "&amp", "&ampx;", "&foo;", "&#60;", "&#x3c;",
                         "&#X3C", "&#999;", "&#99999999999999999999;", "&#xFFFFFFFFFFFFFFFFFFFF;", "&#0;", "&#x100;",
                         "a", "1", "x", "#", "\x00", "\xe9"],
    "jsDecode": ["\\", "\\u", "\\u003c", "\\uff1c", "\\uFF1c", "\\U003c", "\\x", "\\x3c", "\\X3c", "\\0", "\\07",
                 "\\074", "\\377", "\\400", "\\777", "\\8", "\\n", "\\q", "\\\\", "a", "0", "7", "f", "u"],
    "cssDecode": ["\\", "\\3c", "\\3c ", "\\00003c", "\\0003c", "\\ff1c", "\\0ff1c", "\\00ff1c", "\\1ff1c", "\\FF1C",
                  "\\a", "\\\n", "\\g", "\\1234567", " ", "\t", "\n", "a", "f", "0"],
    "removeNulls": ["\x00", "a", "\x00\x00", " "],
    "removeWhitespace": [" ", "\t", "\n", "\v", "\f", "\r", "\xa0", "a", "\x00"],
    "compressWhitespace": [" ", "\t", "\n", "\v", "\f", "\r", "\xa0", "a", "\x00"],
    "replaceComments": ["/*", "*/", "/", "*", "a", " ", "/**/", "\x00"],
    "removeCommentsChar": ["/*", "*/", "<!--", "-->", "--", "-", "#", "<!-", "a", "<", "/", "*"],
    "cmdLine": ["\"", "'", "\\", "^", " ", ",", ";", "\t", "\r", "\n", "/", "(", "A", "b", "C", "\x00", "cat",
                "/ETC/passwd", "\xc9"],
    "normalizePath": ["/", "\\", ".", "..", "a", "b", "//", "./", "../", "/./", "/../", "\\..\\", "...", "\x00"],
}
TOKENS["normalizePathWin"] = TOKENS["normalizePath"]
CHAIN_TOKENS = sorted({t for tokens in TOKENS.values() for t in tokens} | {"%00", "..%2f", "%c0%ae", "<script>", "'"})
EDGE = {
    "urlDecodeUni": ["%u2039script%u203a", "%uFF1Cscript%uFF1E", "%u0027%uFF1C%u12", "..%u2215..%u2215etc", "%u",
                     "%u0", "%u00", "%u004", "%%u0041", "%U0041", "%u00zz", "a+b%2B", "%2"],
    "utf8toUnicode": ["\x00<script>", "\x00\xe9", "a\x00", "\x00", "a\xc3", "ab\xc3", "\xc3\xa9", "\xf0\x9f\x98\x80",
                      "\xf4\x8f\xbf\xbf", "\xc3\xa9\x00\xa9"],
    "htmlEntityDecode": ["alert&lpar;1&rpar;", "javascript&colon;alert(1)", "&lt;a&#x3C;&#60&quot&foo;&#;", "&#1000;",
                         "&", "&#", "&#x", "&#x;", "&#;", "&amp", "&AMP;", "&quot&quot;", "&nbsp;&NonBreakingSpace;"],
    "normalizePath": ["/a/b/../c", "//a/./b", "/../../etc/passwd", "a/../../b", "/a/b/", "/..", "/a/..", "./", ".",
                      "..", "../x", "a/./b/.", "/a//b///c"],
    "normalizePathWin": ["..\\..\\windows\\win.ini", "/a\\..\\b", "\\\\a\\.\\b", "c:\\x\\..\\..\\y"],
    "cmdLine": ["C^A\"T  /ETC,PASSWD;x", "a\x00b", "  (a) , / x"],
}


def run(cmd: list[str], lines: list[str]) -> list[bytes]:
    out = subprocess.run(cmd, input="".join(lines).encode("latin-1"), capture_output=True, check=True).stdout
    result = out.split(b"\n")[:-1]
    assert len(result) == len(lines), (cmd, len(result), len(lines))
    return result


def tfns_vectors(harness: Path, mapping: Path, chains: list[tuple[str, ...]], inputs: list[str]) -> list[list]:
    """[masukan heksa, [[changed, keluaran heksa], ...]] per (rantai, masukan)."""
    lines = [f"{','.join(chain)} {value.encode('latin-1').hex()}\n" for chain, value in zip(chains, inputs)]
    vectors = []
    for line in run([str(harness / "tfns_map"), str(mapping)], lines):
        parts = line.decode("ascii").split(" ")
        assert parts[0].startswith("0:") and "ERR" not in parts
        vectors.append([parts[0][2:], [[int(p.split(":")[0]), p.split(":")[1]] for p in parts[1:]]])
    return vectors


def pm_vectors(harness: Path, mode: str, arg: str, inputs: list[str]) -> list[list]:
    """[masukan heksa, frasa yang dilaporkan acmp (str latin-1) atau None]."""
    out = run([str(harness / "pm"), mode, arg], [v.encode("latin-1").hex() + "\n" for v in inputs])
    return [[v.encode("latin-1").hex(), line[2:].decode("latin-1") if line.startswith(b"1 ") else None]
            for v, line in zip(inputs, out)]


def random_value(rng: random.Random, tokens: list[str], max_tokens: int = 8) -> str:
    parts = []
    for _ in range(rng.randint(0, max_tokens)):
        parts.append(rng.choice(tokens) if rng.random() < 0.75 else chr(rng.randrange(256)))
    return "".join(parts)


def pm_inputs(rng: random.Random, phrases: list[str], extra: list[str]) -> list[str]:
    alphabet = sorted({c for p in phrases for c in p} | set("/ .-_"))
    word = lambda n: "".join(rng.choice(alphabet) for _ in range(n))  # noqa: E731
    out = ["", *extra]
    for p in rng.sample(phrases, min(150, len(phrases))):
        style = rng.randrange(4)
        variant = p if style == 0 else p.upper() if style == 1 else "".join(
            c.upper() if rng.random() < 0.5 else c for c in p)
        out.append(variant if rng.random() < 0.4 else word(rng.randint(0, 6)) + variant + word(rng.randint(0, 6)))
    for _ in range(120):  # tekanan tautan gagal satu langkah: awalan frasa A lalu frasa B
        a, b = rng.choice(phrases), rng.choice(phrases)
        cut = rng.randint(1, max(1, len(a) - 1))
        out.append(rng.choice([a[:cut] + b, a[cut:] + b, a[:cut] + b[rng.randint(0, len(b) - 1):], word(2) + a + b]))
    for _ in range(60):
        p = rng.choice(phrases)
        i = rng.randrange(len(p))
        out.append(p[:i] + rng.choice(alphabet) + p[i + 1:])  # satu huruf diganti
    out += [word(rng.randint(1, 30)) for _ in range(50)]
    out += ["".join(chr(rng.randrange(256)) for _ in range(rng.randint(1, 30))) for _ in range(20)]
    # kandidat yang membedakan acmp dari pencarian substring biasa: dipilih dengan port Python, kebenarannya tetap
    # keluaran harness C
    acmp, low = Acmp(phrases), [p.lower() for p in phrases]
    missed, partial = [], []
    for _ in range(20000):
        if len(missed) >= 30 and len(partial) >= 30:
            break
        a, b = rng.choice(phrases), rng.choice(phrases)
        s = a[:rng.randint(1, len(a))] + b[rng.randint(0, len(b) - 1):] + rng.choice(["", b, word(3)])
        found = acmp.find(s)
        if found is None and any(p in s.lower() for p in low) and len(missed) < 30:
            missed.append(s)
        elif found is not None and found.lower() not in low and len(partial) < 30:
            partial.append(s)
    return list(dict.fromkeys(out + missed + partial))


def build(harness: Path) -> dict:
    """Seluruh isi fixture dari biner harness (tfns_map, pm) di folder `harness`."""
    config = load_config()
    crs, umap = config["crs"], config["engine"]["unicode_mapping"]
    rules_dir = ensure_crs(crs["version"], crs["url"], crs["sha256"]) / "rules"
    mapping = ensure_unicode_mapping(umap["url"], umap["sha256"])
    rng = random.Random(SEED)

    tfns = {}
    for name in HARNESS_TFNS:
        tokens = TOKENS[name]
        if name == "htmlEntityDecode":  # semua entitas bernama, huruf acak, dengan/tanpa ';'
            tokens = tokens + [f"&{''.join(c.upper() if rng.random() < 0.3 else c for c in e)}{rng.choice(['', ';'])}"
                               for e in ENTITY_NAMES]
        values = ["", *tokens, *EDGE.get(name, []), *(random_value(rng, tokens) for _ in range(120))]
        values = list(dict.fromkeys(values))
        tfns[name] = tfns_vectors(harness, mapping, [(name,)] * len(values), values)

    rules, _ = load_rules(rules_dir, [str(c) for c in crs["categories"]])
    crs_chains = sorted({link.transforms for r in rules for link in r.links
                         if link.transforms and set(link.transforms) <= set(HARNESS_TFNS)})
    chain_edge = ["%00", "..%00/", "a%00b", "%2e%2e%2f", "%c0%ae%c0%ae/", "\x00<script>", "%u2039script%u203a",
                  "&lt;script&gt;", "\\x3cscript\\x3e", "\\3c script\\3e", " \t ", "%u0000a", ";cat /etc/passwd",
                  "..\\..\\x", "/a/b/../c//d", "&#x3c;&lpar;", "%00%00x/y", "x%00/../y"]
    chains = []
    for chain in crs_chains:
        values = list(dict.fromkeys(chain_edge + [random_value(rng, CHAIN_TOKENS, 10) for _ in range(40)]))
        chains.append([",".join(chain), tfns_vectors(harness, mapping, [chain] * len(values), values)])

    # sapuan penuh %u0000-%uFFFF lewat urlDecodeUni; semua titik kode BMP (+ tiap ke-17 dari U+10000-10FFFF) dalam
    # UTF-8 lewat utf8toUnicode
    def utf8(lo: int) -> str:
        points = range(lo, min(lo + 4096, 0x110000), 1 if lo < 0x10000 else 17)
        return "".join(map(chr, points)).encode("utf-8", "surrogatepass").decode("latin-1")

    sweeps = {}
    for name, values in (("urlDecodeUni", ["".join(f"%u{c:04x}" for c in range(lo, lo + 4096))
                                            for lo in range(0, 0x10000, 4096)]),
                         ("utf8toUnicode", [utf8(lo) for lo in range(0x80, 0x110000, 4096)])):
        digest = hashlib.sha256()
        for _, steps in tfns_vectors(harness, mapping, [(name,)] * len(values), values):
            digest.update(bytes.fromhex(steps[-1][1]))
        sweeps[name] = digest.hexdigest()

    pm = {}
    extra = ["/app/config/parameters.yml", "/config/parameters.yml", "/app/auth.json", "/.htaccess", "/%2ehtaccess",
             "Mozilla/5.00 (Nikto/2.1.6)", "sqlmap/1.4", "../../etc/passwd", ";cat /etc/passwd", "|powershell -enc A"]
    for name in PM_FILES:
        phrases = load_data_file(rules_dir, name)
        pm[name] = {"content": (rules_dir / name).read_bytes().decode("latin-1"),
                    "vectors": pm_vectors(harness, "file", str(rules_dir / name), pm_inputs(rng, phrases, extra))}
    (arg,) = [link.argument for r in rules if r.id == 941180 for link in r.links]
    phrases = arg.split()
    extra += ["document.documentElement.innerHTML", "window.document.cookie", "document.dom=1;document.cookie",
              "document.bodyy;document.cookie", "self.document.write('x')", "x.innerHTML=1"]
    pm["@pm 941180"] = {"argument": arg, "vectors": pm_vectors(harness, "pm", arg, pm_inputs(rng, phrases, extra))}

    lines = mapping.read_bytes().decode("latin-1").split("\n")
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{umap['codepage']} "))
    end = next(i for i in range(start + 1, len(lines)) if lines[i][:1].isdigit() and ":" not in lines[i])
    fixture = {
        "meta": {
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "modsecurity": "2.9.15 (tag v2.9.15, commit 151074aca78a416764b12ba1221e61a17a6c714d)",
            "harness_sha256": {f: hashlib.sha256((harness / f).read_bytes()).hexdigest() for f in ("tfns_map", "pm")},
            "seed": SEED,
            "crs_version": crs["version"],
            "unicode_mapping_sha256": umap["sha256"],
            "codepage": umap["codepage"],
            "not_covered": "escapeSeqDecode, parse_pm_content, dan langkah path Apache tidak ada di harness; "
                           "diuji dengan kasus tangan dari kode C di tests/baselines/test_modsec.py dan test_crs_parser.py",
        },
        # baris header codepage sampai header berikutnya: cukup untuk unicode_map_create() memuat tabel yang sama
        "unicode_mapping_excerpt": "\n".join(lines[start:end + 1]),
        "tfns": tfns,
        "chains": chains,
        "sweeps_sha256": sweeps,
        "pm": pm,
    }
    return fixture


VOLATILE_META = ("generated_utc", "harness_sha256")  # bergantung waktu dan kompilator, bukan isi vektor


def main() -> int:
    check = "--check" in sys.argv[1:]
    (harness,) = [Path(a).resolve() for a in sys.argv[1:] if a != "--check"]
    fixture = build(harness)
    if check:
        stored = json.loads(OUT.read_text(encoding="utf-8"))
        for doc in (stored, fixture):
            for key in VOLATILE_META:
                doc["meta"].pop(key, None)
        same = stored == fixture
        print(f"[golden] {'cocok' if same else 'BERBEDA'}: vektor dari harness {harness} vs {OUT.relative_to(ROOT)}")
        return 0 if same else 1
    OUT.write_text(json.dumps(fixture, separators=(",", ":")) + "\n", encoding="utf-8")
    counts = {"tfns": sum(map(len, fixture["tfns"].values())), "chains": sum(len(v) for _, v in fixture["chains"]),
              "pm": sum(len(v["vectors"]) for v in fixture["pm"].values())}
    print(f"[golden] {counts} -> {OUT.relative_to(ROOT)} ({OUT.stat().st_size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
