"""Port Python ModSecurity 2.9.15 (src/baselines/modsec.py) vs vektor emas dari kode C aslinya.

Vektor di tests/fixtures/modsec_v2915_golden.json dibuat scripts/make_modsec_golden.py dengan menjalankan harness C yang
dikompilasi dari sumber ModSecurity v2.9.15 (tfns_map: re_tfns.c/msc_util.c + unicode.mapping 20127; pm: acmp.c).
"""

import hashlib
import json
from pathlib import Path

import pytest

from src.baselines import modsec as m
from src.baselines.crs import ensure_crs, ensure_unicode_mapping, load_data_file, pm_phrases
from src.baselines.regex_baseline import load_config

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "modsec_v2915_golden.json").read_text("utf-8"))
UNICODE_MAP = m.load_unicode_map(FIXTURE["unicode_mapping_excerpt"], FIXTURE["meta"]["codepage"])


def _bytes(hexstr: str) -> str:
    return bytes.fromhex(hexstr).decode("latin-1")


def _expected(steps: list) -> list[tuple[str, bool]]:
    return [(_bytes(out), bool(changed)) for changed, out in steps]


@pytest.mark.parametrize("name", sorted(FIXTURE["tfns"]))
def test_every_transformation_vector_matches_modsecurity_c(name):
    for value, steps in FIXTURE["tfns"][name]:
        assert m.transform_steps(_bytes(value), (name,), UNICODE_MAP) == _expected(steps), (name, _bytes(value))


@pytest.mark.parametrize("chain, vectors", FIXTURE["chains"], ids=[c for c, _ in FIXTURE["chains"]])
def test_every_crs_transformation_chain_matches_modsecurity_c(chain, vectors):
    # rantai CRS apa adanya: sisa buffer (removeNulls -> cmdLine) dan bendera changed (dipakai multiMatch) ikut diuji
    names = tuple(chain.split(","))
    for value, steps in vectors:
        assert m.transform_steps(_bytes(value), names, UNICODE_MAP) == _expected(steps), (chain, _bytes(value))


def test_full_sweeps_match_modsecurity_c():
    # %u0000-%uFFFF lewat urlDecodeUni dengan peta 20127; semua titik kode BMP (+ sampel U+10000-10FFFF) lewat
    # utf8toUnicode, dengan potongan yang sama seperti scripts/make_modsec_golden.py
    def utf8(lo: int) -> str:
        points = range(lo, min(lo + 4096, 0x110000), 1 if lo < 0x10000 else 17)
        return "".join(map(chr, points)).encode("utf-8", "surrogatepass").decode("latin-1")

    sweeps = {"urlDecodeUni": ["".join(f"%u{c:04x}" for c in range(lo, lo + 4096)) for lo in range(0, 0x10000, 4096)],
              "utf8toUnicode": [utf8(lo) for lo in range(0x80, 0x110000, 4096)]}
    for name, values in sweeps.items():
        digest = hashlib.sha256()
        for value in values:
            digest.update(m.transform_steps(value, (name,), UNICODE_MAP)[-1][0].encode("latin-1"))
        assert digest.hexdigest() == FIXTURE["sweeps_sha256"][name], name


@pytest.mark.parametrize("name", sorted(FIXTURE["pm"]))
def test_every_phrase_match_vector_matches_acmp_c(name, tmp_path):
    spec = FIXTURE["pm"][name]
    if "content" in spec:  # berkas .data CRS 4.30.0 apa adanya -> frasa seperti msre_op_pmFromFile_param_init
        (tmp_path / name).write_bytes(spec["content"].encode("latin-1"))
        phrases = load_data_file(tmp_path, name)
    else:
        phrases = pm_phrases(m.to_bytes_str(spec["argument"]))
    acmp = m.Acmp(phrases)
    for value, expected in spec["vectors"]:
        assert acmp.find(_bytes(value)) == expected, (name, _bytes(value))


@pytest.mark.slow
def test_pinned_downloads_match_fixture_inputs():
    config = load_config()
    mapping = config["engine"]["unicode_mapping"]
    path = ensure_unicode_mapping(mapping["url"], mapping["sha256"])  # unduh sekali ke data/external/modsecurity/
    assert m.load_unicode_map(path.read_bytes().decode("latin-1"), int(mapping["codepage"])) == UNICODE_MAP
    crs = config["crs"]
    rules = ensure_crs(crs["version"], crs["url"], crs["sha256"]) / "rules"
    for name, spec in FIXTURE["pm"].items():
        if "content" in spec:
            assert (rules / name).read_bytes().decode("latin-1") == spec["content"], name
