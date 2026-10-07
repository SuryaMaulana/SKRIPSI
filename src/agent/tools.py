"""Alat deterministik deep agent (Tabel komponen BAB III).

- Parser: parse_log_line, validate_fields.
- Analisis Payload: url_decode_recursive, html_decode, pattern_match, scanner_indicators, lookup_owasp.
- Verifikasi: evidence_exists, schema_check.

pattern_match memakai mesin emulasi CRS yang sama dengan pembanding regex_full (configs/regex_full.yaml): agen mendapat
WAF sebagai alat (keputusan penulis, dicatat). Keluarannya hanya id aturan, pesan, tag serangan CRS, variabel, dan data
yang cocok; pemetaan kelas penelitian tidak diberikan. scanner_indicators ditulis dari ciri WEB_SCANNING Tabel 2.1 dan
daftar/nilai bawaan CRS. lookup_owasp membaca configs/owasp_kb.yaml (statis, tanpa internet). Tidak ada impor dari
src/data/gate/. Semua alat membaca baris log asli dari konteks baris (context.current()); alat dekode menerima nama
bagian log (path, query, referer, user_agent), bukan teks bebas, agar hasil dekode selalu berasal dari log itu sendiri.
"""

from __future__ import annotations

import html
import json
from functools import lru_cache
from typing import Literal
from urllib.parse import unquote, unquote_plus

import yaml
from langchain_core.tools import tool

from ..baselines import regex_baseline as rb
from ..baselines.crs import ensure_crs, load_data_file, tx_defaults
from ..baselines.llm_single import parse_output
from ..baselines.modsec import collections
from ..common.evidence import evidence_exists as _evidence_exists
from ..data.clf_parser import parse_line
from ..data.config import CONFIGS_DIR
from . import context

REGEX_FULL_CONFIG = CONFIGS_DIR / "regex_full.yaml"
KB_PATH = CONFIGS_DIR / "owasp_kb.yaml"
MAX_DECODE_LAYERS = 3
_FIELDS = ("ip", "ident", "user", "method", "path", "query", "status", "bytes", "referer", "user_agent")
Bagian = Literal["path", "query", "referer", "user_agent"]  # bagian log yang dapat membawa payload


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False)


@lru_cache(maxsize=1)
def _ruleset() -> rb.RuleSet:
    return rb.build_ruleset(rb.load_config(REGEX_FULL_CONFIG))


@lru_cache(maxsize=1)
def _scanner_lists() -> dict:
    config = rb.load_config(REGEX_FULL_CONFIG)
    rules_dir = ensure_crs(config["crs"]["version"], config["crs"]["url"], config["crs"]["sha256"]) / "rules"
    defaults = tx_defaults(rules_dir)
    agents = [p.lower() for p in load_data_file(rules_dir, "scanners-user-agents.data")]
    agents += ["nmap", "zgrab", "sqlmap", "acunetix", "netsparker", "w3af"]  # Tabel 2.1 dan Baş Seyyar dkk.
    return {
        "user_agents": sorted(set(agents)),
        "allowed_methods": defaults["allowed_methods"].split(),
        "restricted_extensions": defaults["restricted_extensions"].split(),
        "probe_paths": ["/.env", "/wp-login.php"],  # Tabel 2.1
        "vcs_dirs": ["/.git/", "/.svn/", "/.hg/", "/.bzr/"],
    }


@lru_cache(maxsize=1)
def _knowledge_base() -> dict:
    return yaml.safe_load(KB_PATH.read_text(encoding="utf-8"))


def _parsed() -> dict:
    ctx = context.current()
    if ctx.parsed is None:
        record = parse_line(ctx.raw_log_masked)
        ctx.parsed = {"terurai": False} if record is None else {
            "terurai": True, **{k: ("" if record[k] is None else str(record[k])) for k in _FIELDS}}
    return ctx.parsed


# ------------------------------------------------------------------------------------------------- Parser


@tool
def parse_log_line() -> str:
    """Urai baris log yang sedang dianalisis (Combined Log Format) menjadi kolom ip, ident, user, method, path, query,
    status, bytes, referer, dan user_agent. Baris log diambil dari sistem, tidak perlu argumen. Stempel waktu dan versi
    protokol sudah disamarkan sehingga tidak dikeluarkan."""
    return _json(_parsed())


@tool
def validate_fields() -> str:
    """Periksa kelengkapan dan kewajaran kolom hasil urai baris log yang sedang dianalisis: metode HTTP, kode status,
    ukuran respons, bentuk path, dan keberadaan user agent/referer. Tidak menilai apakah baris itu serangan."""
    ctx = context.current()
    fields = _parsed()
    if not fields.get("terurai"):
        ctx.validation = {"valid": False, "masalah": ["baris tidak sesuai Combined Log Format"]}
        return _json(ctx.validation)
    problems = []
    method = fields["method"]
    if method not in ("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"):
        problems.append(f"metode di luar RFC 9110/5789: {method}")
    if not (fields["status"].isdigit() and 100 <= int(fields["status"]) <= 599):
        problems.append(f"kode status tidak wajar: {fields['status']}")
    if not (fields["bytes"].isdigit() or fields["bytes"] in ("", "-")):
        problems.append(f"ukuran respons tidak wajar: {fields['bytes']}")
    if not fields["path"].startswith("/") and "://" not in fields["path"]:
        problems.append("path tidak diawali '/'")
    if fields["user_agent"] in ("", "-"):
        problems.append("user agent kosong")
    ctx.validation = {"valid": not problems, "masalah": problems}
    return _json(ctx.validation)


# ------------------------------------------------------------------------------------------------- Analisis Payload


def _url_layers(text: str) -> list[str]:
    layers = [text]
    for _ in range(MAX_DECODE_LAYERS):
        decoded = unquote_plus(layers[-1]) if len(layers) == 1 else unquote(layers[-1])
        if decoded == layers[-1]:
            break
        layers.append(decoded)
    return layers


@tool
def url_decode_recursive(bagian: Bagian) -> str:
    """URL-decode berulang (maksimal 3 lapis) sampai tidak berubah pada satu bagian baris log yang sedang dianalisis:
    path, query, referer, atau user_agent. Bagian diambil dari baris log asli (bukan dari teks yang Anda tulis).
    Kembalikan setiap lapis, mulai dari teks asli."""
    entry = {"bagian": bagian, "lapis": [x[:2000] for x in _url_layers(_parsed().get(bagian, ""))]}
    context.current().decoded.append(entry)
    return _json(entry)


@tool
def html_decode(bagian: Bagian) -> str:
    """Decode entity HTML (mis. &lt; &#60; &quot;) pada satu bagian baris log yang sedang dianalisis (path, query,
    referer, atau user_agent), baik bentuk mentah maupun sesudah URL-decode penuh. Bagian diambil dari baris log asli."""
    layers = _url_layers(_parsed().get(bagian, ""))
    results = list(dict.fromkeys(html.unescape(x) for x in (layers[0], layers[-1])))
    entry = {"bagian": bagian, "hasil": [x[:2000] for x in results]}
    context.current().html_decoded.append(entry)
    return _json(entry)


@tool
def pattern_match() -> str:
    """Cocokkan baris log yang sedang dianalisis dengan aturan OWASP CRS 4.30.0 PL1 (emulasi WAF ModSecurity, cakupan
    sama dengan pembanding regex_full). Kembalikan aturan yang cocok: id, pesan, tag serangan CRS, variabel, dan data
    yang cocok. Tidak memberi label kelas."""
    ctx = context.current()
    fields = _parsed()
    ruleset = _ruleset()
    row = {"id": ctx.row_id, "raw_log_masked": ctx.raw_log_masked, "user_agent": fields.get("user_agent", ""),
           "referer": fields.get("referer", "")}
    coll = collections(rb.request_from_row(row))
    removals = ruleset.evaluator.active_removals(coll)
    hits = []
    for rule in ruleset.rules:
        match = ruleset.evaluator.evaluate(rule, coll, removals)
        if match is not None:
            hits.append({"aturan": rule.id, "pesan": rule.msg, "tag": [t for t in rule.tags if t.startswith("attack-")],
                         "variabel": rb._text(match.variable), "cocok": rb._text(match.data or match.value)})
    ctx.pattern_hits = hits
    return _json({"jumlah": len(hits), "aturan_cocok": hits})


@tool
def scanner_indicators() -> str:
    """Indikator pemindaian per baris sesuai ciri WEB_SCANNING Tabel 2.1: user agent pemindai, metode HTTP di luar
    GET/HEAD/POST/OPTIONS, berkas cadangan/VCS (ekstensi terlarang CRS, akhiran ~, folder .git/.svn), dan probe /.env
    atau /wp-login.php. Hanya indikator, bukan label kelas."""
    ctx = context.current()
    fields = _parsed()
    lists = _scanner_lists()
    ua = fields.get("user_agent", "").lower()
    path = unquote(fields.get("path", "")).lower()
    basename = path.rsplit("/", 1)[-1]
    extension = "." + basename.rsplit(".", 1)[1] + "/" if "." in basename else None
    indicators = {
        "ua_pemindai": [p for p in lists["user_agents"] if p and p in ua][:5],
        "metode_non_standar": None if fields.get("method") in lists["allowed_methods"] else fields.get("method"),
        "ekstensi_cadangan": extension if extension in lists["restricted_extensions"] else (
            "~" if basename.endswith("~") else None),
        "folder_vcs": [d for d in lists["vcs_dirs"] if d in path + "/"],
        "probe_berkas": [p for p in lists["probe_paths"] if path.endswith(p) or p + "?" in path],
    }
    ctx.scanner_indicators = indicators
    return _json(indicators)


@tool
def lookup_owasp(kelas: str) -> str:
    """Ambil basis pengetahuan ringkas (Tabel 2.1 + OWASP) untuk satu kelas: SQLI, XSS, PATH_TRAVERSAL, CMD_INJECTION,
    WEB_SCANNING, atau NORMAL."""
    kb = _knowledge_base()
    key = kelas.strip().upper()
    context.current().kb_lookups.append(key)
    if key not in kb:
        return _json({"galat": f"kelas tidak dikenal: {kelas}", "kelas_tersedia": list(kb)})
    return _json({key: kb[key]})


# ------------------------------------------------------------------------------------------------- Verifikasi


@tool
def evidence_exists(item: str) -> str:
    """Periksa apakah satu item evidence ada secara harfiah (substring) di baris log asli, mentah atau hasil decode
    (URL-decode sampai 3 lapis, entity HTML). Salin item evidence apa adanya dari keluaran klasifikasi."""
    return _json({"item": item, "ada": _evidence_exists(item, context.current().raw_log_masked)})


@tool
def schema_check() -> str:
    """Periksa apakah keluaran klasifikasi terakhir sesuai skema {label, confidence, evidence[], explanation}: label
    salah satu dari 6 kelas, confidence 0-1, evidence daftar string, explanation string."""
    latest = context.current().latest_classification()
    if latest is None:
        return _json({"valid": False, "alasan": "belum ada keluaran klasifikasi"})
    if "_parse_error" in latest:
        return _json({"valid": False, "alasan": latest["_parse_error"]})
    output, reason = parse_output(json.dumps(latest))
    return _json({"valid": output is not None, "alasan": reason})


PARSER_TOOLS = [parse_log_line, validate_fields]
PAYLOAD_TOOLS = [url_decode_recursive, html_decode, pattern_match, scanner_indicators, lookup_owasp]
VERIFIER_TOOLS = [evidence_exists, schema_check]
