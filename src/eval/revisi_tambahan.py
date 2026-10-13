"""Analisis tambahan revisi jurnal (keputusan penulis 2026-10-13): sumber angka di teks naskah yang tidak berasal dari
Tabel 4-11 -> reports/revisi_tambahan.md (+ .json). Dijalankan oleh make eval setelah src/eval/revisi.py.

Definisi:
- Tanpa pilot: metrik pada 470 baris sampel di luar results/archive/pilot/pilot_ids.json (30 baris pilot, 5 per kelas).
  IK macro-F1 seperti Tabel 5 dan uji berpasangan seperti Tabel 6 (revisi.paired_bootstrap dan paired_permutation),
  dengan templat dan draw dihitung ulang pada 470 baris.
- Kaskade §3.6 (post hoc pada keluaran per baris yang ada): baris yang diberi kelas serangan oleh regex utama memakai
  label regex; baris yang diberi NORMAL memakai label LLM tunggal run yang sama (r1-r3). Varian: regex_full sebagai
  lapis pertama. Biaya = cost_usd (billed) dan harga list (token x tarif configs/llm.yaml) LLM tunggal hanya pada baris
  yang diteruskan, dibagi jumlah seluruh baris sampel, per 1.000 baris.
- Sub-tipe WEB_SCANNING: aturan gerbang di awalan template_key: V1 sapuan metode (label 274), W1 UA pemindai, P1 ekstensi
  cadangan/terlarang (label 272), T3 berkas VCS/cadangan/terlarang tanpa traversal (label 126). Recall = porsi baris
  sub-tipe itu yang diprediksi WEB_SCANNING, rerata run. Aturan regex = aturan berkelas WEB_SCANNING yang cocok per baris.
- Label berubah antar run: baris yang labelnya (keluaran di luar 6 kelas = invalid) tidak sama di semua run, seperti
  replikasi.aggregate; dirinci menurut kelas gerbang dan menurut himpunan label yang muncul di ketiga run.
- SQLI terlewat regex utama: baris SQLI gerbang yang diprediksi NORMAL oleh regex utama. Letak payload = field tempat
  famili sintaks SQL aturan gerbang S1 (src/data/gate/sqli.py: _SQLMAP, _ZAP_SQL, _SQL_OTHER) cocok, diperiksa terpisah
  pada path, query string, User-Agent, dan Referer setelah multi_decode. Aturan 942 regex utama yang memeriksa path =
  aturan yang target link pertamanya memuat REQUEST_FILENAME, REQUEST_BASENAME, REQUEST_URI, REQUEST_URI_RAW, atau
  REQUEST_LINE (dilewati bila arsip CRS belum diunduh oleh make regex).
- Dedup persis: bingkai 6 kelas dibangun ulang dari data/raw (hanya dibaca; MD5 diverifikasi) dengan fungsi pipeline
  src/data seperti src/data/prepare.py. Paritas: dedup isi resmi -> batas templat RFI -> split harus menghasilkan id
  srbh_test.parquet persis. Kontrafaktual: dedup pada raw_log utuh (dengan stempel waktu) -> batas templat RFI -> split
  yang sama; kembaran isi = baris uji yang audit.content_key-nya (baris log tanpa stempel waktu) ada di train.
Laporan hanya memuat jumlah agregat, tanpa id per baris.
Jalankan: make eval  (atau python -m src.eval.revisi_tambahan --out reports/revisi_tambahan.md)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

from ..common.inputs import SAMPLE_PATH, load_inputs, split_path
from ..common.runinfo import run_info
from ..data.config import CLASSES, ROOT
from ..data.gate import sqli as gate_sqli
from ..data.gate.common import multi_decode
from .evaluate import OTHER, RESULTS_DIR, Truth, _indices, binary, evidence_literal, load_truth, multiclass
from .replikasi import bootstrap_mean_macro_f1, summarize
from .revisi import FIRST, N_PAIRED, NAMES, ORDER, PAIRS, SHORT, _list_rates, _n, _p, _table, cell, collect
from .revisi import paired_bootstrap, paired_permutation

PILOT_IDS = RESULTS_DIR / "archive" / "pilot" / "pilot_ids.json"
WS_SUBTYPES = {"V1": "Method sweeps", "W1": "Scanner user agents", "P1": "Backup/forbidden extensions",
               "T3": "VCS or forbidden files"}
SQL_FAMILIES = (gate_sqli._SQLMAP, gate_sqli._ZAP_SQL, gate_sqli._SQL_OTHER)  # famili aturan gerbang S1
CARRIERS = ("path", "query", "user_agent", "referer")
PATH_VARIABLES = ("REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_LINE")
LABEL_NAMES = (*CLASSES, "invalid")  # indeks OTHER = keluaran di luar 6 kelas


# ------------------------------------------------------------------------------------------------- bantuan


def subset(truth: Truth, keep: set[str]) -> Truth:
    ids = [i for i in truth.labels if i in keep]
    return Truth({i: truth.labels[i] for i in ids}, {i: truth.template_keys[i] for i in ids},
                 f"{truth.source} ({len(ids)} baris)", {i: truth.logs[i] for i in ids})


def arrays(truth: Truth, data: dict) -> tuple[list[str], np.ndarray, list[str], dict[str, list[np.ndarray]]]:
    """id, label gerbang (indeks), klaster "kelas|template_key", dan prediksi per run tiap metode."""
    ids = list(truth.labels)
    gold = [truth.labels[i] for i in ids]
    t = _indices(gold, gold)[0]
    clusters = [f"{truth.labels[i]}|{truth.template_keys[i]}" for i in ids]
    preds = {name: [_indices(gold, [m.predictions[i] for i in ids])[1] for m in entry["methods"]]
             for name, entry in data.items()}
    return ids, t, clusters, preds


def scores(t: np.ndarray, p: np.ndarray) -> dict:
    """Metrik klasifikasi satu run (definisi Tabel 4, 5, dan 7)."""
    b, m = binary(t, p), multiclass(t, p)
    normal = CLASSES.index("NORMAL")
    valid_normal = (t == normal) & (p != OTHER)
    return {"accuracy": m["accuracy"], "macro_f1": m["macro_f1"], "biner_f1": b["f1"], "biner_fpr": b["fpr"],
            "biner_fpr_tanpa_invalid": float((p[valid_normal] != normal).mean()) if valid_normal.any() else None,
            **{f"f1_{c}": m["per_class"][c]["f1"] for c in CLASSES}}


def paired(t: np.ndarray, a: list[np.ndarray], b: list[np.ndarray], clusters: list[str], n: int) -> dict:
    boot = paired_bootstrap(t, a, b, clusters, n)
    perm = paired_permutation(t, a, b, clusters, n)
    return {**boot, "p_permutasi": perm["p"], "n_permutasi": perm["n_permutasi"]}


# ------------------------------------------------------------------------------------------------- analisis


def without_pilot(truth: Truth, data: dict, n_paired: int = N_PAIRED, pilot_path: Path = PILOT_IDS) -> dict:
    pilot = set(json.loads(pilot_path.read_text(encoding="utf-8"))["ids"])
    if not pilot <= set(truth.labels):
        raise ValueError(f"{pilot_path.name}: {len(pilot - set(truth.labels))} id pilot tidak ada di sampel")
    sub = subset(truth, set(truth.labels) - pilot)
    ids, t, clusters, preds = arrays(sub, data)
    methods = {}
    for name, entry in data.items():
        per_run = [scores(t, p) for p in preds[name]]
        out = {k: summarize([r[k] for r in per_run]) for k in per_run[0]}
        literal = [evidence_literal(m, sub) for m in entry["methods"]]
        if all(literal):
            out["evidence_literal"] = summarize([x["proportion"] for x in literal])
        out["ik_macro_f1"] = bootstrap_mean_macro_f1(t, preds[name], clusters)
        out["macro_f1_500"] = entry["group"]["metrics"]["macro_f1"]
        methods[name] = out
    tests = [{"a": a, "b": b, **paired(t, preds[a], preds[b], clusters, n_paired)} for a, b in PAIRS
             if a in preds and b in preds]
    return {"berkas_pilot": str(pilot_path.relative_to(ROOT)) if pilot_path.is_relative_to(ROOT) else str(pilot_path),
            "pilot": len(pilot), "pilot_per_kelas": {c: sum(truth.labels[i] == c for i in pilot) for c in CLASSES},
            "n": len(ids), "per_kelas": {c: sum(sub.labels[i] == c for i in ids) for c in CLASSES},
            "metode": methods, "uji_berpasangan": tests}


def cascade(truth: Truth, data: dict, n_paired: int = N_PAIRED) -> dict:
    if "llm_single" not in data:
        return {}
    ids, t, clusters, preds = arrays(truth, data)
    gold = [truth.labels[i] for i in ids]
    rate_in, rate_out = _list_rates()
    out = {"llm_single_biaya_per_1000_baris_usd": data["llm_single"]["group"]["metrics"]["biaya_per_1000_baris_usd"],
           "lapis_pertama": {}}
    for first in ("regex", "regex_full"):
        if first not in data:
            continue
        layer = data[first]["methods"][0].predictions
        sent = {i for i in ids if layer[i] == "NORMAL"}
        runs, billed, listed = [], [], []
        for m in data["llm_single"]["methods"]:
            runs.append(_indices(gold, [m.predictions[i] if i in sent else layer[i] for i in ids])[1])
            rows = [r for r in m.rows if r["id"] in sent]
            billed.append(1000 * sum(r["cost_usd"] for r in rows) / len(ids))
            listed.append(1000 * sum(r["prompt_tokens"] * rate_in + r["completion_tokens"] * rate_out for r in rows)
                          / 1e6 / len(ids))
        per_run = [scores(t, p) for p in runs]
        out["lapis_pertama"][first] = {
            "baris_ke_llm": len(sent),
            "baris_ke_llm_per_kelas": {c: sum(truth.labels[i] == c for i in sent) for c in CLASSES},
            "metrik": {k: summarize([r[k] for r in per_run]) for k in per_run[0]},
            "ik_macro_f1": bootstrap_mean_macro_f1(t, runs, clusters),
            "biaya_per_1000_baris_usd": summarize(billed),
            "biaya_list_per_1000_baris_usd": summarize(listed),
            "uji_berpasangan": [{"b": b, **paired(t, runs, preds[b], clusters, n_paired)} for b in ("llm_single", first)],
        }
    return out


def _ws_rules(row: dict) -> set[str]:
    return {hit["rule"] for hit in row.get("matched_rules") or [] if hit["class"] == "WEB_SCANNING"}


def ws_subtypes(truth: Truth, data: dict) -> dict:
    ids = [i for i in truth.labels if truth.labels[i] == "WEB_SCANNING"]
    rule = {i: str(truth.template_keys[i]).split(":")[0] for i in ids}
    unknown = sorted(set(rule.values()) - set(WS_SUBTYPES))
    if unknown:
        raise ValueError(f"sub-tipe WEB_SCANNING tanpa nama: {unknown}")
    groups = {r: [i for i in ids if rule[i] == r] for r in WS_SUBTYPES}
    out = {"n": {r: len(g) for r, g in groups.items()},
           "rincian": {r: dict(Counter(truth.template_keys[i] for i in g).most_common()) for r, g in groups.items()},
           "metode": {}, "aturan_regex": {}}
    for name, entry in data.items():
        runs = entry["methods"]
        out["metode"][name] = {
            r: {"recall": summarize([sum(m.predictions[i] == "WEB_SCANNING" for i in g) / len(g) for m in runs]),
                "prediksi_rerata": {k: v / len(runs) for k, v in
                                    Counter(m.predictions[i] for m in runs for i in g).most_common()}}
            for r, g in groups.items() if g}
        if name in ("regex", "regex_full"):
            rows = {x["id"]: x for x in runs[0].rows}
            out["aturan_regex"][name] = {r: dict(Counter(h for i in g for h in _ws_rules(rows[i])).most_common())
                                         for r, g in groups.items()}
    return out


def label_changes(truth: Truth, data: dict) -> dict:
    _, t, _, preds = arrays(truth, data)
    out = {}
    for name, runs in preds.items():
        if len(runs) < 2:
            continue
        labels = np.array(runs)
        changed = np.flatnonzero((labels != labels[0]).any(axis=0))
        seen = [set(labels[:, j].tolist()) for j in changed]
        out[name] = {
            "baris": len(changed),
            "per_kelas_gerbang": {c: int((t[changed] == k).sum()) for k, c in enumerate(CLASSES)},
            "memuat_label": {c: sum(k in s for s in seen) for k, c in enumerate(LABEL_NAMES)},
            "himpunan_label": dict(Counter(" / ".join(LABEL_NAMES[k] for k in sorted(s)) for s in seen).most_common()),
        }
    return out


def sql_carriers(row: dict) -> set[str]:
    """Field tempat famili sintaks SQL aturan gerbang S1 cocok (setelah multi_decode), diperiksa per field."""
    return {c for c in CARRIERS if any(f.search(multi_decode(row.get(c) or "")) for f in SQL_FAMILIES)}


def sqli_rules_on_path() -> dict | None:
    """Aturan 942 konfigurasi regex utama yang target link pertamanya memuat variabel path; None bila CRS belum ada."""
    from ..baselines.crs import EXTERNAL_DIR
    from ..baselines.regex_baseline import build_ruleset, load_config

    config = load_config()
    if not (EXTERNAL_DIR / f"coreruleset-{config['crs']['version']}.tar.gz").exists():
        return None
    rules = [r for r in build_ruleset(config).rules if r.category == "942"]
    on_path = [r.id for r in rules if any(t.collection.upper() in PATH_VARIABLES and not (t.exclude or t.count)
                                          for t in r.links[0].targets)]
    return {"aturan_942_dipakai": len(rules), "memeriksa_path": sorted(on_path), "variabel_path": list(PATH_VARIABLES)}


def sqli_missed(truth: Truth, data: dict, inputs: list[dict], rules_on_path: dict | None = None) -> dict:
    if "regex" not in data:
        return {}
    regex = data["regex"]["methods"][0].predictions
    rows = {r["id"]: r for r in inputs}
    sqli = [i for i in truth.labels if truth.labels[i] == "SQLI"]
    missed = [i for i in sqli if regex[i] == "NORMAL"]
    where = {i: sql_carriers(rows[i]) for i in missed}
    query = {i: bool(rows[i]["query"]) for i in missed}
    count = lambda cond: sum(1 for i in missed if cond(i))  # noqa: E731
    return {
        "sqli": len(sqli), "prediksi_regex": dict(Counter(regex[i] for i in sqli).most_common()), "terlewat": len(missed),
        "tanpa_query_string": count(lambda i: not query[i]),
        "payload_di_path": count(lambda i: "path" in where[i]),
        "payload_hanya_di_path": count(lambda i: where[i] == {"path"}),
        "payload_di_path_tanpa_query_string": count(lambda i: "path" in where[i] and not query[i]),
        "payload_di_path_dengan_query_string": count(lambda i: "path" in where[i] and query[i]),
        "payload_di_query_string": count(lambda i: "query" in where[i]),
        "payload_di_user_agent": count(lambda i: "user_agent" in where[i]),
        "payload_di_referer": count(lambda i: "referer" in where[i]),
        "tanpa_famili_s1": count(lambda i: not where[i]),
        "aturan_942_memeriksa_path": rules_on_path,
    }


def exact_dedup() -> dict:
    """Kontrafaktual dedup persis dari data/raw (hanya dibaca), dengan cek paritas terhadap split uji resmi."""
    import pandas as pd

    from ..data import audit
    from ..data.config import LABEL_MAPPING_SRC, SRBH_CSV
    from ..data.download import verify_srbh
    from ..data.gate import MODULES
    from ..data.gate.rfi import rfi_template
    from ..data.labels import EXCLUDED, apply_gate, load_mapping, validate_columns
    from ..data.load import detect_label_columns, read_raw
    from ..data.prepare import opaque_id
    from ..data.reconstruct import mask_log, reconstruct
    from ..data.split import RFI_RULE, cap_rfi_templates, dedup, stratified_split

    if not SRBH_CSV.exists():
        return {"dilewati": f"{SRBH_CSV.relative_to(ROOT)} tidak ada (make download)"}
    md5 = verify_srbh()
    raw = read_raw()
    label_cols = detect_label_columns(raw)
    mapping = load_mapping(LABEL_MAPPING_SRC)
    validate_columns(label_cols, mapping)
    # Langkah 3-4 src/data/prepare.py: label gerbang, templat RFI, rekonstruksi log dan masking.
    df = raw.astype({c: np.int8 for c in label_cols})
    labeled, _ = apply_gate(df, mapping, MODULES)
    is_rfi = labeled["label_rule"] == RFI_RULE
    labeled["rfi_template"] = ""
    labeled.loc[is_rfi, "rfi_template"] = [rfi_template(multi_decode(u)) for u in raw.loc[is_rfi, "request_http_request"]]
    rec = reconstruct(raw)
    full = pd.concat([pd.DataFrame({"id": [opaque_id(i) for i in df.index], "row_id": df.index}, index=df.index),
                      rec[["raw_log"]], mask_log(rec["raw_log"]).rename("raw_log_masked"), labeled], axis=1)
    six = full[full["label"] != EXCLUDED].drop(columns="exclusion_reason")
    cap = int(mapping.options["rfi_template_cap"])

    content, content_stats = dedup(six, key="raw_log_masked")
    _, _, test = stratified_split(cap_rfi_templates(content, cap)[0])
    official = pd.read_parquet(split_path("test"), columns=["id"])["id"].tolist()
    if test["id"].tolist() != official:
        raise RuntimeError("paritas gagal: dedup isi -> batas RFI -> split tidak menghasilkan srbh_test.parquet")

    exact, exact_stats = dedup(six, key="raw_log")
    out = {"md5": md5, "baris_mentah": len(raw), "baris_6_kelas": len(six), "paritas_split_uji_resmi": True,
           "dedup_isi": content_stats, "dedup_persis": exact_stats, "batas_templat_rfi": cap, "kontrafaktual": {}}
    for name, part in (("dengan_batas_rfi", cap_rfi_templates(exact, cap)[0]), ("tanpa_batas_rfi", exact)):
        train, _, test = stratified_split(part)
        twin = audit.content_key(test["raw_log"]).isin(set(audit.content_key(train["raw_log"])))
        out["kontrafaktual"][name] = {
            "train": len(train), "uji": len(test), "uji_berkembaran": int(twin.sum()), "persen": 100 * float(twin.mean()),
            "per_kelas": {c: [int(twin[(test["label"] == c).to_numpy()].sum()), int((test["label"] == c).sum())]
                          for c in CLASSES}}
    return out


def build(truth: Truth, data: dict, inputs: list[dict], n_paired: int = N_PAIRED, dedup: bool = True) -> dict:
    return {"tanpa_pilot": without_pilot(truth, data, n_paired), "kaskade": cascade(truth, data, n_paired),
            "sub_tipe_web_scanning": ws_subtypes(truth, data), "label_berubah_antar_run": label_changes(truth, data),
            "sqli_terlewat_regex": sqli_missed(truth, data, inputs, sqli_rules_on_path()),
            "dedup_persis": exact_dedup() if dedup else {"dilewati": "opsi --tanpa-dedup"}}


# ------------------------------------------------------------------------------------------------- tampilan


def _comparison(first: str, second: str, x: dict) -> list[str]:
    return [f"{first} − {second}", _n(x["selisih"]), f"[{_n(x['ik_bawah'])}, {_n(x['ik_atas'])}]", _p(x["p"]),
            _p(x["p_permutasi"])]


def _counts(values: dict, keys) -> str:
    return ", ".join(f"{k} {values[k]}" for k in keys if values.get(k))


def render(result: dict) -> str:
    out = ["Format angka mengikuti manuskrip (titik desimal; metode LLM: rerata tiga run dengan rentang min–maks). "
           "Definisi: docstring src/eval/revisi_tambahan.py. Laporan hanya memuat jumlah agregat (tanpa id per baris).", ""]

    x = result["tanpa_pilot"]
    names = [n for n in ORDER if n in x["metode"]]
    m = x["metode"]
    runs = {n: len(m[n]["macro_f1"]["values"]) for n in names}
    out += [f"## 1. Tanpa {x['pilot']} baris pilot ({x['n']} baris)", "",
            f"Pilot: `{x['berkas_pilot']}` ({_counts(x['pilot_per_kelas'], CLASSES)}). Sisa {x['n']} baris: "
            f"{_counts(x['per_kelas'], CLASSES)}.", ""]
    out.append(_table(["Method", f"Macro-F1 ({x['n']})", "95% CI", "Macro-F1 (500)", "Binary F1", "FPR",
                       "FPR excl. invalid", "Literal items"],
                      [[NAMES[n], cell(m[n]["macro_f1"], runs=runs[n]),
                        f"[{_n(m[n]['ik_macro_f1']['low'])}, {_n(m[n]['ik_macro_f1']['high'])}]",
                        cell(m[n]["macro_f1_500"], runs=runs[n]), cell(m[n]["biner_f1"], runs=runs[n]),
                        cell(m[n]["biner_fpr"], runs=runs[n]), cell(m[n]["biner_fpr_tanpa_invalid"], runs=runs[n]),
                        cell(m[n].get("evidence_literal"), runs=runs[n])] for n in names]))
    out += ["", f"F1 per kelas pada {x['n']} baris:", ""]
    out.append(_table(["Method", "SQLI", "XSS", "PT", "CMD", "WS", "NORMAL"],
                      [[NAMES[n], *(cell(m[n][f"f1_{c}"], runs=runs[n], dagger=True) for c in CLASSES)] for n in names]))
    out += ["", f"Uji berpasangan pada {x['n']} baris ({x['uji_berpasangan'][0]['n_draw']:,} draw; definisi Tabel 6):", ""]
    out.append(_table(["Comparison (A − B)", "Difference", "95% CI", "p, bootstrap", "p, permutation"],
                      [_comparison(FIRST[y["a"]], SHORT[y["b"]], y) for y in x["uji_berpasangan"]]))

    x = result["kaskade"]
    if x:
        layer_name = {"regex": "Cascade: regex → single LLM", "regex_full": "Cascade: full regex (post hoc) → single LLM"}
        out += ["", "## 2. Kaskade §3.6 (post hoc): baris NORMAL menurut regex diteruskan ke LLM tunggal", ""]
        rows = []
        for first, y in x["lapis_pertama"].items():
            mt, k = y["metrik"], len(y["metrik"]["macro_f1"]["values"])
            rows.append([layer_name[first], str(y["baris_ke_llm"]), cell(mt["macro_f1"], runs=k),
                         f"[{_n(y['ik_macro_f1']['low'])}, {_n(y['ik_macro_f1']['high'])}]", cell(mt["biner_f1"], runs=k),
                         cell(mt["biner_fpr"], runs=k), cell(mt["biner_fpr_tanpa_invalid"], runs=k),
                         cell(y["biaya_per_1000_baris_usd"], runs=k), cell(y["biaya_list_per_1000_baris_usd"], runs=k)])
        out.append(_table(["Configuration", "Lines sent to the LLM", "Macro-F1", "95% CI", "Binary F1", "FPR",
                           "FPR excl. invalid", "USD per 1,000 lines, billed", "USD per 1,000 lines, list price"], rows))
        out += ["", "Baris yang diteruskan ke LLM menurut kelas gerbang: " + "; ".join(
            f"{first} {_counts(y['baris_ke_llm_per_kelas'], CLASSES)}" for first, y in x["lapis_pertama"].items()) + ".",
                f"Pembanding: LLM tunggal sendiri {cell(x['llm_single_biaya_per_1000_baris_usd'], runs=k)} USD per 1,000 "
                "baris (billed).", ""]
        out.append(_table(["Comparison (A − B)", "Difference", "95% CI", "p, bootstrap", "p, permutation"],
                          [_comparison(layer_name[first], SHORT[z["b"]], z) for first, y in x["lapis_pertama"].items()
                           for z in y["uji_berpasangan"]]))
        out += ["", "F1 per kelas kaskade: " + "; ".join(
            f"{first} " + ", ".join(f"{c} {cell(y['metrik'][f'f1_{c}'], runs=k)}" for c in CLASSES)
            for first, y in x["lapis_pertama"].items()) + "."]

    x = result["sub_tipe_web_scanning"]
    names = [n for n in ORDER if n in x["metode"]]
    out += ["", "## 3. Recall WEB_SCANNING per sub-tipe (aturan gerbang)", ""]
    out.append(_table(["Sub-type (gate rule)", "Lines", *(NAMES[n] for n in names)],
                      [[f"{WS_SUBTYPES[r]} ({r})", str(x["n"][r]),
                        *(cell(x["metode"][n][r]["recall"], 2, runs=len(x["metode"][n][r]["recall"]["values"]))
                          for n in names)] for r in WS_SUBTYPES if x["n"][r]]))
    out += ["", "Rincian template_key per sub-tipe:", ""]
    out += [f"- {r}: " + ", ".join(f"{k.split(':', 1)[1] if ':' in k else k} {v}" for k, v in x["rincian"][r].items())
            for r in WS_SUBTYPES if x["n"][r]]
    out += ["", "Prediksi pada baris sub-tipe (rerata per run):", ""]
    out += [f"- {NAMES[n]}: " + "; ".join(
        f"{r} " + ", ".join(f"{k} {v:.1f}" for k, v in x["metode"][n][r]["prediksi_rerata"].items())
        for r in WS_SUBTYPES if x["n"][r]) for n in names]
    out += ["", "Aturan regex berkelas WEB_SCANNING yang cocok (jumlah baris per aturan):", ""]
    out += [f"- {NAMES[n]}: " + "; ".join(f"{r} " + (", ".join(f"{k} {v}" for k, v in rules.items()) or "tidak ada")
                                          for r, rules in x["aturan_regex"][n].items() if x["n"][r])
            for n in ORDER if n in x["aturan_regex"]]

    x = result["label_berubah_antar_run"]
    names = [n for n in ORDER if n in x]
    out += ["", "## 4. Label berubah antar run, menurut kelas gerbang", ""]
    out.append(_table(["Method", "Lines", *CLASSES],
                      [[NAMES[n], str(x[n]["baris"]), *(str(x[n]["per_kelas_gerbang"][c]) for c in CLASSES)]
                       for n in names]))
    out += ["", "Baris berubah yang memuat label tertentu di salah satu run (satu baris bisa dihitung di dua label):", ""]
    out.append(_table(["Method", *LABEL_NAMES], [[NAMES[n], *(str(x[n]["memuat_label"][c]) for c in LABEL_NAMES)]
                                                 for n in names]))
    out += ["", "Himpunan label yang muncul di ketiga run:", ""]
    out += [f"- {NAMES[n]}: " + ", ".join(f"{k} {v}" for k, v in x[n]["himpunan_label"].items()) for n in names]

    x = result["sqli_terlewat_regex"]
    if x:
        out += ["", "## 5. SQLI yang terlewat regex utama: letak payload", ""]
        out += [f"- SQLI di sampel: {x['sqli']}; prediksi regex utama: "
                + ", ".join(f"{k} {v}" for k, v in x["prediksi_regex"].items()) + f". Terlewat (NORMAL): {x['terlewat']}.",
                f"- Payload SQL (famili S1 gerbang) di path: **{x['payload_di_path']} dari {x['terlewat']}** "
                f"(hanya di path: {x['payload_hanya_di_path']}; tanpa query string: "
                f"{x['payload_di_path_tanpa_query_string']}; dengan query string tanpa payload SQL: "
                f"{x['payload_di_path_dengan_query_string']}).",
                f"- Tanpa query string sama sekali: {x['tanpa_query_string']} dari {x['terlewat']}.",
                f"- Payload di query string: {x['payload_di_query_string']}; di User-Agent: {x['payload_di_user_agent']}; "
                f"di Referer: {x['payload_di_referer']}; tanpa famili S1 terlihat: {x['tanpa_famili_s1']}."]
        rules = x["aturan_942_memeriksa_path"]
        out.append(f"- Aturan 942 (PL1, regex) di konfigurasi utama: {rules['aturan_942_dipakai']}; yang memeriksa path "
                   f"({', '.join(rules['variabel_path'])}): {', '.join(map(str, rules['memeriksa_path']))}."
                   if rules else "- Aturan 942 yang memeriksa path: dilewati (arsip CRS belum diunduh; jalankan make regex).")

    x = result["dedup_persis"]
    out += ["", "## 6. Dedup persis vs dedup isi (kontrafaktual dari data/raw)", ""]
    if "dilewati" in x:
        out.append(f"Dilewati: {x['dilewati']}.")
    else:
        d, c = x["dedup_persis"], x["dedup_isi"]
        out += [f"- Bingkai 6 kelas dibangun ulang dari data/raw (MD5 `{x['md5']}`): {x['baris_6_kelas']:,} baris dari "
                f"{x['baris_mentah']:,}. Paritas dengan split uji resmi: {'cocok' if x['paritas_split_uji_resmi'] else 'GAGAL'}.",
                f"- Dedup isi (resmi, kunci raw_log_masked): dibuang {c['duplicates_dropped'] + c['conflict_rows_dropped']:,} "
                f"(konflik label {c['conflict_rows_dropped']:,}), sisa {c['rows_out']:,}.",
                f"- Dedup persis (raw_log utuh dengan stempel waktu): dibuang **{d['duplicates_dropped'] + d['conflict_rows_dropped']:,}** "
                f"(konflik label {d['conflict_rows_dropped']:,}), sisa {d['rows_out']:,}; per kelas: "
                + ", ".join(f"{k} {v:,}" for k, v in d["duplicates_dropped_by_class"].items()) + "."]
        for name, title in (("dengan_batas_rfi", f"dedup persis -> batas templat RFI ({x['batas_templat_rfi']}) -> split"),
                            ("tanpa_batas_rfi", "dedup persis -> split (tanpa batas templat RFI)")):
            y = x["kontrafaktual"][name]
            out.append(f"- Kontrafaktual {title}: baris uji yang punya kembaran isi di train **{y['uji_berkembaran']:,} dari "
                       f"{y['uji']:,} ({_n(y['persen'], 2)}%)**; per kelas: "
                       + ", ".join(f"{k} {a:,}/{b:,}" for k, (a, b) in y["per_kelas"].items()) + ".")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analisis tambahan revisi jurnal: sumber angka teks naskah")
    parser.add_argument("--out", type=Path, help="simpan Markdown + JSON ke path ini (.md)")
    parser.add_argument("--tanpa-dedup", action="store_true", help="lewati kontrafaktual dedup (butuh data/raw)")
    parser.add_argument("--n-paired", type=int, default=N_PAIRED, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    truth = load_truth("sample")
    data = collect(truth)
    result = build(truth, data, load_inputs(SAMPLE_PATH), args.n_paired, dedup=not args.tanpa_dedup)
    info = run_info("revisi_tambahan", None, metode={n: [m.relpath for m in v["methods"]] for n, v in data.items()},
                    n_paired=args.n_paired)
    text = (f"# Revisi jurnal — analisis tambahan untuk angka di teks naskah\n\nLaporan {info['run_id']} (commit "
            f"{str(info['git_commit'])[:7]}, dirty={info['git_dirty']})\n\n" + render(result))
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        args.out.with_suffix(".json").write_text(json.dumps({"run": info, **result}, ensure_ascii=False, indent=1) + "\n",
                                                 encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
