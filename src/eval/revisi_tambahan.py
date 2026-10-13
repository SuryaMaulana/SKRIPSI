"""Analisis tambahan revisi jurnal (keputusan penulis 2026-10-13): sumber angka di teks naskah yang tidak berasal dari
Tabel 4-11 -> reports/revisi_tambahan.md (+ .json). Dijalankan oleh make eval setelah src/eval/revisi.py.

Definisi:
- Tanpa pilot: metrik Tabel 4, 5, 7, dan literal evidence pada 470 baris sampel di luar
  results/archive/pilot/pilot_ids.json (30 baris pilot, 5 per kelas). IK macro-F1 seperti Tabel 5 (1.000 draw), uji
  berpasangan seperti Tabel 6 (revisi.paired_bootstrap dan paired_permutation) dan McNemar seperti suplemen Tabel 6,
  dengan templat dan draw dihitung ulang pada 470 baris; uji berpasangan 500 baris dihitung ulang di samping sebagai
  pembanding. Akurasi 6 kelas pada 30 baris pilot vs 470 baris lain menunjukkan apakah baris pilot lebih mudah.
- Kaskade §3.6 (post hoc pada keluaran per baris yang ada): baris yang diberi kelas serangan oleh regex utama (CRS PL1 +
  aturan Baş Seyyar dkk.) memakai label regex; baris yang diberi NORMAL memakai label LLM tunggal run yang sama (r1-r3).
  Varian: regex_full sebagai lapis pertama. Sensitivitas: regex utama dengan hit berkas terlarang (930130/930140, yang
  oleh configs/regex_baseline.yaml restricted_files dipetakan ke WEB_SCANNING bila tanpa traversal) memakai kelas bawaan
  kategori 930 (PATH_TRAVERSAL); label dihitung ulang dari matched_rules dengan skor dan tie_break regex_baseline
  (rekonstruksi tanpa perubahan harus sama persis dengan results/regex.jsonl). Biaya = cost_usd (billed) dan harga list
  (token x tarif configs/llm.yaml) LLM tunggal hanya pada baris yang diteruskan, dibagi jumlah seluruh baris sampel, per
  1.000 baris. Baris diteruskan yang dipulihkan = baris yang diberi kelas gerbangnya oleh LLM.
- Sub-tipe WEB_SCANNING: aturan gerbang di awalan template_key: V1 metode non-standar (label 274), W1 UA pemindai
  (label 310), P1 label 272 (di sampel ini hanya ekstensi cadangan/terlarang: .bak, .backup, .swp, .log), T3 berkas
  VCS/cadangan/terlarang tanpa traversal (label 126). Rincian = template_key; T3:lainnya dirinci menurut nama berkas di
  path. Recall = porsi baris yang diprediksi WEB_SCANNING, rerata run. Aturan regex = aturan berkelas WEB_SCANNING yang
  cocok per baris.
- Label berubah antar run: baris yang labelnya (keluaran di luar 6 kelas = invalid) tidak sama di semua run, seperti
  replikasi.aggregate; dirinci menurut kelas gerbang, label yang muncul, dan keterlibatan keluaran invalid.
- SQLI terlewat regex utama: baris SQLI gerbang yang diprediksi NORMAL oleh regex utama. Letak payload = field tempat
  famili sintaks SQL aturan gerbang S1 (src/data/gate/sqli.py: _SQLMAP, _ZAP_SQL, _SQL_OTHER) cocok, diperiksa terpisah
  pada path, query string, User-Agent, dan Referer setelah multi_decode. Aturan 942 regex utama yang memeriksa path =
  aturan terpakai (PL1, tanpa operator yang dikecualikan, dapat dievaluasi dari log) yang target link pertamanya memuat
  REQUEST_FILENAME, REQUEST_BASENAME, REQUEST_URI, REQUEST_URI_RAW, atau REQUEST_LINE; dibaca dari berkas aturan CRS
  yang sudah diekstrak oleh make regex (tanpa unduhan), dicocokkan dengan rules_dir_sha256 dan jumlah aturan 942 di
  results/regex.run.json.
- Dedup persis: bingkai 6 kelas dibangun ulang dari data/raw (hanya dibaca; MD5 diverifikasi) dengan fungsi pipeline
  src/data seperti src/data/prepare.py. Paritas: dedup isi resmi -> batas templat RFI -> split harus menghasilkan id
  srbh_train/val/test.parquet dan baris RFI_TEMPLATE_CAP srbh_excluded.parquet persis. Kontrafaktual: dedup pada raw_log
  utuh (dengan stempel waktu) -> batas templat RFI -> split stratified baru dengan seed yang sama; kembaran isi = baris
  uji yang audit.content_key-nya (baris log tanpa stempel waktu) ada di train.
Laporan hanya memuat jumlah agregat, tanpa id per baris. † = nilai identik di ketiga run pada presisi yang ditampilkan.
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
from .revisi import FIRST, MCNEMAR_PAIRS, N_PAIRED, NAMES, ORDER, PAIRS, SHORT, _list_rates, _n, _p, _table, cell
from .revisi import collect, mcnemar_pairs, paired_bootstrap, paired_permutation

PILOT_IDS = RESULTS_DIR / "archive" / "pilot" / "pilot_ids.json"
REGEX_RUN = RESULTS_DIR / "regex.run.json"
WS_SUBTYPES = {"V1": "Non-standard methods", "W1": "Scanner user agent", "P1": "Backup/forbidden extensions",
               "T3": "VCS or forbidden files"}
SQL_FAMILIES = (gate_sqli._SQLMAP, gate_sqli._ZAP_SQL, gate_sqli._SQL_OTHER)  # famili aturan gerbang S1
CARRIERS = ("path", "query", "user_agent", "referer")
PATH_VARIABLES = ("REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_LINE")
LABEL_NAMES = (*CLASSES, "invalid")  # indeks OTHER = keluaran di luar 6 kelas
LAYERS = {"regex": "Cascade: regex → single LLM", "regex_full": "Cascade: full regex (post hoc) → single LLM",
          "regex_930": "Sensitivity: regex with restricted files → PATH_TRAVERSAL (CRS 930 default) → single LLM"}
CASCADE_SHORT = {"regex": "Cascade (regex → single LLM)", "regex_full": "Cascade (full regex → single LLM)",
                 "regex_930": "Sensitivity cascade (restricted files → PATH_TRAVERSAL)"}
SECOND = {**SHORT, "regex_930": "regex with restricted files → PATH_TRAVERSAL"}


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
    return {"biner_accuracy": b["accuracy"], "biner_precision": b["precision"], "biner_recall": b["recall"],
            "biner_f1": b["f1"], "biner_fpr": b["fpr"],
            "biner_fpr_tanpa_invalid": float((p[valid_normal] != normal).mean()) if valid_normal.any() else None,
            "accuracy": m["accuracy"], "macro_precision": m["macro_precision"], "macro_recall": m["macro_recall"],
            "macro_f1": m["macro_f1"],
            **{f"f1_{c}": m["per_class"][c]["f1"] for c in CLASSES},
            **{f"recall_{c}": m["per_class"][c]["recall"] for c in CLASSES}}


def paired(t: np.ndarray, a: list[np.ndarray], b: list[np.ndarray], clusters: list[str], n: int) -> dict:
    boot = paired_bootstrap(t, a, b, clusters, n)
    perm = paired_permutation(t, a, b, clusters, n)
    return {**boot, "p_permutasi": perm["p"], "n_permutasi": perm["n_permutasi"]}


def _label(label: str) -> str:
    return label if label in CLASSES else "invalid"


# ------------------------------------------------------------------------------------------------- analisis


def without_pilot(truth: Truth, data: dict, n_paired: int = N_PAIRED, pilot_path: Path = PILOT_IDS) -> dict:
    pilot = set(json.loads(pilot_path.read_text(encoding="utf-8"))["ids"])
    if not pilot <= set(truth.labels):
        raise ValueError(f"{pilot_path.name}: {len(pilot - set(truth.labels))} id pilot tidak ada di sampel")
    sub = subset(truth, set(truth.labels) - pilot)
    ids, t, clusters, preds = arrays(sub, data)
    _, t_pilot, _, preds_pilot = arrays(subset(truth, pilot), data)
    methods = {}
    for name, entry in data.items():
        per_run = [scores(t, p) for p in preds[name]]
        out = {k: summarize([r[k] for r in per_run]) for k in per_run[0]}
        literal = [evidence_literal(m, sub) for m in entry["methods"]]
        if all(literal):
            out["evidence_literal"] = summarize([x["proportion"] for x in literal])
        out["ik_macro_f1"] = bootstrap_mean_macro_f1(t, preds[name], clusters)
        out["macro_f1_500"] = entry["group"]["metrics"]["macro_f1"]
        out["akurasi_pilot"] = summarize([float((p == t_pilot).mean()) for p in preds_pilot[name]])
        methods[name] = out
    pairs = [(a, b) for a, b in PAIRS if a in preds and b in preds]
    _, t_all, clusters_all, preds_all = arrays(truth, data)
    return {"berkas_pilot": str(pilot_path.relative_to(ROOT)) if pilot_path.is_relative_to(ROOT) else str(pilot_path),
            "pilot": len(pilot), "pilot_per_kelas": {c: sum(truth.labels[i] == c for i in pilot) for c in CLASSES},
            "n": len(ids), "per_kelas": {c: sum(sub.labels[i] == c for i in ids) for c in CLASSES},
            "metode": methods,
            "uji_berpasangan": [{"a": a, "b": b, **paired(t, preds[a], preds[b], clusters, n_paired)} for a, b in pairs],
            "uji_berpasangan_500": [{"a": a, "b": b, **paired(t_all, preds_all[a], preds_all[b], clusters_all, n_paired)}
                                    for a, b in pairs],
            "mcnemar": [{"a": a, "b": b, "pasangan": mcnemar_pairs(t, preds[a], preds[b])} for a, b in MCNEMAR_PAIRS
                        if a in preds and b in preds]}


def regex_labels(rows: list[dict], config: dict, restricted_as_category: bool = False) -> dict[str, str]:
    """Label regex dari matched_rules seperti regex_baseline.classify: skor kelas = jumlah poin hit, seri dipecah
    tie_break, NORMAL bila tidak ada skor. restricted_as_category: hit CRS pada aturan restricted_files memakai kelas
    bawaan kategorinya (class_map), bukan WEB_SCANNING."""
    from ..baselines.regex_baseline import ATTACK_CLASSES

    special = {str(r) for r in config["restricted_files"]["rules"]}
    order = config["scoring"]["tie_break"]
    out = {}
    for row in rows:
        score = dict.fromkeys(ATTACK_CLASSES, 0)
        for hit in row["matched_rules"]:
            crs = str(hit.get("source", "")).startswith("CRS")
            label = config["class_map"][hit["rule"][:3]] if restricted_as_category and crs and hit["rule"] in special else hit["class"]
            score[label] += hit["points"]
        out[row["id"]] = (max(ATTACK_CLASSES, key=lambda c: (score[c], -order.index(c))) if any(score.values())
                          else "NORMAL")
    return out


def _first_layers(data: dict) -> dict[str, dict[str, str]]:
    from ..baselines.regex_baseline import load_config

    layers = {name: data[name]["methods"][0].predictions for name in ("regex", "regex_full") if name in data}
    rows = data["regex"]["methods"][0].rows if "regex" in data else []
    if rows and all("matched_rules" in r for r in rows):
        config = load_config()
        if regex_labels(rows, config) != layers["regex"]:
            raise RuntimeError("label regex hasil rekonstruksi dari matched_rules tidak sama dengan results/regex.jsonl")
        layers["regex_930"] = regex_labels(rows, config, restricted_as_category=True)
    return layers


def ws_groups(truth: Truth) -> dict[str, list[str]]:
    ids = [i for i in truth.labels if truth.labels[i] == "WEB_SCANNING"]
    rule = {i: str(truth.template_keys[i]).split(":")[0] for i in ids}
    unknown = sorted(set(rule.values()) - set(WS_SUBTYPES))
    if unknown:
        raise ValueError(f"sub-tipe WEB_SCANNING tanpa nama: {unknown}")
    return {r: [i for i in ids if rule[i] == r] for r in WS_SUBTYPES}


def cascade(truth: Truth, data: dict, n_paired: int = N_PAIRED) -> dict:
    if "llm_single" not in data:
        return {}
    ids, t, clusters, preds = arrays(truth, data)
    gold = [truth.labels[i] for i in ids]
    groups = ws_groups(truth)
    rate_in, rate_out = _list_rates()
    out = {"llm_single_biaya_per_1000_baris_usd": data["llm_single"]["group"]["metrics"]["biaya_per_1000_baris_usd"],
           "lapis_pertama": {}}
    for first, layer in _first_layers(data).items():
        sent = {i for i in ids if layer[i] == "NORMAL"}
        runs, billed, listed = [], [], []
        for m in data["llm_single"]["methods"]:
            runs.append({i: m.predictions[i] if i in sent else layer[i] for i in ids})
            rows = [r for r in m.rows if r["id"] in sent]
            billed.append(1000 * sum(r["cost_usd"] for r in rows) / len(ids))
            listed.append(1000 * sum(r["prompt_tokens"] * rate_in + r["completion_tokens"] * rate_out for r in rows)
                          / 1e6 / len(ids))
        arrays_ = [_indices(gold, [p[i] for i in ids])[1] for p in runs]
        per_run = [scores(t, p) for p in arrays_]
        layer_array = [_indices(gold, [layer[i] for i in ids])[1]]
        out["lapis_pertama"][first] = {
            "baris_ke_llm": len(sent),
            "baris_ke_llm_per_kelas": {c: sum(truth.labels[i] == c for i in sent) for c in CLASSES},
            "baris_ke_llm_dipulihkan_per_kelas": {
                c: summarize([sum(p[i] == c for i in sent if truth.labels[i] == c) for p in runs]) for c in CLASSES},
            "metrik": {k: summarize([r[k] for r in per_run]) for k in per_run[0]},
            "ik_macro_f1": bootstrap_mean_macro_f1(t, arrays_, clusters),
            "recall_sub_tipe_ws": {r: summarize([sum(p[i] == "WEB_SCANNING" for i in g) / len(g) for p in runs])
                                   for r, g in groups.items() if g},
            "biaya_per_1000_baris_usd": summarize(billed),
            "biaya_list_per_1000_baris_usd": summarize(listed),
            "uji_berpasangan": [{"b": b, **paired(t, arrays_, other, clusters, n_paired)}
                                for b, other in (("llm_single", preds["llm_single"]), (first, layer_array))],
        }
    return out


def _ws_rules(row: dict) -> set[str]:
    return {hit["rule"] for hit in row.get("matched_rules") or [] if hit["class"] == "WEB_SCANNING"}


def ws_subtypes(truth: Truth, data: dict, inputs: list[dict] | None = None) -> dict:
    groups = ws_groups(truth)
    rows = {r["id"]: r for r in inputs or []}

    def detail(i: str) -> str:
        key = str(truth.template_keys[i])
        if key.endswith(":lainnya") and i in rows:  # T3 selain .git/.svn: nama berkas di path
            return key.split(":")[0] + ":" + multi_decode(rows[i]["path"]).rstrip("/").rsplit("/", 1)[-1]
        return key

    details = {r: Counter(detail(i) for i in g) for r, g in groups.items()}
    out = {"n": {r: len(g) for r, g in groups.items()},
           "rincian": {r: dict(c.most_common()) for r, c in details.items()},
           "metode": {}, "recall_per_rincian": {}, "aturan_regex": {}}
    for name, entry in data.items():
        runs = entry["methods"]
        out["metode"][name] = {
            r: {"recall": summarize([sum(m.predictions[i] == "WEB_SCANNING" for i in g) / len(g) for m in runs]),
                "prediksi_rerata": {k: v / len(runs) for k, v in
                                    Counter(_label(m.predictions[i]) for m in runs for i in g).most_common()}}
            for r, g in groups.items() if g}
        out["recall_per_rincian"][name] = {
            d: summarize([sum(m.predictions[i] == "WEB_SCANNING" for i in g if detail(i) == d) / n for m in runs])
            for r, g in groups.items() for d, n in details[r].most_common()}
        if name in ("regex", "regex_full"):
            by_id = {x["id"]: x for x in runs[0].rows}
            out["aturan_regex"][name] = {r: dict(Counter(h for i in g for h in _ws_rules(by_id[i])).most_common())
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
            "melibatkan_invalid": sum(OTHER in s for s in seen),
            "antar_kelas_valid": sum(OTHER not in s for s in seen),
            "himpunan_label": dict(Counter(" / ".join(LABEL_NAMES[k] for k in sorted(s)) for s in seen).most_common()),
        }
    return out


def sql_carriers(row: dict) -> set[str]:
    """Field tempat famili sintaks SQL aturan gerbang S1 cocok (setelah multi_decode), diperiksa per field."""
    return {c for c in CARRIERS if any(f.search(multi_decode(row.get(c) or "")) for f in SQL_FAMILIES)}


def sqli_rules_on_path(run_path: Path = REGEX_RUN) -> dict | None:
    """Aturan 942 terpakai di konfigurasi regex utama yang target link pertamanya memuat variabel path; dibaca dari
    berkas aturan CRS yang sudah diekstrak (tanpa unduhan). None bila folder aturan belum ada (make regex)."""
    from ..baselines.crs import EXTERNAL_DIR, load_rules, tree_digest
    from ..baselines.modsec import is_applicable
    from ..baselines.regex_baseline import load_config, mapped_class

    config = load_config()
    crs = config["crs"]
    rules_dir = EXTERNAL_DIR / f"coreruleset-{crs['version']}" / "rules"
    if not rules_dir.is_dir():
        return None
    summary = json.loads(run_path.read_text(encoding="utf-8"))["ruleset"]
    if tree_digest(rules_dir) != summary["rules_dir_sha256"]:
        raise RuntimeError(f"{rules_dir} berbeda dari aturan yang dipakai {run_path.name} (rules_dir_sha256)")
    excluded = set(crs["excluded_operators"])
    rules = [r for r in load_rules(rules_dir, ["942"])[0]
             if r.paranoia <= int(crs["paranoia_level"]) and mapped_class(r, config) is not None
             and not any(link.operator in excluded for link in r.links) and all(is_applicable(link) for link in r.links)]
    if len(rules) != summary["used_by_category"]["942"]:
        raise RuntimeError(f"aturan 942 terpakai {len(rules)} != {summary['used_by_category']['942']} di {run_path.name}")
    on_path = [r.id for r in rules if any(t.collection.upper() in PATH_VARIABLES and not (t.exclude or t.count)
                                          for t in r.links[0].targets)]
    return {"aturan_942_dipakai": len(rules), "memeriksa_path": sorted(on_path), "variabel_path": list(PATH_VARIABLES)}


def sqli_missed(truth: Truth, data: dict, inputs: list[dict], rules_on_path: dict | None = None) -> dict:
    if "regex" not in data:
        return {}
    regex = data["regex"]["methods"][0]
    rows = {r["id"]: r for r in inputs}
    sqli = [i for i in truth.labels if truth.labels[i] == "SQLI"]
    missed = [i for i in sqli if regex.predictions[i] == "NORMAL"]
    where = {i: sql_carriers(rows[i]) for i in missed}
    query = {i: bool(rows[i]["query"]) for i in missed}
    count = lambda cond: sum(1 for i in missed if cond(i))  # noqa: E731
    hits = {r["id"]: {h["rule"] for h in r.get("matched_rules") or []} for r in regex.rows}
    caught = [i for i in sqli if regex.predictions[i] == "SQLI"]
    return {
        "sqli": len(sqli), "prediksi_regex": dict(Counter(regex.predictions[i] for i in sqli).most_common()),
        "terlewat": len(missed),
        "tanpa_query_string": count(lambda i: not query[i]),
        "payload_di_path": count(lambda i: "path" in where[i]),
        "payload_hanya_di_path": count(lambda i: where[i] == {"path"}),
        "payload_di_path_tanpa_query_string": count(lambda i: "path" in where[i] and not query[i]),
        "payload_di_path_query_string_tanpa_sql": count(lambda i: "path" in where[i] and query[i] and "query" not in where[i]),
        "payload_di_query_string": count(lambda i: "query" in where[i]),
        "payload_di_user_agent": count(lambda i: "user_agent" in where[i]),
        "payload_di_referer": count(lambda i: "referer" in where[i]),
        "tanpa_famili_s1": count(lambda i: not where[i]),
        "aturan_942_memeriksa_path": rules_on_path,
        "aturan_pada_sqli_terdeteksi": dict(Counter(h for i in caught for h in hits.get(i, ()) if h.startswith("942"))
                                            .most_common()),
        "baris_dengan_aturan_path": ({str(r): sum(str(r) in h for h in hits.values())
                                      for r in rules_on_path["memeriksa_path"]} if rules_on_path else None),
    }


def exact_dedup() -> dict:
    """Kontrafaktual dedup persis dari data/raw (hanya dibaca), dengan cek paritas terhadap split resmi."""
    import pandas as pd

    from ..data import audit
    from ..data.config import LABEL_MAPPING_SRC, PROCESSED_DIR, SRBH_CSV
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
    capped, _, cap_dropped = cap_rfi_templates(content, cap)
    for name, part in zip(("train", "val", "test"), stratified_split(capped)):
        if part["id"].tolist() != pd.read_parquet(split_path(name), columns=["id"])["id"].tolist():
            raise RuntimeError(f"paritas gagal: dedup isi -> batas RFI -> split tidak menghasilkan srbh_{name}.parquet")
    excluded = pd.read_parquet(PROCESSED_DIR / "srbh_excluded.parquet", columns=["id", "exclusion_reason"])
    if set(cap_dropped["id"]) != set(excluded.loc[excluded["exclusion_reason"] == "RFI_TEMPLATE_CAP", "id"]):
        raise RuntimeError("paritas gagal: baris yang dibuang batas templat RFI berbeda dari srbh_excluded.parquet")

    exact, exact_stats = dedup(six, key="raw_log")
    out = {"md5": md5, "baris_mentah": len(raw), "baris_6_kelas": len(six),
           "paritas": "srbh_train/val/test.parquet dan baris RFI_TEMPLATE_CAP srbh_excluded.parquet cocok",
           "dedup_isi": content_stats, "dedup_persis": exact_stats, "batas_templat_rfi": cap, "kontrafaktual": {}}
    for name, part in (("dengan_batas_rfi", cap_rfi_templates(exact, cap)[0]), ("tanpa_batas_rfi", exact)):
        train, _, test = stratified_split(part)
        twin = audit.content_key(test["raw_log"]).isin(set(audit.content_key(train["raw_log"])))
        attack = (test["label"] != "NORMAL").to_numpy()
        out["kontrafaktual"][name] = {
            "train": len(train), "uji": len(test), "uji_berkembaran": int(twin.sum()), "persen": 100 * float(twin.mean()),
            "persen_normal": 100 * float(twin[~attack].mean()), "persen_serangan": 100 * float(twin[attack].mean()),
            "per_kelas": {c: [int(twin[(test["label"] == c).to_numpy()].sum()), int((test["label"] == c).sum())]
                          for c in CLASSES}}
    return out


def build(truth: Truth, data: dict, inputs: list[dict], n_paired: int = N_PAIRED, dedup: bool = True) -> dict:
    return {"tanpa_pilot": without_pilot(truth, data, n_paired), "kaskade": cascade(truth, data, n_paired),
            "sub_tipe_web_scanning": ws_subtypes(truth, data, inputs),
            "label_berubah_antar_run": label_changes(truth, data),
            "sqli_terlewat_regex": sqli_missed(truth, data, inputs, sqli_rules_on_path()),
            "dedup_persis": exact_dedup() if dedup else {"dilewati": "opsi --tanpa-dedup"}}


# ------------------------------------------------------------------------------------------------- tampilan


def _ci(x: dict) -> str:
    return f"[{_n(x['ik_bawah'])}, {_n(x['ik_atas'])}]"


def _comparison(first: str, second: str, x: dict) -> list[str]:
    return [f"{first} − {second}", _n(x["selisih"]), _ci(x), _p(x["p"]), _p(x["p_permutasi"])]


def _counts(values: dict, keys) -> str:
    return ", ".join(f"{k} {values[k]}" for k in keys if values.get(k))


def _cell(stat: dict | None, digits: int = 3) -> str:
    runs = len(stat["values"]) if stat and stat.get("values") else 1
    return cell(stat, digits, runs=runs, dagger=True)


PAIRED_HEADER = ["Comparison (A − B)", "Difference", "95% CI", "p, bootstrap", "p, permutation"]


def _section_pilot(x: dict) -> list[str]:
    names = [n for n in ORDER if n in x["metode"]]
    m = x["metode"]
    out = [f"## 1. Tanpa {x['pilot']} baris pilot ({x['n']} baris)", "",
           f"Pilot: `{x['berkas_pilot']}` ({_counts(x['pilot_per_kelas'], CLASSES)}). Sisa {x['n']} baris: "
           f"{_counts(x['per_kelas'], CLASSES)}.", "", f"Tabel 4 pada {x['n']} baris:", ""]
    keys = ("biner_accuracy", "biner_precision", "biner_recall", "biner_f1", "biner_fpr", "biner_fpr_tanpa_invalid")
    out.append(_table(["Method", "Accuracy", "Precision", "Recall", "F1", "FPR", "FPR excl. invalid"],
                      [[NAMES[n], *(_cell(m[n][k]) for k in keys)] for n in names]))
    out += ["", f"Tabel 5 dan literal evidence pada {x['n']} baris (IK: bootstrap templat 1,000 draw, definisi Tabel 5):", ""]
    out.append(_table(["Method", "Accuracy", "Macro-P", "Macro-R", f"Macro-F1 ({x['n']})", "95% CI", "Macro-F1 (500)",
                       "Literal items"],
                      [[NAMES[n], *(_cell(m[n][k]) for k in ("accuracy", "macro_precision", "macro_recall", "macro_f1")),
                        f"[{_n(m[n]['ik_macro_f1']['low'])}, {_n(m[n]['ik_macro_f1']['high'])}]",
                        _cell(m[n]["macro_f1_500"]), _cell(m[n].get("evidence_literal"))] for n in names]))
    out += ["", f"F1 per kelas pada {x['n']} baris:", ""]
    out.append(_table(["Method", "SQLI", "XSS", "PT", "CMD", "WS", "NORMAL"],
                      [[NAMES[n], *(_cell(m[n][f"f1_{c}"]) for c in CLASSES)] for n in names]))
    tests = x["uji_berpasangan"]
    if tests:
        full = {(y["a"], y["b"]): y for y in x["uji_berpasangan_500"]}
        out += ["", f"Uji berpasangan ({tests[0]['n_draw']:,} draw; definisi Tabel 6) pada {x['n']} baris, dengan 500 baris "
                    "sebagai pembanding:", ""]
        out.append(_table(["Comparison (A − B)", f"Difference ({x['n']})", "95% CI", "p, bootstrap / permutation",
                           "Difference (500)", "95% CI (500)", "p (500), bootstrap / permutation"],
                          [[f"{FIRST[y['a']]} − {SHORT[y['b']]}", _n(y["selisih"]), _ci(y),
                            f"{_p(y['p'])} / {_p(y['p_permutasi'])}", _n(z["selisih"]), _ci(z),
                            f"{_p(z['p'])} / {_p(z['p_permutasi'])}"]
                           for y in tests for z in [full[(y["a"], y["b"])]]]))
    if x["mcnemar"]:
        out += ["", f"McNemar eksak pada {x['n']} baris per pasangan run berindeks sama:", ""]
        out.append(_table(["A − B", "run", "A benar, B salah", "B benar, A salah", "p eksak"],
                          [[f"{SHORT[y['a']]} − {SHORT[y['b']]}", f"r{q['run']}–r{q['run']}", str(q["a_benar_b_salah"]),
                            str(q["b_benar_a_salah"]), f"{q['p']:.2e}"] for y in x["mcnemar"] for q in y["pasangan"]]))
    out += ["", f"Akurasi 6 kelas pada {x['pilot']} baris pilot vs {x['n']} baris lain (baris pilot lebih mudah bila "
                "akurasinya lebih tinggi):", ""]
    out.append(_table(["Method", f"Pilot ({x['pilot']})", f"Lain ({x['n']})"],
                      [[NAMES[n], _cell(m[n]["akurasi_pilot"]), _cell(m[n]["accuracy"])] for n in names]))
    return out


def _section_cascade(x: dict) -> list[str]:
    layers = x["lapis_pertama"]
    out = ["## 2. Kaskade §3.6 (post hoc): baris NORMAL menurut regex diteruskan ke LLM tunggal", ""]
    out.append(_table(["Configuration", "Lines sent to the LLM", "Macro-F1", "95% CI", "Binary F1", "FPR",
                       "FPR excl. invalid", "USD per 1,000 lines, billed", "USD per 1,000 lines, list price"],
                      [[LAYERS[first], str(y["baris_ke_llm"]), _cell(y["metrik"]["macro_f1"]),
                        f"[{_n(y['ik_macro_f1']['low'])}, {_n(y['ik_macro_f1']['high'])}]", _cell(y["metrik"]["biner_f1"]),
                        _cell(y["metrik"]["biner_fpr"]), _cell(y["metrik"]["biner_fpr_tanpa_invalid"]),
                        _cell(y["biaya_per_1000_baris_usd"]), _cell(y["biaya_list_per_1000_baris_usd"])]
                       for first, y in layers.items()]))
    out += ["", f"Pembanding: LLM tunggal sendiri {_cell(x['llm_single_biaya_per_1000_baris_usd'])} USD per 1,000 baris "
                "(billed). FPR kaskade = FPR LLM tunggal bila lapis pertama tidak menandai satu pun baris NORMAL.", "",
            "Baris yang diteruskan ke LLM per kelas gerbang, dan yang diberi kelas gerbangnya oleh LLM (rerata run):", ""]
    out.append(_table(["Configuration", *CLASSES],
                      [[LAYERS[first], *(f"{_cell(y['baris_ke_llm_dipulihkan_per_kelas'][c], 1)} / "
                                         f"{y['baris_ke_llm_per_kelas'][c]}" for c in CLASSES)]
                       for first, y in layers.items()]))
    out += ["", "F1 dan recall per kelas kaskade:", ""]
    out.append(_table(["Configuration", "Metric", *CLASSES],
                      [[LAYERS[first], metric, *(_cell(y["metrik"][f"{key}_{c}"]) for c in CLASSES)]
                       for first, y in layers.items() for metric, key in (("F1", "f1"), ("Recall", "recall"))]))
    out += ["", "Recall WEB_SCANNING per sub-tipe kaskade:", ""]
    subtypes = [r for r in WS_SUBTYPES if any(r in y["recall_sub_tipe_ws"] for y in layers.values())]
    out.append(_table(["Configuration", *(f"{WS_SUBTYPES[r]} ({r})" for r in subtypes)],
                      [[LAYERS[first], *(_cell(y["recall_sub_tipe_ws"].get(r), 2) for r in subtypes)]
                       for first, y in layers.items()]))
    out += ["", f"Uji berpasangan ({next(iter(layers.values()))['uji_berpasangan'][0]['n_draw']:,} draw; definisi "
                "Tabel 6):" if layers else "", ""]
    out.append(_table(PAIRED_HEADER, [_comparison(CASCADE_SHORT[first], SECOND[z["b"]], z)
                                      for first, y in layers.items() for z in y["uji_berpasangan"]]))
    return out


def _section_ws(x: dict) -> list[str]:
    names = [n for n in ORDER if n in x["metode"]]
    present = [r for r in WS_SUBTYPES if x["n"][r]]
    out = ["## 3. Recall WEB_SCANNING per sub-tipe (aturan gerbang)", ""]
    out.append(_table(["Sub-type (gate rule)", "Lines", *(NAMES[n] for n in names)],
                      [[f"{WS_SUBTYPES[r]} ({r})", str(x["n"][r]), *(_cell(x["metode"][n][r]["recall"], 2) for n in names)]
                       for r in present]))
    out += ["", "Recall per template_key (T3:lainnya dirinci menurut nama berkas):", ""]
    out.append(_table(["Template", "Lines", *(NAMES[n] for n in names)],
                      [[d, str(k), *(_cell(x["recall_per_rincian"][n][d], 2) for n in names)]
                       for r in present for d, k in x["rincian"][r].items()]))
    out += ["", "Prediksi pada baris sub-tipe (rerata per run):", ""]
    out += [f"- {NAMES[n]}: " + "; ".join(
        f"{r} " + ", ".join(f"{k} {v:.1f}" for k, v in x["metode"][n][r]["prediksi_rerata"].items()) for r in present)
        for n in names]
    out += ["", "Aturan regex berkelas WEB_SCANNING yang cocok (jumlah baris per aturan):", ""]
    out += [f"- {NAMES[n]}: " + "; ".join(f"{r} " + (", ".join(f"{k} {v}" for k, v in rules.items()) or "tidak ada")
                                          for r, rules in x["aturan_regex"][n].items() if x["n"][r])
            for n in ORDER if n in x["aturan_regex"]]
    return out


def _section_changes(x: dict) -> list[str]:
    names = [n for n in ORDER if n in x]
    out = ["## 4. Label berubah antar run, menurut kelas gerbang", ""]
    out.append(_table(["Method", "Lines", *CLASSES, "With an invalid output", "Between valid classes only"],
                      [[NAMES[n], str(x[n]["baris"]), *(str(x[n]["per_kelas_gerbang"][c]) for c in CLASSES),
                        str(x[n]["melibatkan_invalid"]), str(x[n]["antar_kelas_valid"])] for n in names]))
    out += ["", "Baris berubah yang memuat label tertentu di salah satu run (satu baris bisa dihitung di lebih dari satu "
                "label):", ""]
    out.append(_table(["Method", *LABEL_NAMES], [[NAMES[n], *(str(x[n]["memuat_label"][c]) for c in LABEL_NAMES)]
                                                 for n in names]))
    out += ["", "Himpunan label yang muncul di ketiga run:", ""]
    out += [f"- {NAMES[n]}: " + ", ".join(f"{k} {v}" for k, v in x[n]["himpunan_label"].items()) for n in names]
    return out


def _section_sqli(x: dict) -> list[str]:
    out = ["## 5. SQLI yang terlewat regex utama: letak payload", "",
           f"- SQLI di sampel: {x['sqli']}; prediksi regex utama: "
           + ", ".join(f"{k} {v}" for k, v in x["prediksi_regex"].items()) + f". Terlewat (NORMAL): {x['terlewat']}.",
           f"- Payload SQL (famili S1 gerbang) di path: **{x['payload_di_path']} dari {x['terlewat']}** (hanya di path: "
           f"{x['payload_hanya_di_path']}; tanpa query string: {x['payload_di_path_tanpa_query_string']}; dengan query "
           f"string tanpa payload SQL: {x['payload_di_path_query_string_tanpa_sql']}).",
           f"- Tanpa query string sama sekali: {x['tanpa_query_string']} dari {x['terlewat']}.",
           f"- Payload di query string: {x['payload_di_query_string']}; di User-Agent: {x['payload_di_user_agent']}; "
           f"di Referer: {x['payload_di_referer']}; tanpa famili S1 terlihat: {x['tanpa_famili_s1']}."]
    rules = x["aturan_942_memeriksa_path"]
    if rules:
        fired = ", ".join(f"{k} {v}" for k, v in x["baris_dengan_aturan_path"].items())
        out.append(f"- Aturan 942 terpakai (PL1, regex) di konfigurasi utama: {rules['aturan_942_dipakai']}; yang "
                   f"memeriksa path ({', '.join(rules['variabel_path'])}): {', '.join(map(str, rules['memeriksa_path']))}"
                   f" (jumlah baris dari 500 yang memicunya: {fired}).")
    else:
        out.append("- Aturan 942 yang memeriksa path: dilewati (aturan CRS belum diekstrak; jalankan make regex).")
    out.append("- Aturan 942 pada baris SQLI yang diprediksi SQLI (jumlah baris): "
               + (", ".join(f"{k} {v}" for k, v in x["aturan_pada_sqli_terdeteksi"].items()) or "tidak ada") + ".")
    return out


def _section_dedup(x: dict) -> list[str]:
    out = ["## 6. Dedup persis vs dedup isi (kontrafaktual dari data/raw)", ""]
    if "dilewati" in x:
        return out + [f"Dilewati: {x['dilewati']}."]
    d, c = x["dedup_persis"], x["dedup_isi"]
    out += [f"- Bingkai 6 kelas dibangun ulang dari data/raw (MD5 `{x['md5']}`): {x['baris_6_kelas']:,} baris dari "
            f"{x['baris_mentah']:,}. Paritas: {x['paritas']}.",
            f"- Dedup isi (resmi, kunci raw_log_masked = baris log tanpa stempel waktu dan protokol): dibuang "
            f"{c['duplicates_dropped'] + c['conflict_rows_dropped']:,} (konflik label {c['conflict_rows_dropped']:,}), "
            f"sisa {c['rows_out']:,}.",
            f"- Dedup persis (raw_log utuh dengan stempel waktu): dibuang **{d['duplicates_dropped'] + d['conflict_rows_dropped']:,}** "
            f"(konflik label {d['conflict_rows_dropped']:,}), sisa {d['rows_out']:,}; per kelas: "
            + ", ".join(f"{k} {v:,}" for k, v in d["duplicates_dropped_by_class"].items()) + "."]
    for name, title in (("dengan_batas_rfi", f"dedup persis -> batas templat RFI ({x['batas_templat_rfi']}) -> split"),
                        ("tanpa_batas_rfi", "dedup persis -> split (tanpa batas templat RFI)")):
        y = x["kontrafaktual"][name]
        out.append(f"- Kontrafaktual {title} (split baru: train {y['train']:,}, uji {y['uji']:,}): baris uji yang punya "
                   f"kembaran isi (kunci audit.content_key = baris log tanpa stempel waktu) di train **{y['uji_berkembaran']:,} "
                   f"dari {y['uji']:,} ({_n(y['persen'], 2)}%)**; NORMAL {_n(y['persen_normal'], 1)}%, kelas serangan "
                   f"{_n(y['persen_serangan'], 1)}%; per kelas: "
                   + ", ".join(f"{k} {a:,}/{b:,}" for k, (a, b) in y["per_kelas"].items()) + ".")
    return out


def render(result: dict) -> str:
    out = ["Format angka mengikuti manuskrip (titik desimal; metode LLM: rerata tiga run dengan rentang min–maks; † = "
           "identik di ketiga run pada presisi yang ditampilkan). Definisi: docstring src/eval/revisi_tambahan.py. Laporan "
           "hanya memuat jumlah agregat (tanpa id per baris).", ""]
    out += _section_pilot(result["tanpa_pilot"]) + [""]
    if result["kaskade"]:
        out += _section_cascade(result["kaskade"]) + [""]
    out += _section_ws(result["sub_tipe_web_scanning"]) + [""]
    out += _section_changes(result["label_berubah_antar_run"]) + [""]
    if result["sqli_terlewat_regex"]:
        out += _section_sqli(result["sqli_terlewat_regex"]) + [""]
    out += _section_dedup(result["dedup_persis"])
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
