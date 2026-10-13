"""Laporan revisi jurnal (keputusan penulis 2026-10-13): semua angka Tabel 4-11 manuskrip untuk kelima metode, termasuk
ablasi LLM tunggal + loop verifikasi (src/baselines/llm_single_verified.py), ditata per nomor tabel manuskrip dengan
format angka manuskrip (titik desimal) -> reports/revisi_ablasi.md (+ .json). Dijalankan oleh make eval.

Definisi (angka C/E manuskrip revisi_v2 untuk Tabel 4, 6, 9, 10, dan 11 kolom 1-2 tereproduksi persis dengan definisi ini):
- Tabel 4: metrik biner seperti evaluate.binary (keluaran invalid = FN pada baris serangan, FP pada baris NORMAL); FPR
  tanpa invalid = FP / (FP + TN) setelah baris NORMAL berkeluaran di luar 6 kelas dibuang.
- Tabel 5: seperti replikasi.aggregate (IK bootstrap klaster 1.000 draw, random_state 42, draw sama untuk ketiga run).
- Tabel 6: selisih macro-F1 rerata run (A - B). Bootstrap klaster berpasangan 10.000 draw: default_rng(42), templat
  diresampel di dalam tiap kelas sebenarnya (urutan kelas CLASSES, templat urut kunci), indeks sama untuk kedua metode;
  IK = persentil 2,5/97,5; p = 2 x porsi terkecil selisih di sisi <= 0 atau >= 0. Permutasi berpasangan tingkat templat
  10.000 kali: default_rng(42), templat diurut menurut kunci "kelas|template_key", prediksi kedua metode ditukar per
  templat bila rng.random() < 0,5 (metode satu run diulang menjadi run berpasangan), p = porsi |selisih permutasi| >=
  |selisih teramati|. McNemar eksak (binomial dua sisi) per pasangan run berindeks sama (r1-r1, r2-r2, r3-r3).
- Tabel 9: billed = cost_usd OpenRouter per baris; harga list = semua token masuk dan keluar dengan tarif input/output
  configs/llm.yaml (tanpa diskon cache); persentase ter-cache = cached_tokens / prompt_tokens pada log panggilan run
  (tanpa panggilan yang dibatalkan galat API, seperti latensi per panggilan).
- Tabel 11: literal = evaluate.evidence_literal; keluaran pertama: metode dengan verifikasi (deep agent, ablasi) = porsi
  baris terverifikasi yang klasifikasi pertamanya lolos verifikasi, LLM tunggal = porsi baris yang semua item
  evidence-nya literal; class-consistent = item evidence (setelah decode) memuat pola kelas prediksi dari
  configs/leksikon_kelas.yaml (bagian utama; utama + tambahan_kb sebagai sensitivitas), dihitung pada prediksi serangan.
- Dekomposisi §3.4: selisih agent - LLM tunggal = (ablasi - LLM tunggal, bagian loop) + (agent - ablasi, bagian
  orkestrasi), dalam poin dan persen selisih total.
Jalankan: make eval  (atau python -m src.eval.revisi --out reports/revisi_ablasi.md)
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from functools import lru_cache
from pathlib import Path

import numpy as np
import yaml
from scipy.stats import binomtest

from ..common.evidence import decoded_forms, evidence_exists
from ..common.runinfo import run_info
from ..data.config import CLASSES, RANDOM_STATE, ROOT
from .evaluate import K, RESULTS_DIR, _indices, load_method, load_truth, macro_f1
from .replikasi import (
    EXPECTED_RUNS,
    GROUPS,
    SINGLE_RUN,
    aggregate,
    call_records,
    check_complete,
    check_consistent,
    group_files,
    summarize,
)

LEXICON_PATH = ROOT / "configs" / "leksikon_kelas.yaml"
LLM_CONFIG = ROOT / "configs" / "llm.yaml"
N_PAIRED = 10_000
ATTACK = tuple(c for c in CLASSES if c != "NORMAL")
CLASS_SET = set(CLASSES)
ORDER = ("regex", "regex_full", "llm_single", "agent", "llm_single_verified")
NAMES = {"regex": "Regex (CRS PL1, 6 categories)", "regex_full": "Full regex (all categories; post hoc)",
         "llm_single": "Single LLM (zero-shot)", "agent": "Deep agent",
         "llm_single_verified": "Single LLM + verifier loop (ablation)"}
SHORT = {"regex": "regex", "regex_full": "full regex (post hoc)", "llm_single": "single LLM", "agent": "deep agent",
         "llm_single_verified": "ablation"}  # nama di Tabel 6 manuskrip, sebagai suku kedua
FIRST = {"regex": "Regex", "regex_full": "Full regex (post hoc)", "llm_single": "Single LLM", "agent": "Deep agent",
         "llm_single_verified": "Ablation"}  # sebagai suku pertama
PAIRS = (("llm_single", "agent"), ("llm_single", "regex"), ("agent", "regex"), ("llm_single", "regex_full"),
         ("agent", "regex_full"), ("llm_single_verified", "llm_single"), ("llm_single_verified", "agent"))
MCNEMAR_PAIRS = (("llm_single", "agent"), ("llm_single_verified", "llm_single"), ("llm_single_verified", "agent"))


# ------------------------------------------------------------------------------------------------- leksikon


@lru_cache(maxsize=4)
def load_lexicon(path: Path = LEXICON_PATH, with_kb: bool = False) -> dict[str, tuple[re.Pattern, ...]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = {}
    for label in ATTACK:
        patterns = list(data["utama"][label]) + (list(data["tambahan_kb"].get(label) or []) if with_kb else [])
        out[label] = tuple(re.compile(p, re.IGNORECASE) for p in patterns)
    return out


def class_consistent(item: str, label: str, lexicon: dict) -> bool:
    """Apakah item evidence (setelah decode) memuat indikator kelas `label` dari leksikon."""
    patterns = lexicon.get(label, ())
    return any(p.search(form) for form in decoded_forms(item.strip()) for p in patterns)


# ------------------------------------------------------------------------------------------------- metrik per run


def _list_rates() -> tuple[float, float]:
    pricing = yaml.safe_load(LLM_CONFIG.read_text(encoding="utf-8"))["pricing_usd_per_1m_tokens"]
    return float(pricing["input"]), float(pricing["output"])


def extra_metrics(method, truth, lexicons: dict[str, dict]) -> dict:
    """Metrik revisi satu run (pelengkap replikasi.run_metrics)."""
    rows = [r for r in method.rows if r["id"] in truth.labels]
    out = {}
    normal_valid = [r for r in rows if truth.labels[r["id"]] == "NORMAL" and r["label"] in CLASS_SET]
    out["biner_fpr_tanpa_invalid"] = (sum(r["label"] != "NORMAL" for r in normal_valid) / len(normal_valid)
                                      if normal_valid else None)
    out["parse_error"] = sum(r.get("label") == "PARSE_ERROR" or r.get("status") == "PARSE_ERROR" for r in rows)
    if rows and "prompt_tokens" in rows[0]:
        rate_in, rate_out = _list_rates()
        out["biaya_list_per_1000_baris_usd"] = 1000 * statistics.mean(
            (r["prompt_tokens"] * rate_in + r["completion_tokens"] * rate_out) / 1e6 for r in rows)
        used, _ = call_records(method)
        prompt = sum(r.get("prompt_tokens") or 0 for r in used)
        if prompt:
            out["token_cache_persen"] = 100 * sum(r.get("cached_tokens") or 0 for r in used) / prompt
        out["truncated_kejadian"] = sum(r.get("truncated_calls", 0) for r in rows)
        out["truncated_baris"] = sum(r.get("truncated_calls", 0) > 0 for r in rows)
    if rows and "evidence" in rows[0]:
        if "verifikasi" in rows[0]:
            verified = [r for r in rows if r["verifikasi"]["putusan"]]
            out["keluaran_pertama_lolos"] = (sum(r["verifikasi"]["putusan"][0]["lolos"] for r in verified) / len(verified)
                                            if verified else None)
        else:
            out["keluaran_pertama_lolos"] = statistics.mean(
                all(evidence_exists(e, truth.logs[r["id"]]) for e in r.get("evidence") or [] if isinstance(e, str))
                for r in rows)
        attack = [r for r in rows if r["label"] in ATTACK]
        for name, lexicon in lexicons.items():
            items = good = lines_good = lines_none = 0
            for r in attack:
                evidence = [e for e in r.get("evidence") or [] if isinstance(e, str)]
                flags = [(evidence_exists(e, truth.logs[r["id"]]), class_consistent(e, r["label"], lexicon))
                         for e in evidence]
                items += len(flags)
                good += sum(lit and con for lit, con in flags)
                lines_good += any(lit and con for lit, con in flags)
                lines_none += not any(con for _, con in flags)
            out[f"konsisten_item_{name}"] = good / items if items else None
            out[f"konsisten_baris_{name}"] = lines_good / len(attack) if attack else None
            out[f"tanpa_konsisten_{name}"] = lines_none / len(attack) if attack else None
    if rows and "verifikasi" in rows[0]:
        out["verification_failed"] = sum(r["status"] == "verification_failed" for r in rows)
        out["putaran_rerata"] = statistics.mean(r["verifikasi"]["putaran"] for r in rows)
        out["baris_ditolak"] = sum(r["verifikasi"]["penolakan"] > 0 for r in rows)
    return out


# ------------------------------------------------------------------------------------------------- uji berpasangan


def _strata(t: np.ndarray, clusters: list[str]) -> list[list[np.ndarray]]:
    """Templat per kelas sebenarnya, seperti replikasi.bootstrap_mean_macro_f1 (urutan kelas, kunci templat terurut)."""
    strata = []
    for k in range(K):
        rows_k = np.flatnonzero(t == k)
        keys = sorted({clusters[i] for i in rows_k})
        groups = [rows_k[[clusters[i] == key for i in rows_k]] for key in keys]
        if groups:
            strata.append(groups)
    return strata


def _mean_f1(t: np.ndarray, preds: list[np.ndarray], idx: np.ndarray | None = None) -> float:
    if idx is None:
        return float(np.mean([macro_f1(t, p) for p in preds]))
    return float(np.mean([macro_f1(t[idx], p[idx]) for p in preds]))


def paired_bootstrap(t: np.ndarray, a: list[np.ndarray], b: list[np.ndarray], clusters: list[str], n: int = N_PAIRED,
                     random_state: int = RANDOM_STATE) -> dict:
    strata = _strata(t, clusters)
    rng = np.random.default_rng(random_state)
    diffs = np.empty(n)
    for i in range(n):
        idx = np.concatenate([groups[j] for groups in strata for j in rng.integers(0, len(groups), len(groups))])
        diffs[i] = _mean_f1(t, a, idx) - _mean_f1(t, b, idx)
    low, high = np.percentile(diffs, [2.5, 97.5])
    p = min(1.0, 2 * min(float((diffs <= 0).mean()), float((diffs >= 0).mean())))
    return {"selisih": _mean_f1(t, a) - _mean_f1(t, b), "ik_bawah": float(low), "ik_atas": float(high), "p": p,
            "n_draw": n}


def paired_permutation(t: np.ndarray, a: list[np.ndarray], b: list[np.ndarray], clusters: list[str], n: int = N_PAIRED,
                       random_state: int = RANDOM_STATE) -> dict:
    keys = sorted(set(clusters))
    labels = np.array(clusters)
    groups = [np.flatnonzero(labels == key) for key in keys]
    runs = max(len(a), len(b))
    a_runs = a if len(a) == runs else a * runs
    b_runs = b if len(b) == runs else b * runs
    observed = _mean_f1(t, a) - _mean_f1(t, b)
    rng = np.random.default_rng(random_state)
    hits = 0
    for _ in range(n):
        swap = rng.random(len(groups)) < 0.5
        mask = np.zeros(len(t), dtype=bool)
        for group, flip in zip(groups, swap):
            if flip:
                mask[group] = True
        perm_a = [np.where(mask, pb, pa) for pa, pb in zip(a_runs, b_runs)]
        perm_b = [np.where(mask, pa, pb) for pa, pb in zip(a_runs, b_runs)]
        hits += abs(_mean_f1(t, perm_a) - _mean_f1(t, perm_b)) >= abs(observed)
    return {"selisih": observed, "p": hits / n, "n_permutasi": n}


def mcnemar_pairs(t: np.ndarray, a: list[np.ndarray], b: list[np.ndarray]) -> list[dict]:
    out = []
    for k, (pa, pb) in enumerate(zip(a, b), 1):
        a_only = int(((pa == t) & (pb != t)).sum())
        b_only = int(((pb == t) & (pa != t)).sum())
        p = binomtest(a_only, a_only + b_only, 0.5).pvalue if a_only + b_only else 1.0
        out.append({"run": k, "a_benar_b_salah": a_only, "b_benar_a_salah": b_only, "p": float(p)})
    return out


# ------------------------------------------------------------------------------------------------- agregasi


def collect(truth, preview: bool = False) -> dict:
    """Muat metode yang tersedia: {nama: {"methods": [...], "group": agregat replikasi}}."""
    out = {}
    for name in SINGLE_RUN:
        path = RESULTS_DIR / f"{name}.jsonl"
        if path.exists():
            methods = [load_method(path)]
            out[name] = {"methods": methods, "group": aggregate(methods, truth)}
    for name, base in GROUPS.items():
        files = group_files(base)
        if not files:
            continue
        methods = [load_method(p) for p in files]
        check_complete(base, methods, truth, expected=None if preview else EXPECTED_RUNS)
        check_consistent(methods)
        out[name] = {"methods": methods, "group": aggregate(methods, truth)}
    return out


def build(truth, data: dict, n_paired: int = N_PAIRED) -> dict:
    lexicons = {"utama": load_lexicon(), "utama_kb": load_lexicon(with_kb=True)}
    for name, entry in data.items():
        per_run = [extra_metrics(m, truth, lexicons) for m in entry["methods"]]
        keys = list(dict.fromkeys(k for r in per_run for k in r))
        entry["extra"] = {k: summarize([r.get(k) for r in per_run]) for k in keys}
    ids = list(truth.labels)
    t, _ = _indices([truth.labels[i] for i in ids], [truth.labels[i] for i in ids])
    clusters = [f"{truth.labels[i]}|{truth.template_keys[i]}" for i in ids]
    preds = {name: [_indices([truth.labels[i] for i in ids], [m.predictions[i] for i in ids])[1] for m in entry["methods"]]
             for name, entry in data.items()}
    tests = []
    for a, b in PAIRS:
        if a in preds and b in preds:
            boot = paired_bootstrap(t, preds[a], preds[b], clusters, n_paired)
            perm = paired_permutation(t, preds[a], preds[b], clusters, n_paired)
            tests.append({"a": a, "b": b, **boot, "p_permutasi": perm["p"], "n_permutasi": perm["n_permutasi"]})
    mcnemar = [{"a": a, "b": b, "pasangan": mcnemar_pairs(t, preds[a], preds[b])} for a, b in MCNEMAR_PAIRS
               if a in preds and b in preds]
    return {"metode": {name: {"runs": entry["group"]["runs"], "metrik": entry["group"]["metrics"],
                              "metrik_revisi": entry["extra"], "ik_macro_f1": entry["group"].get("macro_f1_ci95"),
                              "confusion_rerata": entry["group"]["confusion_mean"],
                              "baris_label_berubah_antar_run": entry["group"]["baris_label_berubah_antar_run"]}
                       for name, entry in data.items()},
            "uji_berpasangan": tests, "mcnemar": mcnemar, "dekomposisi": decomposition(data)}


def decomposition(data: dict) -> dict:
    need = ("llm_single", "agent", "llm_single_verified")
    if not all(n in data for n in need):
        return {}
    out = {}
    for key, source in (("evidence_literal", "metrics"), ("macro_f1", "metrics")):
        single, agent, ablation = (data[n]["group"][source][key]["mean"] for n in need)
        total = agent - single
        loop, orchestration = ablation - single, agent - ablation
        out[key] = {"llm_single": single, "agent": agent, "ablasi": ablation, "selisih_total": total,
                    "bagian_loop": loop, "bagian_orkestrasi": orchestration,
                    "persen_loop": 100 * loop / total if total else None,
                    "persen_orkestrasi": 100 * orchestration / total if total else None}
    return out


# ------------------------------------------------------------------------------------------------- tampilan


def _n(x: float, digits: int = 3, thousands: bool = False) -> str:
    text = f"{x:,.{digits}f}" if thousands else f"{x:.{digits}f}"
    return text.replace("-", "−")


def cell(stat: dict | None, digits: int = 3, space: bool = False, thousands: bool = False, dagger: bool = False,
         runs: int = 1) -> str:
    if not stat or stat.get("mean") is None:
        return "–"
    mean = _n(stat["mean"], digits, thousands)
    if runs <= 1 or _n(stat["min"], digits, thousands) == _n(stat["max"], digits, thousands):
        return mean + ("†" if dagger and runs > 1 else "")
    return f"{mean}{' ' if space else ''}({_n(stat['min'], digits, thousands)}–{_n(stat['max'], digits, thousands)})"


def _p(p: float) -> str:
    return "<0.001" if p < 0.001 else f"{p:.3f}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    return "\n".join(lines + ["| " + " | ".join(r) + " |" for r in rows])


def render(result: dict) -> str:
    m = result["metode"]
    names = [n for n in ORDER if n in m]
    runs = {n: len(m[n]["runs"]) for n in names}
    llm = [n for n in names if "token_masukan_rerata" in m[n]["metrik"]]
    out = ["Format angka mengikuti manuskrip (titik desimal; metode LLM: rerata tiga run dengan rentang min–maks; "
           "† = identik di ketiga run). Definisi setiap kolom: docstring src/eval/revisi.py.", ""]

    out += ["## Tabel 4 — Binary detection (S1)", ""]
    keys = ("biner_accuracy", "biner_precision", "biner_recall", "biner_f1", "biner_fpr")
    out.append(_table(["Method", "Accuracy", "Precision", "Recall", "F1", "FPR", "FPR excl. invalid"],
                      [[NAMES[n], *(cell(m[n]["metrik"][k], runs=runs[n]) for k in keys),
                        cell(m[n]["metrik_revisi"]["biner_fpr_tanpa_invalid"], runs=runs[n])] for n in names]))

    out += ["", "## Tabel 5 — Six-class classification (S2)", ""]
    rows = []
    for n in names:
        ci = m[n]["ik_macro_f1"]
        rows.append([NAMES[n], *(cell(m[n]["metrik"][k], runs=runs[n]) for k in
                                 ("accuracy", "macro_precision", "macro_recall", "macro_f1")),
                     f"[{_n(ci['low'])}, {_n(ci['high'])}]" if ci else "–"])
    out.append(_table(["Method", "Accuracy", "Macro-P", "Macro-R", "Macro-F1", "95% CI of macro-F1"], rows))

    out += ["", "## Tabel 6 — Paired comparisons of mean-of-runs macro-F1 (10,000 template-level draws)", ""]
    out.append(_table(["Comparison (A − B)", "Difference", "95% CI", "p, bootstrap", "p, permutation"],
                      [[f"{FIRST[x['a']]} − {SHORT[x['b']]}", _n(x["selisih"]),
                        f"[{_n(x['ik_bawah'])}, {_n(x['ik_atas'])}]", _p(x["p"]), _p(x["p_permutasi"])]
                       for x in result["uji_berpasangan"]]))
    if result["mcnemar"]:
        out += ["", "Suplemen — McNemar eksak per pasangan run berindeks sama (mengabaikan klaster templat):", ""]
        out.append(_table(["A − B", "run", "A benar, B salah", "B benar, A salah", "p eksak"],
                          [[f"{SHORT[x['a']]} − {SHORT[x['b']]}", f"r{q['run']}–r{q['run']}", str(q["a_benar_b_salah"]),
                            str(q["b_benar_a_salah"]), f"{q['p']:.2e}"] for x in result["mcnemar"] for q in x["pasangan"]]))

    out += ["", "## Tabel 7 — Per-class F1", ""]
    out.append(_table(["Method", "SQLI", "XSS", "PT", "CMD", "WS", "NORMAL"],
                      [[NAMES[n], *(cell(m[n]["metrik"][f"f1_{c}"], runs=runs[n], dagger=True) for c in CLASSES)]
                       for n in names]))

    out += ["", "## Tabel 8 — Confusion matrices (rows = true class; LLM methods: mean of three runs)", ""]
    for n in names:
        cm = m[n]["confusion_rerata"]
        fmt = (lambda v: f"{v:.1f}") if runs[n] > 1 else (lambda v: str(int(round(v))))
        support = [int(round(sum(row))) for row in cm]
        body = [[f"{c} ({s})", *(fmt(v) for v in row)] for c, s, row in zip(CLASSES, support, cm)]
        out += [f"{NAMES[n]}", "", _table(["True \\ Predicted", *CLASSES, "Invalid"], body), ""]

    if llm:
        out += ["## Tabel 9 — Tokens, calls, and cost per log line", ""]
        out.append(_table(["Method", "Input tokens/line", "Output tokens/line", "LLM calls/line",
                           "USD per 1,000 lines, billed", "USD per 1,000 lines, list price", "% input tokens cached"],
                          [[NAMES[n], cell(m[n]["metrik"]["token_masukan_rerata"], 0, thousands=True, runs=runs[n]),
                            cell(m[n]["metrik"]["token_keluaran_rerata"], 0, thousands=True, runs=runs[n]),
                            cell(m[n]["metrik"]["panggilan_llm_rerata"], 1, runs=runs[n]),
                            cell(m[n]["metrik"]["biaya_per_1000_baris_usd"], 3, runs=runs[n]),
                            cell(m[n]["metrik_revisi"]["biaya_list_per_1000_baris_usd"], 3, runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("token_cache_persen"), 1, runs=runs[n])] for n in llm]))
        out += ["", "## Tabel 10 — Latency in seconds", ""]
        out.append(_table(["Method", "Per line, median", "Per line, p95", "Per call, median", "Per call, p95"],
                          [[NAMES[n], *(cell(m[n]["metrik"].get(k), 2, space=True, runs=runs[n]) for k in
                                        ("latensi_median_s", "latensi_p95_s", "latensi_panggilan_median_s",
                                         "latensi_panggilan_p95_s"))] for n in llm]))
        out.append("Ablasi: latensi per baris = jumlah latensi panggilan baris itu (konvensi LLM tunggal).")

        out += ["", "## Tabel 11 — Evidence traceability", ""]
        out.append(_table(["Method", "Literal items (all predictions)", "Lines with all items literal, first output",
                           "Literal and class-consistent items (attack predictions)",
                           "Attack lines with ≥ 1 literal, class-consistent item"],
                          [[NAMES[n], cell(m[n]["metrik"].get("evidence_literal"), runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("keluaran_pertama_lolos"), runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("konsisten_item_utama"), runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("konsisten_baris_utama"), runs=runs[n])] for n in llm]))
        out.append("Keluaran pertama: deep agent dan ablasi = porsi baris terverifikasi yang klasifikasi pertamanya lolos "
                   "verifikasi; LLM tunggal = porsi baris yang semua item evidence-nya literal. Class-consistent: leksikon "
                   "configs/leksikon_kelas.yaml bagian utama (indikator Tabel 1).")
        out += ["", "Sensitivitas leksikon (utama + tambahan_kb) dan porsi prediksi serangan tanpa item class-consistent:", ""]
        out.append(_table(["Method", "Literal & consistent items (utama+kb)", "Attack lines ≥ 1 (utama+kb)",
                           "Attack lines without consistent item (utama)", "(utama+kb)"],
                          [[NAMES[n], cell(m[n]["metrik_revisi"].get("konsisten_item_utama_kb"), runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("konsisten_baris_utama_kb"), runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("tanpa_konsisten_utama"), runs=runs[n]),
                            cell(m[n]["metrik_revisi"].get("tanpa_konsisten_utama_kb"), runs=runs[n])] for n in llm]))

        out += ["", "## Verifikasi, keluaran degeneratif, dan stabilitas (per run)", ""]
        rows = []
        for n in llm:
            x = m[n]["metrik_revisi"]

            def per_run(key):
                stat = x.get(key)
                if not stat or stat.get("mean") is None:
                    return "–"
                return f"{_n(stat['mean'], 1)} ({' / '.join(_n(v, 0) for v in stat['values'])})"

            rows.append([NAMES[n], per_run("verification_failed"),
                         cell(x.get("putaran_rerata"), 2, space=True, runs=runs[n]), per_run("baris_ditolak"),
                         per_run("truncated_kejadian"), per_run("truncated_baris"), per_run("parse_error"),
                         f"{m[n]['baris_label_berubah_antar_run']} of 500"])
        out.append(_table(["Method", "verification_failed lines (r1 / r2 / r3)", "Verification rounds/line",
                           "Lines with ≥ 1 rejection", "TRUNCATED calls", "Lines with TRUNCATED", "PARSE_ERROR",
                           "Lines whose label changed across runs"], rows))

    if result["dekomposisi"]:
        out += ["", "## Dekomposisi §3.4 — loop verifikasi vs orkestrasi", ""]
        rows = []
        for key, title in (("evidence_literal", "Literal-evidence rate"), ("macro_f1", "Macro-F1")):
            d = result["dekomposisi"][key]
            rows.append([title, _n(d["llm_single"]), _n(d["ablasi"]), _n(d["agent"]), _n(d["selisih_total"]),
                         f"{_n(d['bagian_loop'])} ({_n(d['persen_loop'], 1)}%)",
                         f"{_n(d['bagian_orkestrasi'])} ({_n(d['persen_orkestrasi'], 1)}%)"])
        out.append(_table(["Metric", "Single LLM", "Ablation", "Deep agent", "Gap (agent − single)",
                           "Loop part (ablation − single)", "Orchestration part (agent − ablation)"], rows))
        out.append("Persen = bagian / selisih total, dihitung dari rerata tiga run sebelum pembulatan.")

    out += ["", "## Run yang dipakai", ""]
    out.append(_table(["Method", "run_id", "commit"], [[NAMES[n], str(r["run_id"]), str(r["git_commit"])[:7]]
                                                      for n in names for r in m[n]["runs"]]))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Laporan revisi jurnal: Tabel 4-11 manuskrip termasuk ablasi")
    parser.add_argument("--out", type=Path, help="simpan Markdown + JSON ke path ini (.md)")
    parser.add_argument("--preview", action="store_true", help="izinkan jumlah run selain 3 (pratinjau)")
    parser.add_argument("--n-paired", type=int, default=N_PAIRED, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    truth = load_truth("sample")
    data = collect(truth, args.preview)
    result = build(truth, data, args.n_paired)
    info = run_info("revisi", None, metode={n: [r["file"] for r in v["runs"]] for n, v in result["metode"].items()},
                    leksikon=str(LEXICON_PATH.relative_to(ROOT)), n_paired=args.n_paired)
    text = (f"# Revisi jurnal — angka Tabel 4–11 termasuk ablasi\n\nLaporan {info['run_id']} (commit "
            f"{str(info['git_commit'])[:7]}, dirty={info['git_dirty']})\n\n"
            + ("PRATINJAU — jumlah run belum lengkap; bukan laporan akhir.\n\n" if args.preview else "") + render(result))
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        args.out.with_suffix(".json").write_text(json.dumps({"run": info, **result}, ensure_ascii=False, indent=1) + "\n",
                                                 encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
