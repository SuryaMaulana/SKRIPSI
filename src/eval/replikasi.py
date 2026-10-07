"""Agregasi replikasi run LLM (keputusan penulis 2026-10-08): C dan E dijalankan beberapa kali pada 500 baris yang sama
(run berbeda, seed sama) karena label dapat berubah antar run walau temperature 0. Untuk setiap metrik dilaporkan rerata
dan rentang min-maks atas run; tabel utama memakai rerata.

- Kelompok run: berkas utama (results/llm_single.jsonl, results/agent.jsonl) + replikasi results/replikasi/<nama>_r*.jsonl.
  Semua run satu kelompok wajib berkonfigurasi identik (model, versi model, parameter generasi, routing, hash prompt, berkas
  masukan); bila tidak, agregasi dihentikan.
- IK 95% macro-F1 rerata run: bootstrap klaster yang sama dengan evaluate.py (templat diresampel di dalam kelas, 1.000 kali,
  random_state=42); pada tiap draw, macro-F1 setiap run dihitung pada baris yang sama lalu dirata-rata atas run.
- Confusion matrix rerata = rerata jumlah sel atas run.
- Metode deterministik (regex, regex_full) memakai satu run (rentang = nilai itu sendiri).
Jalankan: make eval  (atau python -m src.eval.replikasi)
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

import numpy as np

from ..common.runinfo import run_info
from ..data.config import CLASSES, RANDOM_STATE, ROOT
from .evaluate import (
    K,
    N_BOOTSTRAP,
    RESULTS_DIR,
    Method,
    _f,
    _indices,
    _table,
    binary,
    evidence_literal,
    load_method,
    load_truth,
    macro_f1,
    multiclass,
)

REPLICATION_DIR = RESULTS_DIR / "replikasi"
GROUPS = {"llm_single": "llm_single", "agent": "agent"}  # nama metode -> nama berkas utama
CONFIG_KEYS = ("model", "model_version", "generation", "provider_routing", "prompt_sha256", "input_sha256")
SINGLE_RUN = ("regex", "regex_full")


def group_files(name: str, main_dir: Path = RESULTS_DIR, replication_dir: Path = REPLICATION_DIR,
                include_main: bool = True) -> list[Path]:
    files = [main_dir / f"{name}.jsonl"] if include_main else []
    files += sorted(replication_dir.glob(f"{name}_r*.jsonl"), key=lambda p: (len(p.name), p.name))
    return [p for p in files if p.exists() and p.stat().st_size > 0 and not p.name.endswith("_calls.jsonl")]


def check_consistent(methods: list[Method]) -> dict:
    """Konfigurasi bersama kelompok run; galat bila ada run yang berbeda konfigurasi."""
    reference = {k: methods[0].run.get(k) for k in CONFIG_KEYS}
    for m in methods[1:]:
        diff = [k for k in CONFIG_KEYS if m.run.get(k) != reference[k]]
        if diff:
            raise ValueError(f"{m.relpath}: konfigurasi berbeda dari {methods[0].relpath} pada {diff}")
    return reference


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    return float(np.percentile(values, q * 100))


def run_metrics(method: Method, truth) -> dict:
    """Metrik skalar satu run (urutan kunci = urutan tampil)."""
    ids = [i for i in truth.labels if i in method.predictions]
    t, p = _indices([truth.labels[i] for i in ids], [method.predictions[i] for i in ids])
    b, m = binary(t, p), multiclass(t, p)
    ev = evidence_literal(method, truth)
    rows = [r for r in method.rows if r["id"] in truth.labels]
    out = {
        "biner_accuracy": b["accuracy"], "biner_precision": b["precision"], "biner_recall": b["recall"], "biner_f1": b["f1"],
        "biner_fpr": b["fpr"],
        "accuracy": m["accuracy"], "macro_precision": m["macro_precision"], "macro_recall": m["macro_recall"],
        "macro_f1": m["macro_f1"],
        **{f"f1_{c}": m["per_class"][c]["f1"] for c in CLASSES},
        "prediksi_tidak_valid": m["invalid_predictions"],
    }
    if ev:
        out["evidence_literal"] = ev["proportion"]
    if rows and "prompt_tokens" in rows[0]:
        latency = [r["latency_s"] for r in rows]
        out.update({
            "token_masukan_rerata": statistics.mean(r["prompt_tokens"] for r in rows),
            "token_keluaran_rerata": statistics.mean(r["completion_tokens"] for r in rows),
            "latensi_median_s": _pct(latency, 0.5), "latensi_p95_s": _pct(latency, 0.95),
            "biaya_total_usd": sum(r["cost_usd"] for r in rows),
            "biaya_per_1000_baris_usd": 1000 * sum(r["cost_usd"] for r in rows) / len(rows),
            "panggilan_llm_rerata": statistics.mean(r.get("llm_calls", r.get("attempts", 1)) for r in rows),
        })
    if rows and "tool_calls" in rows[0]:  # deep agent
        out.update({
            "pemanggilan_alat_rerata": statistics.mean(r["tool_calls"] for r in rows),
            "verification_failed": sum(r["status"] == "verification_failed" for r in rows),
            "delegasi_keempat_subagen": sum(bool((r.get("delegasi") or {}).get("keempat_subagen")) for r in rows),
        })
    return out


def summarize(values: list[float | None]) -> dict:
    present = [v for v in values if v is not None]
    if not present:
        return {"mean": None, "min": None, "max": None, "values": values}
    return {"mean": float(np.mean(present)), "min": float(min(present)), "max": float(max(present)), "values": values}


def bootstrap_mean_macro_f1(t: np.ndarray, preds: list[np.ndarray], clusters: list[str], n: int = N_BOOTSTRAP,
                            random_state: int = RANDOM_STATE) -> dict:
    """Seperti evaluate.bootstrap_macro_f1, tetapi indeks baris setiap draw dipakai untuk semua run, lalu macro-F1
    dirata-rata atas run."""
    import pandas as pd

    rng = np.random.default_rng(random_state)
    strata = []
    for k in range(K):
        rows_k = np.flatnonzero(t == k)
        keys = pd.Series([clusters[i] for i in rows_k])
        groups = [rows_k[idx] for idx in keys.groupby(keys, sort=True).indices.values()]
        if groups:
            strata.append(groups)
    scores = np.empty(n)
    for b in range(n):
        idx = np.concatenate([groups[j] for groups in strata for j in rng.integers(0, len(groups), len(groups))])
        scores[b] = np.mean([macro_f1(t[idx], p[idx]) for p in preds])
    low, high = np.percentile(scores, [2.5, 97.5])
    return {"low": float(low), "high": float(high), "mean": float(scores.mean()), "n_bootstrap": n, "runs": len(preds)}


def aggregate(methods: list[Method], truth) -> dict:
    per_run = [run_metrics(m, truth) for m in methods]
    keys = list(dict.fromkeys(k for r in per_run for k in r))
    ids = [i for i in truth.labels if all(i in m.predictions for m in methods)]
    t, _ = _indices([truth.labels[i] for i in ids], [truth.labels[i] for i in ids])
    preds = [_indices([truth.labels[i] for i in ids], [m.predictions[i] for i in ids])[1] for m in methods]
    confusion = np.mean([multiclass(t, p)["confusion"] for p in preds], axis=0)
    result = {"runs": [{"file": m.relpath, "run_id": m.run.get("run_id"), "git_commit": m.run.get("git_commit"),
                        "git_dirty": m.run.get("git_dirty")} for m in methods],
              "metrics": {k: summarize([r.get(k) for r in per_run]) for k in keys},
              "confusion_mean": confusion.tolist(), "rows": len(ids)}
    if all(truth.template_keys.get(i) is not None for i in ids):
        clusters = [f"{truth.labels[i]}|{truth.template_keys[i]}" for i in ids]
        result["macro_f1_ci95"] = bootstrap_mean_macro_f1(t, preds, clusters)
    labels = np.array(preds)
    result["baris_label_berubah_antar_run"] = int((labels != labels[0]).any(axis=0).sum()) if len(preds) > 1 else 0
    return result


def _cell(stat: dict, digits: int = 3, show_range: bool = True) -> str:
    if stat["mean"] is None:
        return "—"
    fmt = (lambda v: _f(v)) if digits == 3 else (lambda v: f"{v:.{digits}f}".replace(".", ","))
    if not show_range or stat["min"] == stat["max"]:
        return fmt(stat["mean"])
    return f"{fmt(stat['mean'])} ({fmt(stat['min'])}–{fmt(stat['max'])})"


def render(groups: dict[str, dict]) -> str:
    names = list(groups)
    label = {n: f"{n} (rerata {len(g['runs'])} run)" if len(g["runs"]) > 1 else n for n, g in groups.items()}
    out = ["Nilai sel: rerata atas run (min–maks bila run lebih dari satu dan nilainya berbeda). Tabel utama memakai rerata.",
           ""]
    out += ["Tabel 4.2 — deteksi biner (serangan vs NORMAL)", ""]
    out.append(_table(["metode", "accuracy", "precision", "recall", "F1", "FPR"],
                      [[label[n], *(_cell(groups[n]["metrics"][k]) for k in
                                    ("biner_accuracy", "biner_precision", "biner_recall", "biner_f1", "biner_fpr"))]
                       for n in names]))
    out += ["", "Tabel 4.3 — klasifikasi 6 kelas", ""]
    rows = []
    for n in names:
        g = groups[n]
        ci = g.get("macro_f1_ci95")
        rows.append([label[n], *(_cell(g["metrics"][k]) for k in ("accuracy", "macro_precision", "macro_recall", "macro_f1")),
                     f"[{_f(ci['low'])}; {_f(ci['high'])}]" if ci else "—"])
    out.append(_table(["metode", "accuracy", "macro-P", "macro-R", "macro-F1", "IK 95% macro-F1 (rerata run)"], rows))
    out += ["", "F1 per kelas", ""]
    out.append(_table(["metode", *CLASSES], [[label[n], *(_cell(groups[n]["metrics"][f"f1_{c}"]) for c in CLASSES)]
                                             for n in names]))
    with_ev = [n for n in names if "evidence_literal" in groups[n]["metrics"]]
    if with_ev:
        out += ["", "Tabel 4.5 — evidence literal (proporsi item evidence yang ada harfiah di raw_log_masked)", ""]
        out.append(_table(["metode", "proporsi literal"], [[label[n], _cell(groups[n]["metrics"]["evidence_literal"])]
                                                          for n in with_ev]))
    with_cost = [n for n in names if "token_masukan_rerata" in groups[n]["metrics"]]
    if with_cost:
        out += ["", "Tabel 4.4 — token, latensi, dan biaya per baris (deskriptif)", ""]
        keys = ("token_masukan_rerata", "token_keluaran_rerata", "panggilan_llm_rerata", "latensi_median_s", "latensi_p95_s",
                "biaya_per_1000_baris_usd")
        digits = (0, 0, 1, 2, 2, 4)
        out.append(_table(["metode", "token masuk", "token keluar", "panggilan LLM", "latensi median (s)", "latensi p95 (s)",
                           "biaya per 1.000 baris ($)"],
                          [[label[n], *(_cell(groups[n]["metrics"][k], d) for k, d in zip(keys, digits))] for n in with_cost]))
    for n in names:
        g = groups[n]
        if len(g["runs"]) > 1:
            out.append(f"\n{n}: label berubah antar run pada {g['baris_label_berubah_antar_run']} dari {g['rows']} baris.")
        extra = [k for k in ("prediksi_tidak_valid", "verification_failed", "delegasi_keempat_subagen",
                             "pemanggilan_alat_rerata") if k in g["metrics"]]
        if extra:
            out.append(f"{n}: " + "; ".join(f"{k.replace('_', ' ')} {_cell(g['metrics'][k], 1)}" for k in extra) + ".")
    for n in names:
        cm = groups[n]["confusion_mean"]
        extra = any(row[K] for row in cm)
        headers = ["benar \\ prediksi", *CLASSES] + (["tidak valid"] if extra else [])
        body = [[c, *(f"{v:.1f}".replace(".", ",") if len(groups[n]["runs"]) > 1 else str(int(v))
                      for v in (row if extra else row[:K]))] for c, row in zip(CLASSES, cm)]
        out += ["", f"Confusion matrix — {label[n]}", "", _table(headers, body)]
    out += ["", "Run yang dirata-rata", ""]
    out.append(_table(["metode", "berkas", "run_id", "commit", "dirty"],
                      [[n, r["file"], str(r["run_id"]), str(r["git_commit"])[:7], str(r["git_dirty"])]
                       for n in names for r in groups[n]["runs"]]))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agregasi replikasi: rerata dan rentang min-maks per metrik")
    parser.add_argument("--replication-dir", type=Path, default=REPLICATION_DIR)
    parser.add_argument("--replications-only", action="store_true", help="tanpa run utama (hanya results/replikasi/)")
    parser.add_argument("--out", type=Path, help="simpan Markdown + JSON ke path ini (.md)")
    args = parser.parse_args(argv)
    truth = load_truth("sample")
    groups, configs = {}, {}
    for name in SINGLE_RUN:
        path = RESULTS_DIR / f"{name}.jsonl"
        if path.exists():
            method = load_method(path)
            groups[method.display] = aggregate([method], truth)
    for name, base in GROUPS.items():
        files = group_files(base, replication_dir=args.replication_dir, include_main=not args.replications_only)
        if not files:
            continue
        methods = [load_method(p) for p in files]
        configs[name] = check_consistent(methods)
        groups[name] = aggregate(methods, truth)
    info = run_info("replikasi", None, groups={n: [r["file"] for r in g["runs"]] for n, g in groups.items()},
                    configs=configs)
    text = (f"Agregasi replikasi {info['run_id']} (commit {str(info['git_commit'])[:7]}, dirty={info['git_dirty']})\n\n"
            + render(groups))
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        args.out.with_suffix(".json").write_text(json.dumps({"run": info, "groups": groups}, ensure_ascii=False, indent=1)
                                                 + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
