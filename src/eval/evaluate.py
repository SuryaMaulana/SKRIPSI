"""Langkah D — evaluasi prediksi metode: Tabel 4.2 (biner), Tabel 4.3 (6 kelas), F1 per kelas, confusion matrix, IK 95%.

Satu-satunya modul yang membaca label dan template_key. Masukan: satu atau lebih berkas prediksi results/*.jsonl, tiap
baris {id, label, ...}. Berkas *_calls.jsonl (log panggilan LLM), *.run.json, serta folder results/tuning/ dan
results/pilot/ bukan berkas prediksi utama. Aturan penilaian:
- Label prediksi di luar 6 kelas (mis. PARSE_ERROR) selalu dihitung salah, termasuk pada tugas biner.
- Biner: serangan = kelas selain NORMAL. FPR = FP / (FP + TN) pada baris NORMAL.
- Macro-P/R/F1 dirata-rata atas 6 kelas (zero_division = 0).
- Berkas yang barisnya ber-field post_hoc=true ditandai "(post hoc)" di semua tabel.
- Tabel 4.5 evidence literal (metode yang mengeluarkan `evidence`): proporsi item evidence yang ada secara harfiah di
  raw_log_masked mentah atau hasil decode (definisi di src/common/evidence.py, sama dengan alat Verifikasi deep agent).
- IK 95% Macro-F1: bootstrap klaster 1.000 kali (random_state=42) yang meresampel template_key (kunci templat payload,
  laporan data §6), bukan baris. Templat diresampel di dalam tiap kelas sebenarnya (strata = kelas), karena sampel uji
  dibangun dengan kuota per kelas (keputusan asisten); interval = persentil 2,5 dan 97,5.
Jalankan: make eval   (atau python -m src.eval.evaluate results/regex.jsonl results/regex_full.jsonl)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from ..common.evidence import evidence_exists
from ..common.runinfo import run_info
from ..data.config import CLASSES, RANDOM_STATE, ROOT
from ..common.inputs import SAMPLE_PATH, split_path

RESULTS_DIR = ROOT / "results"
N_BOOTSTRAP = 1000
K = len(CLASSES)
CLASS_INDEX = {c: i for i, c in enumerate(CLASSES)}
OTHER = K  # indeks untuk prediksi di luar 6 kelas (PARSE_ERROR dsb.)


@dataclass
class Truth:
    labels: dict[str, str]
    template_keys: dict[str, str | None]
    source: str
    logs: dict[str, str] = field(default_factory=dict)  # raw_log_masked per id (untuk evidence literal)


@dataclass
class Method:
    name: str
    path: Path
    predictions: dict[str, str]
    post_hoc: bool
    run: dict = field(default_factory=dict)
    rows: list[dict] = field(default_factory=list)
    tag: str = ""  # pembeda bila dua berkas bernama sama (mis. results/pilot/llm_single.jsonl -> "pilot")

    @property
    def display(self) -> str:
        name = f"{self.name} [{self.tag}]" if self.tag else self.name
        return f"{name} (post hoc)" if self.post_hoc else name

    @property
    def relpath(self) -> str:
        return str(self.path.relative_to(ROOT)) if self.path.is_relative_to(ROOT) else str(self.path)


def load_truth(source: str = "sample") -> Truth:
    """Label sebenarnya: "sample" = test_sample_500.jsonl (dengan template_key); nama split = srbh_<split>.parquet."""
    if source == "sample":
        labels, keys, logs = {}, {}, {}
        with open(SAMPLE_PATH, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                labels[record["id"]] = record["label"]
                keys[record["id"]] = record["template_key"]
                logs[record["id"]] = record["raw_log_masked"]
        return Truth(labels, keys, str(SAMPLE_PATH.relative_to(ROOT)), logs)
    frame = pd.read_parquet(split_path(source), columns=["id", "label", "raw_log_masked"])
    labels = dict(zip(frame["id"], frame["label"]))
    return Truth(labels, dict.fromkeys(labels), str(split_path(source).relative_to(ROOT)),
                 dict(zip(frame["id"], frame["raw_log_masked"])))


def is_prediction_file(path: Path) -> bool:
    """Berkas prediksi selesai: bukan log panggilan (*_calls.jsonl) dan bukan run yang belum selesai (*.partial.jsonl)."""
    return path.suffix == ".jsonl" and not path.name.endswith(("_calls.jsonl", ".partial.jsonl"))


def load_method(path: Path) -> Method:
    rows = [json.loads(line) for line in open(path, encoding="utf-8")]
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path.name}: id ganda")
    run_path = path.with_name(path.name.removesuffix(".jsonl") + ".run.json")
    run = json.loads(run_path.read_text(encoding="utf-8")) if run_path.exists() else {}
    post_hoc = any(r.get("post_hoc") for r in rows) or bool(run.get("post_hoc"))
    tag = "" if path.parent.resolve() == RESULTS_DIR.resolve() else path.parent.name
    return Method(path.name.removesuffix(".jsonl"), path, {r["id"]: r["label"] for r in rows}, post_hoc, run, rows, tag)


# --------------------------------------------------------------------------------------------------- metrik


def _indices(truth: list[str], pred: list[str]) -> tuple[np.ndarray, np.ndarray]:
    t = np.array([CLASS_INDEX[x] for x in truth])
    p = np.array([CLASS_INDEX.get(x, OTHER) for x in pred])
    return t, p


def confusion(t: np.ndarray, p: np.ndarray) -> np.ndarray:
    """Matriks K x (K+1): baris = kelas sebenarnya, kolom = prediksi (kolom terakhir = di luar 6 kelas)."""
    return np.bincount(t * (K + 1) + p, minlength=K * (K + 1)).reshape(K, K + 1)


def per_class(cm: np.ndarray) -> dict[str, np.ndarray]:
    tp = np.diag(cm[:, :K]).astype(float)
    pred_pos = cm[:, :K].sum(axis=0).astype(float)
    support = cm.sum(axis=1).astype(float)
    precision = np.divide(tp, pred_pos, out=np.zeros(K), where=pred_pos > 0)
    recall = np.divide(tp, support, out=np.zeros(K), where=support > 0)
    denom = precision + recall
    f1 = np.divide(2 * precision * recall, denom, out=np.zeros(K), where=denom > 0)
    return {"precision": precision, "recall": recall, "f1": f1, "support": support}


def macro_f1(t: np.ndarray, p: np.ndarray) -> float:
    pc = per_class(confusion(t, p))
    return float(pc["f1"][pc["support"] > 0].mean())


def multiclass(t: np.ndarray, p: np.ndarray) -> dict:
    """Makro dirata-rata atas 6 kelas; pada subset yang tidak memuat semua kelas, hanya atas kelas yang punya baris
    (`classes_in_macro` mencatatnya) agar kelas yang tidak diuji tidak masuk sebagai F1 = 0."""
    cm = confusion(t, p)
    pc = per_class(cm)
    present = pc["support"] > 0
    return {
        "n": int(len(t)),
        "accuracy": float((t == p).mean()),
        "macro_precision": float(pc["precision"][present].mean()),
        "macro_recall": float(pc["recall"][present].mean()),
        "macro_f1": float(pc["f1"][present].mean()),
        "classes_in_macro": [c for c, ok in zip(CLASSES, present) if ok],
        "per_class": {c: {k: float(v[i]) for k, v in pc.items()} for i, c in enumerate(CLASSES)},
        "confusion": cm.tolist(),
        "invalid_predictions": int((p == OTHER).sum()),
    }


def binary(t: np.ndarray, p: np.ndarray) -> dict:
    """Serangan vs NORMAL. Prediksi tidak valid dihitung salah: pada baris serangan jadi FN, pada baris NORMAL jadi FP."""
    normal = CLASS_INDEX["NORMAL"]
    truth_attack = t != normal
    pred_attack = np.where(p == OTHER, ~truth_attack, p != normal)
    tp = int((truth_attack & pred_attack).sum())
    fp = int((~truth_attack & pred_attack).sum())
    fn = int((truth_attack & ~pred_attack).sum())
    tn = int((~truth_attack & ~pred_attack).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": (tp + tn) / len(t),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else None,  # None = tidak ada baris NORMAL di cakupan
    }


def bootstrap_macro_f1(t: np.ndarray, p: np.ndarray, clusters: list[str], n: int = N_BOOTSTRAP,
                       random_state: int = RANDOM_STATE) -> dict:
    """Bootstrap klaster terstratifikasi: di tiap kelas sebenarnya, templat diambil ulang dengan pengembalian sebanyak
    jumlah templat kelas itu; semua baris templat terpilih ikut. Mengembalikan persentil 2,5/97,5 Macro-F1."""
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
        scores[b] = macro_f1(t[idx], p[idx])
    low, high = np.percentile(scores, [2.5, 97.5])
    return {"low": float(low), "high": float(high), "mean": float(scores.mean()), "n_bootstrap": n,
            "clusters": int(sum(len(g) for g in strata))}


def evaluate(method: Method, truth: Truth, ci: bool = True) -> dict:
    unknown = set(method.predictions) - set(truth.labels)
    if unknown:
        raise ValueError(f"{method.name}: {len(unknown)} id tidak ada di {truth.source}")
    ids = [i for i in truth.labels if i in method.predictions]  # urutan sumber kebenaran
    t, p = _indices([truth.labels[i] for i in ids], [method.predictions[i] for i in ids])
    result = {"method": method.display, "coverage": f"{len(ids)}/{len(truth.labels)}", "binary": binary(t, p),
              "multiclass": multiclass(t, p), "evidence_literal": evidence_literal(method, truth) if truth.logs else None}
    if ci and all(truth.template_keys[i] is not None for i in ids):
        clusters = [f"{truth.labels[i]}|{truth.template_keys[i]}" for i in ids]
        result["macro_f1_ci95"] = bootstrap_macro_f1(t, p, clusters)
    return result


def evidence_literal(method: Method, truth: Truth) -> dict | None:
    """Tabel 4.5: hanya baris yang punya field `evidence` (keluaran LLM); None untuk metode tanpa evidence."""
    rows = [r for r in method.rows if "evidence" in r and r["id"] in truth.labels]
    if not rows:
        return None
    items = literal = rows_with = rows_all = 0
    for row in rows:
        evidence = [e for e in row.get("evidence") or [] if isinstance(e, str)]
        if not evidence:
            continue
        flags = [evidence_exists(e, truth.logs[row["id"]]) for e in evidence]
        rows_with += 1
        items += len(flags)
        literal += sum(flags)
        rows_all += all(flags)
    return {"rows": len(rows), "rows_with_evidence": rows_with, "items": items, "literal": literal,
            "proportion": literal / items if items else None, "rows_all_literal": rows_all}


# --------------------------------------------------------------------------------------------------- analisis aturan


def rule_errors(method: Method, truth: Truth, top: int = 15) -> list[tuple[str, int, dict[str, int]]]:
    """Untuk prediksi berbasis aturan: aturan yang mendukung kelas prediksi pada baris yang salah, terbanyak dulu."""
    counts: dict[str, dict[str, int]] = {}
    for row in method.rows:
        true, pred = truth.labels[row["id"]], row["label"]
        if pred in (true, "NORMAL"):
            continue
        for hit in row.get("matched_rules", []):
            if hit["class"] == pred and hit.get("points", 0) > 0:
                pairs = counts.setdefault(hit["rule"], {})
                pairs[f"{true}->{pred}"] = pairs.get(f"{true}->{pred}", 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -sum(kv[1].values()))[:top]
    return [(rule, sum(pairs.values()), pairs) for rule, pairs in ranked]


# --------------------------------------------------------------------------------------------------- keluaran


def _f(x: float) -> str:
    return f"{x:.3f}".replace(".", ",")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    return "\n".join(lines + ["| " + " | ".join(r) + " |" for r in rows])


def render(results: list[dict], methods: list[Method], truth: Truth) -> str:
    out = [f"Sumber label: {truth.source}. Prediksi di luar 6 kelas dihitung salah.", ""]
    out += ["Tabel 4.2 — deteksi biner (serangan vs NORMAL)", ""]
    out.append(_table(["metode", "cakupan", "accuracy", "precision", "recall", "F1", "FPR"],
                      [[r["method"], r["coverage"], *(_f(r["binary"][k]) for k in ("accuracy", "precision", "recall", "f1")),
                        "—" if r["binary"]["fpr"] is None else _f(r["binary"]["fpr"])] for r in results]))
    out += ["", "Tabel 4.3 — klasifikasi 6 kelas", ""]
    rows = []
    for r in results:
        m, ci = r["multiclass"], r.get("macro_f1_ci95")
        interval = f"[{_f(ci['low'])}; {_f(ci['high'])}]" if ci else "—"
        rows.append([r["method"], r["coverage"], _f(m["accuracy"]), _f(m["macro_precision"]), _f(m["macro_recall"]),
                     _f(m["macro_f1"]), interval])
    out.append(_table(["metode", "cakupan", "accuracy", "macro-P", "macro-R", "macro-F1", "IK 95% macro-F1"], rows))
    for r in results:
        used = r["multiclass"]["classes_in_macro"]
        if len(used) < K:
            out.append(f"\nCatatan: {r['method']} — makro dirata-rata atas {len(used)} kelas yang ada di cakupan "
                       f"({', '.join(used)}).")
    out += ["", "F1 per kelas", ""]
    out.append(_table(["metode", *CLASSES], [[r["method"], *(_f(r["multiclass"]["per_class"][c]["f1"]) for c in CLASSES)]
                                             for r in results]))
    with_evidence = [r for r in results if r.get("evidence_literal")]
    if with_evidence:
        out += ["", "Tabel 4.5 — evidence literal (item evidence yang ada harfiah di raw_log_masked mentah/hasil decode)", ""]
        out.append(_table(["metode", "baris", "baris ber-evidence", "item", "item literal", "proporsi literal",
                           "baris semua literal"],
                          [[r["method"], str(e["rows"]), str(e["rows_with_evidence"]), str(e["items"]), str(e["literal"]),
                            "—" if e["proportion"] is None else _f(e["proportion"]), str(e["rows_all_literal"])]
                           for r in with_evidence for e in [r["evidence_literal"]]]))
        out.append("Metode tanpa field evidence (mis. regex) tidak dimasukkan.")
    for r in results:
        cm = r["multiclass"]["confusion"]
        extra = r["multiclass"]["invalid_predictions"] > 0
        headers = ["benar \\ prediksi", *CLASSES] + (["tidak valid"] if extra else [])
        body = [[c, *(str(v) for v in (row if extra else row[:K]))] for c, row in zip(CLASSES, cm)]
        out += ["", f"Confusion matrix — {r['method']}", "", _table(headers, body)]
    return "\n".join(out) + "\n"


def default_files() -> list[Path]:
    return sorted(p for p in RESULTS_DIR.glob("*.jsonl") if is_prediction_file(p))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluasi prediksi metode (Tabel 4.2/4.3)")
    parser.add_argument("files", nargs="*", type=Path, help="berkas prediksi; bawaan: semua results/*.jsonl prediksi")
    parser.add_argument("--truth", default="sample", help="sample (bawaan) atau nama split: train/val/test")
    parser.add_argument("--rules", action="store_true", help="tampilkan aturan pendorong salah kelas (metode aturan)")
    parser.add_argument("--out", type=Path, help="simpan juga tabel Markdown + JSON ringkasan ke path ini (.md)")
    args = parser.parse_args(argv)
    candidates = args.files or default_files()
    skipped = [p for p in candidates if not is_prediction_file(p) or p.stat().st_size == 0]
    files = [p for p in candidates if p not in skipped]
    truth = load_truth(args.truth)
    methods = [load_method(p) for p in files]
    names = [m.display for m in methods]
    for m in methods:  # dua berkas bernama sama di folder yang sama -> pakai path sebagai pembeda
        if names.count(m.display) > 1:
            m.tag = m.relpath
    results = [evaluate(m, truth, ci=args.truth == "sample") for m in methods]
    info = run_info("evaluate", None, truth=truth.source, skipped=[str(p) for p in skipped],
                    inputs={m.relpath: {k: m.run.get(k) for k in ("run_id", "git_commit", "git_dirty", "model",
                                                                  "model_version")}
                            for m in methods})
    text = f"Evaluasi {info['run_id']} (commit {str(info['git_commit'])[:7]}, dirty={info['git_dirty']})\n\n"
    if skipped:
        text += f"Dilewati (bukan berkas prediksi atau kosong): {', '.join(str(p) for p in skipped)}\n\n"
    text += render(results, methods, truth)
    if args.rules:
        for m in methods:
            ranked = rule_errors(m, truth)
            if ranked:
                text += f"\nAturan pendorong salah kelas — {m.display}\n\n" + _table(
                    ["aturan", "baris salah", "pasangan benar->prediksi"],
                    [[rule, str(n), ", ".join(f"{k}: {v}" for k, v in pairs.items())] for rule, n, pairs in ranked]) + "\n"
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        args.out.with_suffix(".json").write_text(json.dumps({"run": info, "results": results}, ensure_ascii=False,
                                                            indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
