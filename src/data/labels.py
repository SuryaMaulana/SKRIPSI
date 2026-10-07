"""Langkah 3 — pemetaan label CAPEC SR-BH 2020 ke 6 kelas penelitian dengan gerbang bukti.

Sumber kebenaran: configs/label_mapping.yaml. Setiap kolom label di dataset wajib tercantum di YAML, dan ID aturan di
YAML wajib sama dengan ID aturan di modul src/data/gate/, sehingga tidak ada label atau aturan yang hilang diam-diam.

Aturan per baris (gerbang dua kunci, disetujui penulis):
- setiap label aktif dievaluasi modul aturannya dan menyumbang kandidat kelas, alasan eksklusi, atau tidak keduanya;
- ada kandidat -> kelas dengan prioritas tertinggi (urutan `priority` di YAML), aturan pemenang di `label_rule`;
- tidak ada kandidat -> EXCLUDED dengan alasan terkuat (common.REASON_PRECEDENCE), atau NO_EVIDENCE.
`map_labels_only` (tanpa gerbang) hanya dipakai sebagai pembanding di laporan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from .config import CLASSES
from .gate.common import NORMAL_REASONS, REASON_PRECEDENCE, add_decoded

UNMAPPED = "UNMAPPED"
EXCLUDED = "EXCLUDED"
ATTACK_CLASSES = [c for c in CLASSES if c != "NORMAL"]


@dataclass(frozen=True)
class LabelMapping:
    normal_label: str
    targets: dict[str, str]  # kolom label serangan -> kelas serangan atau UNMAPPED
    codes: dict[str, str]  # kolom label -> kode CAPEC
    reasons: dict[str, str]  # kolom label -> alasan pemetaan
    priority: list[str]  # kelas serangan, prioritas tertinggi lebih dulu
    source_text: str  # isi YAML asli, disalin apa adanya ke data/processed/
    status: str = "usulan"  # "disetujui" setelah penulis menyetujui pemetaan
    evidence_gate: bool = False
    rules: dict[str, dict[str, str]] = field(default_factory=dict)  # kolom label -> {rule_id: deskripsi}
    expected: dict[str, dict[str, int]] = field(default_factory=dict)  # kolom label -> {rule_id: rows_expected}
    options: dict = field(default_factory=dict)

    @property
    def attack_labels(self) -> list[str]:
        return list(self.targets)


def load_mapping(path: Path) -> LabelMapping:
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    normal = raw["normal_label"]
    specs = raw["labels"]
    if specs.get(normal, {}).get("target") != "NORMAL":
        raise ValueError(f"Label normal {normal!r} harus tercantum di `labels` dengan target NORMAL")
    targets = {name: spec["target"] for name, spec in specs.items() if name != normal}
    invalid = {name: t for name, t in targets.items() if t not in [*ATTACK_CLASSES, UNMAPPED]}
    if invalid:
        raise ValueError(f"Target tidak valid (harus salah satu {ATTACK_CLASSES} atau {UNMAPPED}): {invalid}")
    priority = list(raw["priority"])
    if sorted(priority) != sorted(ATTACK_CLASSES):
        raise ValueError(f"`priority` harus memuat {ATTACK_CLASSES} masing-masing tepat sekali, bukan {priority}")
    return LabelMapping(
        normal,
        targets,
        codes={name: str(spec["capec"]) for name, spec in specs.items()},
        reasons={name: " ".join(str(spec.get("reason", "")).split()) for name, spec in specs.items()},
        priority=priority,
        source_text=text,
        status=str(raw.get("status", "usulan")),
        evidence_gate=bool(raw.get("evidence_gate", False)),
        rules={name: {str(r["id"]): str(r.get("when", "")) for r in spec.get("rules", [])} for name, spec in specs.items()},
        expected={
            name: {str(r["id"]): int(r["rows_expected"]) for r in spec.get("rules", []) if "rows_expected" in r}
            for name, spec in specs.items()
        },
        options=dict(raw.get("options", {})),
    )


def validate_columns(label_columns: list[str], mapping: LabelMapping) -> None:
    expected = {mapping.normal_label, *mapping.targets}
    not_in_yaml = [c for c in label_columns if c not in expected]
    not_in_data = sorted(expected - set(label_columns))
    if not_in_yaml or not_in_data:
        raise ValueError(f"Kolom label tanpa entri YAML: {not_in_yaml}; entri YAML tanpa kolom di dataset: {not_in_data}")


def validate_rules(mapping: LabelMapping, modules) -> None:
    """ID aturan di YAML (gabungan label-label sebuah modul) harus sama persis dengan RULES modul itu."""
    problems = []
    for module in modules:
        in_yaml = {rid for label in module.LABELS for rid in mapping.rules.get(label, {})}
        if in_yaml != set(module.RULES):
            problems.append(f"{module.__name__}: YAML {sorted(in_yaml)} vs kode {sorted(module.RULES)}")
    if problems:
        raise ValueError("ID aturan YAML dan kode tidak sama: " + "; ".join(problems))


def _capec_combo(df: pd.DataFrame, mapping: LabelMapping) -> pd.Series:
    attack = [c for c in df.columns if c in mapping.targets]  # urutan kolom dataset
    active = df[attack].astype(int).to_numpy() == 1
    keys = active.astype(np.int64) @ (1 << np.arange(len(attack), dtype=np.int64))
    names = {k: "+".join(mapping.codes[attack[i]] for i in range(len(attack)) if k >> i & 1) for k in np.unique(keys)}
    return pd.Series([names[k] for k in keys], index=df.index)


def map_labels_only(df: pd.DataFrame, mapping: LabelMapping) -> pd.DataFrame:
    """Pembanding tanpa gerbang: label -> target per label, prioritas untuk multi-label, label normal apa adanya."""
    validate_columns([c for c in df.columns if c in mapping.codes], mapping)
    attack = [c for c in df.columns if c in mapping.targets]
    active = df[attack].astype(int).to_numpy() == 1
    normal = df[mapping.normal_label].astype(int).to_numpy() == 1
    has_attack = active.any(axis=1)
    conflicts = int((normal & has_attack).sum() + (~normal & ~has_attack).sum())
    if conflicts:
        raise ValueError(f"{conflicts} baris punya label normal yang bertentangan dengan label serangannya")
    target_of = np.array([mapping.targets[c] for c in attack])
    label = np.full(len(df), EXCLUDED, dtype=object)
    n_classes = np.zeros(len(df), dtype=np.int8)
    for cls in reversed(mapping.priority):  # prioritas tertinggi ditulis paling akhir
        hit = active[:, target_of == cls].any(axis=1)
        label[hit] = cls
        n_classes += hit
    label[normal] = "NORMAL"
    rule = np.select([normal, n_classes == 0, n_classes == 1], ["normal", "unmapped_only", "single_class"], "priority")
    return pd.DataFrame({"capec_labels": _capec_combo(df, mapping), "label": label, "label_rule": rule}, index=df.index)


def evaluate_rules(df: pd.DataFrame, modules) -> pd.DataFrame:
    """Jalankan setiap modul pada baris yang membawa labelnya; hasil format panjang (index = row_id)."""
    decoded = add_decoded(df)
    parts = []
    for module in modules:
        has = decoded[list(module.LABELS)].astype(int).eq(1).any(axis=1)
        if has.any():
            parts.append(module.evaluate(decoded[has]))
    entries = pd.concat(parts)
    expected = int(df[[label for m in modules for label in m.LABELS]].astype(int).to_numpy().sum())
    if len(entries) != expected or entries.reset_index().duplicated(["index", "label"]).any():
        raise ValueError(f"Modul aturan harus memberi tepat satu entri per (baris, label aktif): {len(entries)} vs {expected}")
    return entries


def resolve(entries: pd.DataFrame, index: pd.Index, priority: list[str]) -> pd.DataFrame:
    """Gabungkan entri per baris menjadi kelas akhir, aturan penentu, alasan eksklusi, dan tanda bukti lemah."""
    order = {c: i for i, c in enumerate([*priority, "NORMAL"])}
    cand = entries[entries["candidate"] != ""]
    best = cand.assign(_p=cand["candidate"].map(order)).sort_values("_p", kind="stable")
    best = best[~best.index.duplicated(keep="first")]
    precedence = {r: i for i, r in enumerate([*NORMAL_REASONS, *REASON_PRECEDENCE])}
    why = entries[(entries["reason"] != "") & ~entries.index.isin(best.index)]
    why = why.assign(_p=why["reason"].map(precedence)).sort_values("_p", kind="stable")
    why = why[~why.index.duplicated(keep="first")]

    out = pd.DataFrame(index=index)
    out["label"] = EXCLUDED
    out["label_rule"] = ""
    out["exclusion_reason"] = "NO_EVIDENCE"
    out["weak_evidence"] = False
    out.loc[best.index, ["label", "label_rule", "weak_evidence"]] = best[["candidate", "rule_id", "weak"]].to_numpy()
    out.loc[best.index, "exclusion_reason"] = ""
    out.loc[why.index, ["exclusion_reason", "label_rule"]] = why[["reason", "rule_id"]].to_numpy()
    out["weak_evidence"] = out["weak_evidence"].astype(bool)
    candidates = cand.groupby(level=0)["candidate"].agg(lambda s: "+".join(sorted(set(s))))
    out["candidates"] = candidates.reindex(index).fillna("")
    return out


def apply_gate(df: pd.DataFrame, mapping: LabelMapping, modules) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Label akhir per baris + entri aturan mentah (untuk laporan per label)."""
    validate_rules(mapping, modules)
    entries = evaluate_rules(df, modules)
    out = resolve(entries, df.index, mapping.priority)
    out.insert(0, "capec_labels", _capec_combo(df, mapping))
    return out, entries


def summarize(df: pd.DataFrame, labeled: pd.DataFrame, entries: pd.DataFrame, mapping: LabelMapping) -> dict:
    """Distribusi akhir, aturan penentu, dan nasib setiap label (termasuk jumlah dikeluarkan per alasan)."""
    order = [*CLASSES, EXCLUDED]
    final = labeled["label"].value_counts()
    per_label = {}
    for col in [c for c in df.columns if c in mapping.codes]:
        rows = labeled[df[col].astype(int) == 1]
        dest = rows["label"].value_counts()
        own = entries[entries["label"] == col]
        per_label[col] = {
            "rows_with_label": len(rows),
            "final_class": {k: int(dest[k]) for k in order if k in dest},
            "excluded_by_reason": {k: int(v) for k, v in rows.loc[rows["label"] == EXCLUDED, "exclusion_reason"].value_counts().items()},
            "own_rule_counts": {k: int(v) for k, v in own["rule_id"].value_counts().sort_index().items()},
        }
    return {
        "rows_total": len(labeled),
        "final_distribution": {k: int(final.get(k, 0)) for k in order},
        "weak_evidence_sqli": int((labeled["weak_evidence"] & (labeled["label"] == "SQLI")).sum()),
        "deciding_rule_counts": {k: int(v) for k, v in labeled["label_rule"].value_counts().sort_index().items()},
        "excluded_by_reason": {k: int(v) for k, v in labeled.loc[labeled["label"] == EXCLUDED, "exclusion_reason"].value_counts().items()},
        "per_capec_label": per_label,
    }


def write_mapping_copy(mapping: LabelMapping, summary: dict, out_path: Path) -> None:
    """Salin YAML sumber apa adanya (komentar ikut) lalu tambahkan blok hitungan hasil pipeline."""
    block = yaml.safe_dump({"computed": summary}, allow_unicode=True, sort_keys=False)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        mapping.source_text.rstrip()
        + "\n\n# --- Dihitung otomatis oleh `python -m src.data.prepare`; jangan diedit manual ---\n"
        + block,
        encoding="utf-8",
    )
