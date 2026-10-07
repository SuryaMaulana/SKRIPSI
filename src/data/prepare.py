"""Pipeline persiapan data SR-BH 2020 dari awal: `python -m src.data.prepare` (atau `make data`).

   1. verifikasi berkas mentah (MD5)           data/raw/ hanya dibaca, tidak pernah ditulis
   2. inspeksi                                 reports/srbh_inspection.md
   3. pemetaan label + gerbang bukti           data/processed/label_mapping.yaml
   4. rekonstruksi Combined Log Format         raw_log, raw_log_masked (masukan metode), timestamp_original
   5. parsing                                  ip ... user_agent, parse_error
   6. normalisasi                              path_norm, query_norm, ua_norm
   7. fitur sesi 60 detik tanpa IP             sess_* (hanya di parquet untuk analisis; tidak dipakai metode)
   8. dedup isi, batas templat RFI, split      srbh_{train,val,test}.parquet (train: fewshot_eligible), srbh_excluded.parquet
   9. sampel uji 500                           test_sample_500.jsonl (+ template_key untuk bootstrap klaster)
  10. laporan                                  reports/data_report.md
"""

from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd
import yaml

from . import audit, inspect_srbh, report
from .clf_parser import parse_lines
from .config import LABEL_MAPPING_OUT, LABEL_MAPPING_SRC, PROCESSED_DIR, REPORTS_DIR
from .download import verify_srbh
from .gate import MODULES
from .gate.common import multi_decode
from .gate.rfi import rfi_template
from .labels import EXCLUDED, apply_gate, load_mapping, map_labels_only, summarize, validate_columns, write_mapping_copy
from .load import detect_label_columns, read_raw
from .normalize import normalize
from .reconstruct import mask_log, reconstruct
from .sample import draw_sample, quotas, write_jsonl
from .session import session_features
from .split import RFI_RULE, cap_rfi_templates, dedup, stratified_split


def _parity(mapping, entries: pd.DataFrame) -> list[dict]:
    actual = entries.groupby(["label", "rule_id"]).size()
    return [
        {"label": label, "rule_id": rid, "expected": n, "actual": int(actual.get((label, rid), 0))}
        for label, rules in mapping.expected.items()
        for rid, n in rules.items()
    ]


def opaque_id(row_id: int) -> str:
    """ID stabil yang tidak membocorkan urutan berkas (urutan row_id = urutan waktu, yang mengelompokkan kelas)."""
    return "srbh-" + hashlib.sha256(f"srbh2020:{row_id}".encode()).hexdigest()[:16]


def main() -> None:
    md5 = verify_srbh()
    raw = read_raw()
    inspection = inspect_srbh.run(raw, md5)

    label_cols = detect_label_columns(raw)
    mapping = load_mapping(LABEL_MAPPING_SRC)
    validate_columns(label_cols, mapping)
    if mapping.status != "disetujui":
        print(f"[label] {LABEL_MAPPING_SRC.name} berstatus '{mapping.status}': pipeline berhenti setelah inspeksi.")
        return

    # Langkah 3 — label
    df = raw.astype({c: np.int8 for c in label_cols})
    labeled, entries = apply_gate(df, mapping, MODULES)
    summary = summarize(df, labeled, entries, mapping)
    parity = _parity(mapping, entries)
    broken = [p for p in parity if p["expected"] != p["actual"]]
    if broken:
        raise RuntimeError(f"Paritas aturan gerbang gagal (rows_expected vs aktual): {broken}")
    write_mapping_copy(mapping, summary, LABEL_MAPPING_OUT)
    is_rfi = labeled["label_rule"] == RFI_RULE
    labeled["rfi_template"] = ""
    labeled.loc[is_rfi, "rfi_template"] = [rfi_template(multi_decode(u)) for u in raw.loc[is_rfi, "request_http_request"]]
    print(f"[label] {summary['final_distribution']}")

    # Langkah 4–7 — log, parsing, normalisasi, sesi (atas seluruh aliran log)
    rec = reconstruct(raw)
    parsed = parse_lines(rec["raw_log"])
    full = pd.concat(
        [
            pd.DataFrame({"id": [opaque_id(i) for i in df.index], "row_id": df.index}, index=df.index),
            rec[["raw_log"]],
            mask_log(rec["raw_log"]).rename("raw_log_masked"),
            labeled,
            parsed,
            normalize(parsed),
            session_features(parsed["timestamp"], parsed["status"], parsed["path"]),
            rec[["timestamp_original"]],
        ],
        axis=1,
    )
    if full["id"].duplicated().any():
        raise RuntimeError("ID opak bertabrakan")
    print(f"[log] gagal urai: {int((parsed['parse_error'] != '').sum())}")

    # Langkah 8 — dedup, batas templat RFI, split
    excluded = full[full["label"] == EXCLUDED]
    six = full[full["label"] != EXCLUDED].drop(columns="exclusion_reason")
    deduped, dedup_stats = dedup(six, key="raw_log_masked")
    cap = int(mapping.options["rfi_template_cap"])
    capped, cap_table, cap_dropped = cap_rfi_templates(deduped, cap)
    train, val, test = stratified_split(capped)
    # Few-shot hanya boleh dari baris train yang isinya (tanpa stempel waktu) tidak muncul di srbh_test (keputusan penulis).
    in_test = set(audit.content_key(test["raw_log"]))
    train = train.assign(fewshot_eligible=~audit.content_key(train["raw_log"]).isin(in_test))

    # Langkah 9 — sampel uji
    weak_sqli = str(mapping.options.get("sample_weak_sqli", "exclude"))
    sample, pools = draw_sample(test, weak_sqli=weak_sqli)
    sample = sample.assign(template_key=audit.template_keys(sample))

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    for name, part in (("train", train), ("val", val), ("test", test)):
        part.to_parquet(PROCESSED_DIR / f"srbh_{name}.parquet", index=False)
    pd.concat([excluded, cap_dropped.assign(exclusion_reason="RFI_TEMPLATE_CAP")]).sort_values("row_id").to_parquet(
        PROCESSED_DIR / "srbh_excluded.parquet", index=False
    )
    write_jsonl(sample, PROCESSED_DIR / "test_sample_500.jsonl")

    # Langkah 10 — laporan
    failed = parsed["parse_error"] != ""
    q = quotas(test)
    stats = {
        "inspection": inspection,
        "labels": summary,
        "exclusion_reasons": yaml.safe_load(mapping.source_text)["exclusion_reasons"],
        "mapping_targets": dict(mapping.targets),
        "labels_only": map_labels_only(df, mapping)["label"].value_counts().to_dict(),
        "parity": parity,
        "dedup": dedup_stats,
        "rfi_cap": cap,
        "cap_table": cap_table.to_dict("records"),
        "pt_after_cap": int((capped["label"] == "PATH_TRAVERSAL").sum()),
        "parse": {
            "failed": int(failed.sum()),
            "by_reason": parsed.loc[failed, "parse_error"].value_counts().to_dict(),
            "failed_rows": [int(i) for i in parsed.index[failed]],
            "failed_in_six_class": int((six["parse_error"] != "").sum()),
            "all_empty_rows": bool((full.loc[failed, "exclusion_reason"] == "EMPTY_ROW").all()),
        },
        "stages": {
            "raw": len(raw), "excluded_by_gate": len(excluded), "six_class": len(six), "after_dedup": len(deduped),
            "rfi_cap_dropped": len(cap_dropped), "after_cap": len(capped),
            "train": len(train), "val": len(val), "test": len(test), "sample": len(sample),
        },
        "splits": {name: part["label"].value_counts().to_dict() for name, part in (("train", train), ("val", val), ("test", test))},
        "sample_quotas": q,
        "sample_pool": pools,
        "weak_sqli": weak_sqli,
        "fewshot": {"eligible": int(train["fewshot_eligible"].sum()), "excluded": int((~train["fewshot_eligible"]).sum())},
        "weak_sqli_test": (int((test["weak_evidence"] & (test["label"] == "SQLI")).sum()), int((test["label"] == "SQLI").sum())),
        "multi_candidates": audit.multi_candidates(labeled),
        "content_overlap": audit.content_overlap({"train": train, "val": val, "test": test}, sample),
        "normal_windows": audit.normal_windows(test),
        "time_proxy": audit.time_proxy(train, sample),
        "selection_effect": audit.selection_effect(df, sample),
        "concentration": audit.template_concentration(sample),
        "offsets": audit.offset_runs(raw),
        "protocol_http10": {c: int(((capped["label"] == c) & (capped["protocol"] == "HTTP/1.0")).sum()) for c in q},
    }
    (REPORTS_DIR / "data_report.md").write_text(report.render(stats, capped, sample), encoding="utf-8")
    print(f"[split] train {len(train)} | val {len(val)} | test {len(test)} | sampel {len(sample)} -> {PROCESSED_DIR}")


if __name__ == "__main__":
    main()
