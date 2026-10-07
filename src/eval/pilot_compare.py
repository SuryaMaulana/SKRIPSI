"""Perbandingan per baris pilot deep agent (E) dengan LLM tunggal (C) pada 30 baris pilot yang sama.

Skrip sisi evaluasi: boleh membaca label benar. Kolom C memakai run penuh 500 baris (results/llm_single.jsonl) sebagai
rujukan utama; baris yang labelnya berbeda pada pilot C (results/pilot/llm_single.jsonl) ditandai, karena run dengan
prompt, temperature 0, dan seed yang sama tidak selalu identik.
Jalankan: python -m src.eval.pilot_compare [--out reports/pilot_agent.md]
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path

from ..common.evidence import evidence_exists
from ..common.inputs import SAMPLE_PATH, split_path
from ..data.config import ROOT
from ..llm.klasifikasi import CLASS_LABELS

RESULTS = ROOT / "results"


def _rows(path: Path) -> dict[str, dict]:
    return {r["id"]: r for r in map(json.loads, path.read_text(encoding="utf-8").splitlines()) if r}


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def _num(x: float, digits: int = 2) -> str:
    return f"{x:.{digits}f}".replace(".", ",")


def _literal(rows: list[dict], logs: dict[str, str]) -> tuple[int, int]:
    items = [(r["id"], e) for r in rows for e in r.get("evidence") or [] if isinstance(e, str)]
    return sum(evidence_exists(e, logs[i]) for i, e in items), len(items)


def _macro_f1(true: list[str], pred: list[str]) -> float:
    scores = []
    for c in CLASS_LABELS:
        tp = sum(t == c and p == c for t, p in zip(true, pred))
        fp = sum(t != c and p == c for t, p in zip(true, pred))
        fn = sum(t == c and p != c for t, p in zip(true, pred))
        if tp + fn == 0:
            continue
        scores.append(0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn))
    return sum(scores) / len(scores)


def classification_history(calls_path: Path, run_id: str) -> dict[str, list[str]]:
    """Label tiap pemanggilan Klasifikasi per baris, dari log panggilan (dikelompokkan per putaran verifikasi; ulangan
    parse dalam satu putaran diambil yang terakhir). PARSE_ERROR bila tidak ada keluaran yang valid di putaran itu."""
    from ..baselines.llm_single import parse_output

    groups: dict[str, dict[int, str]] = {}
    for line in calls_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.get("run_id") != run_id or record.get("jenis") != "llm" or record.get("subagen") != "klasifikasi":
            continue
        output, _ = parse_output((record.get("respons") or {}).get("content"))
        rounds = groups.setdefault(record["id"], {})
        rounds[record["putaran_verifikasi"]] = output["label"] if output else rounds.get(
            record["putaran_verifikasi"], "PARSE_ERROR")
    return {i: [rounds[k] for k in sorted(rounds)] for i, rounds in groups.items()}


def _deterministic(verdict: dict) -> bool:
    """Penolakan oleh pemeriksaan deterministik: field skema_valid/evidence_hilang bila ada, selain itu alasan persis yang
    ditambahkan graph.verdict_from (bukan teks bebas LLM yang kebetulan mirip)."""
    if "skema_valid" in verdict:
        return not verdict["skema_valid"] or bool(verdict.get("evidence_hilang"))
    return any(a.startswith(("schema_check gagal", "evidence tidak ditemukan di baris log: ")) for a in verdict["alasan"])


def _rejection_kind(verdict: dict) -> str:
    if verdict["lolos"]:
        return "lolos"
    if "verifikator tidak memberi putusan" in verdict["alasan"]:  # batas panggilan tercapai tanpa Verdict
        return "verifikator tanpa putusan" + (" + evidence/skema" if _deterministic(verdict) else "")
    deterministic = _deterministic(verdict)
    if verdict.get("lolos_menurut_llm") is None:  # verifikator deterministik (tanpa LLM), sejak keputusan K2
        return "evidence/skema (deterministik)" if deterministic else "tanpa alasan"
    if deterministic and not verdict["lolos_menurut_llm"]:
        return "evidence/skema + penilaian LLM"
    return "evidence/skema (deterministik)" if deterministic else "penilaian LLM verifikator"


def load_truth(source: str, ids: list[str]) -> dict[str, dict]:
    """Label benar dan raw_log_masked untuk id terpilih: "test" = test_sample_500, selain itu nama split (mis. "val")."""
    wanted = set(ids)
    if source == "test":
        rows = map(json.loads, SAMPLE_PATH.read_text(encoding="utf-8").splitlines())
        return {r["id"]: r for r in rows if r["id"] in wanted}
    import pandas as pd

    frame = pd.read_parquet(split_path(source), columns=["id", "label", "raw_log_masked"])
    return {r["id"]: r for r in frame[frame["id"].isin(wanted)].to_dict("records")}


def _delegated(row: dict) -> bool:
    if "delegasi" in row:
        return row["delegasi"]["keempat_subagen"]
    used = row.get("alat_dipanggil") or {}
    return all(used.get(f"task:{name}") for name in ("parser", "analisis_payload", "klasifikasi", "verifikasi"))


def compare(ids_path: Path, agent_path: Path, singles: list[tuple[str, Path]], calls_path: Path, truth_source: str = "test",
            title: str = "Pilot deep agent vs LLM tunggal") -> str:
    """singles: [(nama kolom, berkas prediksi C)], kolom pertama dipakai untuk perbandingan per baris."""
    ids = json.loads(ids_path.read_text(encoding="utf-8"))["ids"]
    truth = load_truth(truth_source, ids)
    agent = _rows(agent_path)
    cols = [(name, _rows(path), path) for name, path in singles]
    (c_name, single, single_path), others = cols[0], cols[1:]
    run = json.loads(agent_path.with_name(agent_path.name.removesuffix(".jsonl") + ".run.json").read_text("utf-8"))
    c_run = json.loads(single_path.with_name(single_path.name.removesuffix(".jsonl") + ".run.json").read_text("utf-8"))
    logs = {i: truth[i]["raw_log_masked"] for i in ids}
    history = classification_history(calls_path, run["run_id"])
    history.update({i: agent[i]["riwayat_label"] for i in ids if "riwayat_label" in agent[i]})  # run sesudah 725069c
    lines = [f"# {title} ({len(ids)} baris, label benar dari {truth_source})", "",
             f"Run E: `{run['run_id']}` (commit {run['git_commit'][:7]}, dirty={run['git_dirty']}, model {run['model']}). "
             f"C: `{c_run['run_id']}`.",
             "", "## Hasil per baris", "",
             "| # | id | benar | C | E | status E | putaran | tolak | pengingat | 4 sub-agen | LLM E | alat E | "
             "token E (in/out) | latensi E (s) | biaya E ($) | token C (in/out) | latensi C (s) |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for n, i in enumerate(ids, 1):
        e, c, t = agent[i], single[i], truth[i]["label"]
        mark_c = f"{c['label']}{' ✓' if c['label'] == t else ' ✗'}" + "".join(
            f" ({name}: {rows[i]['label']})" for name, rows, _ in others if rows[i]["label"] != c["label"])
        mark_e = f"{e['label']}{' ✓' if e['label'] == t else ' ✗'}"
        v = e["verifikasi"]
        lines.append(f"| {n} | `{i}` | {t} | {mark_c} | {mark_e} | {e['status']} | {v['putaran']} | {v['penolakan']} | "
                     f"{len(e.get('pengingat_prosedur') or [])} | {'ya' if _delegated(e) else 'tidak'} | {e['llm_calls']} | "
                     f"{e['tool_calls']} | {e['prompt_tokens']}/{e['completion_tokens']} | {_num(e['latency_s'], 1)} | "
                     f"{e['cost_usd']:.5f} | {c['prompt_tokens']}/{c['completion_tokens']} | {_num(c['latency_s'], 2)} |")
    true = [truth[i]["label"] for i in ids]
    pred_e = [agent[i]["label"] for i in ids]
    pred_c = [single[i]["label"] for i in ids]
    acc = lambda pred: sum(p == t for p, t in zip(pred, true))  # noqa: E731
    fixed = [i for i in ids if agent[i]["label"] == truth[i]["label"] != single[i]["label"]]
    broken = [i for i in ids if single[i]["label"] == truth[i]["label"] != agent[i]["label"]]
    columns = [(name, rows) for name, rows, _ in cols] + [("E", agent)]
    lines += ["", "## Ringkasan", "", "| metrik | " + " | ".join(name for name, _ in columns) + " |",
              "|---|" + "---|" * len(columns)]

    def row(name: str, fn) -> str:
        return f"| {name} | " + " | ".join(fn(rows) for _, rows in columns) + " |"

    def literal(rows: dict) -> str:
        lit, n_items = _literal([rows[i] for i in ids], logs)
        return f"{lit}/{n_items} = {_num(lit / n_items, 3)}" if n_items else "—"

    lines += [row(f"benar (dari {len(ids)})", lambda r: str(acc([r[i]["label"] for i in ids]))),
              row(f"macro-F1 pada {len(ids)} baris", lambda r: _num(_macro_f1(true, [r[i]["label"] for i in ids]), 3)),
              row("evidence literal", literal),
              row("token masukan per baris (rerata)", lambda r: _num(statistics.mean(r[i]["prompt_tokens"] for i in ids), 0)),
              row("token keluaran per baris (rerata)",
                  lambda r: _num(statistics.mean(r[i]["completion_tokens"] for i in ids), 0)),
              row("latensi median (s)", lambda r: _num(_pct([r[i]["latency_s"] for i in ids], 0.5))),
              row("latensi p95 (s)", lambda r: _num(_pct([r[i]["latency_s"] for i in ids], 0.95))),
              row("biaya total ($)", lambda r: f"{sum(r[i]['cost_usd'] for i in ids):.5f}"),
              row("panggilan LLM per baris (rerata)",
                  lambda r: _num(statistics.mean(r[i].get("llm_calls", r[i].get("attempts", 1)) for i in ids), 1)),
              row("pemanggilan alat per baris (rerata)",
                  lambda r: _num(statistics.mean(r[i]["tool_calls"] for i in ids), 1) if "tool_calls" in r[ids[0]] else "—")]
    statuses = Counter(agent[i]["status"] for i in ids)
    verdicts = [v for i in ids for v in agent[i]["verifikasi"]["putusan"]]
    kinds = Counter(_rejection_kind(v) for v in verdicts if not v["lolos"])
    limit_hits = sum(agent[i]["batas_panggilan_subagen"] + agent[i]["verifikasi"].get("batas_panggilan_verifikator", 0)
                     for i in ids)
    lines += ["", "## Verifikasi dan orkestrasi (E)", "",
              f"- Status: " + ", ".join(f"{k} {statuses.get(k, 0)}" for k in
                                         ("ok", "verification_failed", "verification_skipped", "PARSE_ERROR")),
              f"- Orkestrator mendelegasikan ke keempat sub-agen: {sum(_delegated(agent[i]) for i in ids)}/{len(ids)} baris.",
              f"- Putusan verifikasi: {len(verdicts)}; ditolak {sum(not v['lolos'] for v in verdicts)} kali di "
              f"{sum(agent[i]['verifikasi']['penolakan'] > 0 for i in ids)} baris "
              f"({', '.join(f'{k}: {n}' for k, n in kinds.items()) or '—'}).",
              f"- Baris dengan 2 putaran: {sum(agent[i]['verifikasi']['putaran'] >= 2 for i in ids)}; label berubah setelah "
              f"penolakan: {sum(len(set(history.get(i, []))) > 1 for i in ids)} baris.",
              f"- Pengingat prosedur: {sum(len(agent[i].get('pengingat_prosedur') or []) for i in ids)}; pemanggilan "
              f"sub-agen yang ditahan guard: {sum(len(agent[i].get('ditahan_guard') or []) for i in ids)}; batas panggilan "
              f"sub-agen tercapai: {limit_hits}.",
              f"- E benar di baris yang {c_name} salah: {len(fixed)} ({', '.join(f'`{i}`' for i in fixed) or '—'}); "
              f"E salah di baris yang {c_name} benar: {len(broken)} ({', '.join(f'`{i}`' for i in broken) or '—'}).",
              f"- Label E = {c_name}: {sum(a == b for a, b in zip(pred_e, pred_c))}/{len(ids)}."]
    rejected = [i for i in ids if agent[i]["verifikasi"]["penolakan"]]
    if rejected:
        lines += ["", "## Baris yang ditolak Verifikasi", ""]
        for i in rejected:
            for v in agent[i]["verifikasi"]["putusan"]:
                llm = v.get("lolos_menurut_llm")
                judged = "" if llm is None else f"; LLM {'lolos' if llm else 'tolak'}"
                lines.append(f"- `{i}` putaran {v['putaran']} (klasifikasi ke-{v['klasifikasi_ke']}): "
                             f"{'lolos' if v['lolos'] else 'ditolak'}{judged}; alasan: {' | '.join(a[:200] for a in v['alasan'])}")
            lines.append(f"  - riwayat label klasifikasi: {' -> '.join(history.get(i, [])) or '—'}; label akhir "
                         f"{agent[i]['label']} (klasifikasi ke-{agent[i].get('klasifikasi_dipakai')}), status {agent[i]['status']}, "
                         f"benar {truth[i]['label']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Perbandingan per baris deep agent (E) vs LLM tunggal (C)")
    parser.add_argument("--ids", type=Path, default=RESULTS / "pilot" / "pilot_ids.json")
    parser.add_argument("--agent", type=Path, default=RESULTS / "pilot" / "agent.jsonl")
    parser.add_argument("--single", type=Path, default=RESULTS / "llm_single.jsonl")
    parser.add_argument("--single-pilot", type=Path, default=RESULTS / "pilot" / "llm_single.jsonl",
                        help="kolom C tambahan (kosongkan dengan --single-pilot '' bila tidak ada)")
    parser.add_argument("--calls", type=Path, default=RESULTS / "agent_calls.jsonl")
    parser.add_argument("--truth", default="test", help="test (test_sample_500) atau nama split, mis. val")
    parser.add_argument("--title", default="Pilot deep agent vs LLM tunggal")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    singles = [("C (500 penuh)" if args.truth == "test" else "C", args.single)]
    if str(args.single_pilot) not in ("", "."):
        singles.append(("C pilot", args.single_pilot))
    text = compare(args.ids, args.agent, singles, args.calls, args.truth, args.title)
    print(text)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
