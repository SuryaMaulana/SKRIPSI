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
from ..common.inputs import SAMPLE_PATH
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
    return any(a == "schema_check gagal" or a.startswith("evidence tidak ditemukan di baris log: ")
               for a in verdict["alasan"])


def _rejection_kind(verdict: dict) -> str:
    if verdict["lolos"]:
        return "lolos"
    deterministic = _deterministic(verdict)
    if deterministic and not verdict["lolos_menurut_llm"]:
        return "evidence/skema + penilaian LLM"
    return "evidence/skema (deterministik)" if deterministic else "penilaian LLM verifikator"


def compare(ids_path: Path, agent_path: Path, single_path: Path, single_pilot_path: Path, calls_path: Path) -> str:
    ids = json.loads(ids_path.read_text(encoding="utf-8"))["ids"]
    truth = {r["id"]: r for r in map(json.loads, SAMPLE_PATH.read_text(encoding="utf-8").splitlines())
             if r and r["id"] in set(ids)}
    agent, single, single_pilot = _rows(agent_path), _rows(single_path), _rows(single_pilot_path)
    run = json.loads(agent_path.with_name(agent_path.name.removesuffix(".jsonl") + ".run.json").read_text("utf-8"))
    logs = {i: truth[i]["raw_log_masked"] for i in ids}
    history = classification_history(calls_path, run["run_id"])
    history.update({i: agent[i]["riwayat_label"] for i in ids if "riwayat_label" in agent[i]})  # run sesudah 725069c
    lines = [f"# Pilot deep agent vs LLM tunggal ({len(ids)} baris)", "",
             f"Run E: `{run['run_id']}` (commit {run['git_commit'][:7]}, dirty={run['git_dirty']}, model {run['model']}). "
             f"C: `{json.loads(single_path.with_name('llm_single.run.json').read_text('utf-8'))['run_id']}` (500 baris).",
             "", "## Hasil per baris", "",
             "| # | id | benar | C | E | status E | putaran | tolak | pengingat | LLM E | alat E | token E (in/out) | "
             "latensi E (s) | biaya E ($) | token C (in/out) | latensi C (s) |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for n, i in enumerate(ids, 1):
        e, c, cp, t = agent[i], single[i], single_pilot[i], truth[i]["label"]
        mark_c = f"{c['label']}{' ✓' if c['label'] == t else ' ✗'}" + (f" (pilot: {cp['label']})" if cp["label"] != c["label"] else "")
        mark_e = f"{e['label']}{' ✓' if e['label'] == t else ' ✗'}"
        v = e["verifikasi"]
        lines.append(f"| {n} | `{i}` | {t} | {mark_c} | {mark_e} | {e['status']} | {v['putaran']} | {v['penolakan']} | "
                     f"{len(e.get('pengingat_prosedur') or [])} | {e['llm_calls']} | {e['tool_calls']} | "
                     f"{e['prompt_tokens']}/{e['completion_tokens']} | {_num(e['latency_s'], 1)} | {e['cost_usd']:.5f} | "
                     f"{c['prompt_tokens']}/{c['completion_tokens']} | {_num(c['latency_s'], 2)} |")
    true = [truth[i]["label"] for i in ids]
    pred_e, pred_c, pred_cp = ([d[i]["label"] for i in ids] for d in (agent, single, single_pilot))
    acc = lambda pred: sum(p == t for p, t in zip(pred, true))  # noqa: E731
    fixed = [i for i in ids if agent[i]["label"] == truth[i]["label"] != single[i]["label"]]
    broken = [i for i in ids if single[i]["label"] == truth[i]["label"] != agent[i]["label"]]
    lit_e, n_e = _literal([agent[i] for i in ids], logs)
    lit_c, n_c = _literal([single[i] for i in ids], logs)
    lit_cp, n_cp = _literal([single_pilot[i] for i in ids], logs)
    lines += ["", "## Ringkasan", "",
              "| metrik | C (500 penuh, 30 baris ini) | C (pilot v2) | E (pilot) |", "|---|---|---|---|",
              f"| benar (dari {len(ids)}) | {acc(pred_c)} | {acc(pred_cp)} | {acc(pred_e)} |",
              f"| macro-F1 pada {len(ids)} baris | {_num(_macro_f1(true, pred_c), 3)} | {_num(_macro_f1(true, pred_cp), 3)} | "
              f"{_num(_macro_f1(true, pred_e), 3)} |",
              f"| evidence literal | {lit_c}/{n_c} = {_num(lit_c / n_c, 3)} | {lit_cp}/{n_cp} = {_num(lit_cp / n_cp, 3)} | "
              f"{lit_e}/{n_e} = {_num(lit_e / n_e, 3) if n_e else '—'} |"]
    for name, key, digits in (("token masukan per baris (rerata)", "prompt_tokens", 0),
                              ("token keluaran per baris (rerata)", "completion_tokens", 0)):
        lines.append(f"| {name} | {_num(statistics.mean(single[i][key] for i in ids), digits)} | "
                     f"{_num(statistics.mean(single_pilot[i][key] for i in ids), digits)} | "
                     f"{_num(statistics.mean(agent[i][key] for i in ids), digits)} |")
    for name, q in (("latensi median (s)", 0.5), ("latensi p95 (s)", 0.95)):
        lines.append(f"| {name} | {_num(_pct([single[i]['latency_s'] for i in ids], q))} | "
                     f"{_num(_pct([single_pilot[i]['latency_s'] for i in ids], q))} | "
                     f"{_num(_pct([agent[i]['latency_s'] for i in ids], q))} |")
    lines.append(f"| biaya total ($) | {sum(single[i]['cost_usd'] for i in ids):.5f} | "
                 f"{sum(single_pilot[i]['cost_usd'] for i in ids):.5f} | {sum(agent[i]['cost_usd'] for i in ids):.5f} |")
    lines.append(f"| panggilan LLM per baris (rerata) | 1 | 1 | {_num(statistics.mean(agent[i]['llm_calls'] for i in ids), 1)} |")
    statuses = Counter(agent[i]["status"] for i in ids)
    verdicts = [v for i in ids for v in agent[i]["verifikasi"]["putusan"]]
    kinds = Counter(_rejection_kind(v) for v in verdicts if not v["lolos"])
    lines += ["", "## Verifikasi (E)", "",
              f"- Status: " + ", ".join(f"{k} {statuses.get(k, 0)}" for k in
                                         ("ok", "verification_failed", "verification_skipped", "PARSE_ERROR")),
              f"- Putusan verifikasi: {len(verdicts)}; ditolak {sum(not v['lolos'] for v in verdicts)} kali di "
              f"{sum(agent[i]['verifikasi']['penolakan'] > 0 for i in ids)} baris "
              f"({', '.join(f'{k}: {n}' for k, n in kinds.items()) or '—'}).",
              f"- Baris dengan 2 putaran: {sum(agent[i]['verifikasi']['putaran'] >= 2 for i in ids)}; label berubah setelah "
              f"penolakan: {sum(len(set(history.get(i, []))) > 1 for i in ids)} baris.",
              f"- Pengingat prosedur: {sum(len(agent[i].get('pengingat_prosedur') or []) for i in ids)}; pemanggilan "
              f"sub-agen yang ditahan guard: {sum(len(agent[i].get('ditahan_guard') or []) for i in ids)}; batas panggilan "
              f"sub-agen tercapai: {sum(agent[i]['batas_panggilan_subagen'] + agent[i]['verifikasi']['batas_panggilan_verifikator'] for i in ids)}.",
              f"- E benar di baris yang C salah: {len(fixed)} ({', '.join(f'`{i}`' for i in fixed) or '—'}); "
              f"E salah di baris yang C benar: {len(broken)} ({', '.join(f'`{i}`' for i in broken) or '—'}).",
              f"- Label E = C: {sum(a == b for a, b in zip(pred_e, pred_c))}/{len(ids)}."]
    rejected = [i for i in ids if agent[i]["verifikasi"]["penolakan"]]
    if rejected:
        lines += ["", "## Baris yang ditolak Verifikasi", ""]
        for i in rejected:
            for v in agent[i]["verifikasi"]["putusan"]:
                lines.append(f"- `{i}` putaran {v['putaran']} (klasifikasi ke-{v['klasifikasi_ke']}): "
                             f"{'lolos' if v['lolos'] else 'ditolak'}; LLM {'lolos' if v['lolos_menurut_llm'] else 'tolak'}; "
                             f"alasan: {' | '.join(a[:200] for a in v['alasan'])}")
            lines.append(f"  - riwayat label klasifikasi: {' -> '.join(history.get(i, [])) or '—'}; label akhir "
                         f"{agent[i]['label']} (klasifikasi ke-{agent[i].get('klasifikasi_dipakai')}), status {agent[i]['status']}, "
                         f"benar {truth[i]['label']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Perbandingan pilot E vs C")
    parser.add_argument("--ids", type=Path, default=RESULTS / "pilot" / "pilot_ids.json")
    parser.add_argument("--agent", type=Path, default=RESULTS / "pilot" / "agent.jsonl")
    parser.add_argument("--single", type=Path, default=RESULTS / "llm_single.jsonl")
    parser.add_argument("--single-pilot", type=Path, default=RESULTS / "pilot" / "llm_single.jsonl")
    parser.add_argument("--calls", type=Path, default=RESULTS / "agent_calls.jsonl")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    text = compare(args.ids, args.agent, args.single, args.single_pilot, args.calls)
    print(text)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
