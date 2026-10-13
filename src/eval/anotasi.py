"""Paket audit manusia untuk revisi jurnal (keputusan penulis 2026-10-13). Pelabelan dan penilaian dikerjakan penulis dan
satu anotator lain; skrip ini hanya menyiapkan berkas dan menghitung hasilnya.

siapkan:
- 100 baris test_sample_500 dipilih stratified per kelas (SQLI 17, XSS 17, PATH_TRAVERSAL 17, CMD_INJECTION 17,
  WEB_SCANNING 16, NORMAL 16): baris tiap kelas diurut menurut id lalu diambil acak dengan random_state 42; daftar id
  -> data/processed/audit_100_ids.json (tanpa label).
- Fase A (label): audit/anotasi_A_anotator1.xlsx dan audit/anotasi_A_anotator2.xlsx berisi baris yang sama dengan urutan
  acak berbeda per anotator (seed 1 dan 2). Kolom: no, id, raw_log_masked, path_norm, query_norm, ua_norm,
  label_anotator (dropdown 6 kelas), catatan. Tidak memuat label kelas maupun keluaran model. Lembar Panduan berisi
  Tabel 1 manuskrip apa adanya dan aturan pelabelan penulis.
- Fase B (relevansi bukti): item evidence llm_single_r1 dan agent_r1 untuk 100 baris yang sama, satu baris per item
  unik (id, label_prediksi, evidence_item); item yang identik di kedua metode digabung. Metode disamarkan: tidak ada
  kolom metode, urutan acak berbeda per anotator (seed 11 dan 12). Kolom: no, id, raw_log_masked, label_prediksi,
  evidence_item, skor (dropdown 0/1/2), catatan. Pemetaan butir -> metode disimpan terpisah di
  data/processed/audit_B_key.json, yang tidak dibagikan ke anotator.
hitung: membaca keempat berkas terisi -> reports/revisi_anotasi.md (+ .json):
- Fase A: kappa Cohen tak berbobot antar anotator dan persen setuju; kappa tiap anotator vs label gerbang bukti; label
  konsensus (setuju) atau "perlu diskusi" beserta daftar barisnya; baris yang konsensusnya berbeda dari label gerbang.
- Fase B: rerata skor relevansi per metode setelah kunci dibuka, kappa berbobot kuadratik antar anotator, distribusi skor
  0/1/2 per metode, dan rerata skor pada baris yang labelnya benar vs salah.
Jalankan: python -m src.eval.anotasi siapkan | python -m src.eval.anotasi hitung --a1 ... --a2 ... --b1 ... --b2 ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from openpyxl import Workbook, load_workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation
from sklearn.metrics import cohen_kappa_score

from ..common.inputs import SAMPLE_PATH
from ..data.config import CLASSES, RANDOM_STATE, ROOT

QUOTA = {"SQLI": 17, "XSS": 17, "PATH_TRAVERSAL": 17, "CMD_INJECTION": 17, "WEB_SCANNING": 16, "NORMAL": 16}
IDS_PATH = ROOT / "data" / "processed" / "audit_100_ids.json"
KEY_PATH = ROOT / "data" / "processed" / "audit_B_key.json"
OUT_DIR = ROOT / "audit"
RESULTS = ROOT / "results"
METHOD_RUNS = {"llm_single": "llm_single_r1", "agent": "agent_r1"}
SEEDS_A = {"anotator1": 1, "anotator2": 2}
SEEDS_B = {"anotator1": 11, "anotator2": 12}
COLUMNS_A = ("no", "id", "raw_log_masked", "path_norm", "query_norm", "ua_norm", "label_anotator", "catatan")
COLUMNS_B = ("no", "id", "raw_log_masked", "label_prediksi", "evidence_item", "skor", "catatan")
SCORES = (0, 1, 2)
DISCUSS = "perlu diskusi"

# Tabel 1 manuskrip revisi (revisi_v2.docx), disalin apa adanya.
TABLE_1 = (
    ("Class", "Code", "Definition", "Indicators in request, user agent, or referer"),
    ("SQL injection", "SQLI", "SQL syntax injected into a parameter to manipulate a database query",
     "' OR 1=1, UNION SELECT, SLEEP(, comments -- or #, often URL-encoded (%27, %20)"),
    ("Cross-site scripting", "XSS", "Client-side script injected for execution in the victim's browser",
     "<script>, onerror=, javascript:, encoded variants (%3Cscript%3E), may appear in the referer"),
    ("Path traversal / file inclusion", "PATH_TRAVERSAL",
     "Access to files outside the web root, or local/remote file inclusion",
     "../, ..%2f, /etc/passwd, win.ini, external URLs with a scheme (http://...) in a path or parameter (RFI)"),
    ("Command injection", "CMD_INJECTION", "OS commands injected through a parameter",
     "Command separators (;, &&, |) followed by shell commands such as id, cat /etc/passwd, sleep 15; backtick or $(...) "
     "substitution; encoded variants (%7C, %26%26, %60); Shellshock; PHP-CGI -d allow_url_include"),
    ("Web scanning / enumeration", "WEB_SCANNING", "Automated probing for files, directories, or server capabilities",
     "Scanner user agents (Nmap, zgrab, sqlmap), non-standard methods (PROPFIND, MKCOL, TRACK), backup/VCS files (.bak, "
     ".swp, .git/), probes for /.env, /wp-login.php"),
    ("Normal", "NORMAL", "Legitimate user or search-engine crawler request",
     "Ordinary URI, alphanumeric parameters, status 200/301/304, browser or verified bot user agent"),
)
RULES_A = (
    "Beri label hanya dari apa yang terlihat di baris.",
    "Bila ragu antara serangan dan NORMAL, pilih NORMAL.",
    "Bila ragu antara dua kelas serangan, pilih yang payload-nya paling eksplisit.",
)
HOWTO_A = (
    "Pilih satu kelas di kolom label_anotator untuk setiap baris (dropdown). Kolom catatan boleh dikosongkan.",
    "Jangan mengubah kolom lain dan jangan menghapus baris; mengurutkan ulang baris boleh.",
    "Kerjakan sendiri tanpa berdiskusi dengan anotator lain dan tanpa melihat label dataset atau keluaran model sampai "
    "kedua berkas selesai.",
)
SCALE_B = (
    ("0", "Tidak ada di baris log, atau tidak relevan."),
    ("1", "Ada di baris log, tetapi tidak menunjukkan kelas yang diprediksi."),
    ("2", "Ada di baris log dan menunjukkan kelas yang diprediksi."),
)
HOWTO_B = (
    "Nilai setiap item evidence terhadap label_prediksi di baris yang sama, bukan terhadap label yang menurut Anda benar.",
    "Item dianggap ada bila muncul di baris log apa adanya atau setelah URL-decode (mis. ' OR 1=1 untuk %27%20OR%201=1).",
    "Pilih skor 0, 1, atau 2 di kolom skor (dropdown). Kolom catatan boleh dikosongkan.",
    "Jangan mengubah kolom lain dan jangan menghapus baris; mengurutkan ulang baris boleh. Kerjakan sendiri.",
)
# Dua contoh netral: baris rekaan (alamat IP dokumentasi RFC 5737), bukan dari dataset maupun keluaran metode.
EXAMPLES_B = (
    ('203.0.113.5 - - [01/Jan/2020:00:00:00 +0000] "GET /produk.php?id=7%20UNION%20SELECT%20username,password%20FROM'
     '%20users HTTP/1.1" 200 512 "-" "Mozilla/5.0"', "SQLI",
     (("UNION SELECT username,password", 2, "ada setelah URL-decode dan menunjukkan SQL injection"),
      ("GET /produk.php", 1, "ada, tetapi tidak menunjukkan SQL injection"),
      ("DROP TABLE users", 0, "tidak ada di baris log"))),
    ('198.51.100.7 - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020/03/22/hello-world/ HTTP/1.1" 200 8042 "-" '
     '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"', "NORMAL",
     (("/blog/index.php/2020/03/22/hello-world/", 2, "ada dan menunjukkan permintaan halaman yang wajar"),
      ("GET", 1, "ada, tetapi tidak membedakan permintaan normal dari serangan"),
      ("<script>", 0, "tidak ada di baris log"))),
)

HEADER_FONT = Font(bold=True)
INPUT_FILL = PatternFill("solid", fgColor="FFF2CC")
WRAP = Alignment(wrap_text=True, vertical="top")


# ------------------------------------------------------------------------------------------------- siapkan


def _clean(value):
    """Teks aman untuk xlsx: karakter kontrol yang tidak sah di XML ditulis sebagai \\xhh."""
    if isinstance(value, str):
        return ILLEGAL_CHARACTERS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", value)
    return value


def _put(ws, row: int, col: int, value):
    cell = ws.cell(row=row, column=col, value=_clean(value))
    if isinstance(value, str):
        cell.data_type = "s"  # jangan pernah ditafsirkan sebagai rumus (teks payload bisa diawali '=')
    return cell


def load_sample(path: Path = SAMPLE_PATH) -> pd.DataFrame:
    return pd.read_json(path, lines=True, dtype={"id": str})


def select_ids(sample: pd.DataFrame, quota: dict[str, int] = QUOTA, random_state: int = RANDOM_STATE) -> list[str]:
    ids = []
    for label in CLASSES:
        rows = sample[sample["label"] == label].sort_values("id")
        if len(rows) < quota[label]:
            raise ValueError(f"{label}: hanya {len(rows)} baris, kuota {quota[label]}")
        ids += rows.sample(n=quota[label], random_state=random_state)["id"].tolist()
    return ids


def _shuffled(items: list, seed: int) -> list:
    order = np.random.default_rng(seed).permutation(len(items))
    return [items[k] for k in order]


def _sheet(wb: Workbook, title: str, columns: tuple[str, ...], rows: list[list], dropdown: tuple[str, list[str]],
           widths: dict[str, int]):
    ws = wb.active
    ws.title = title
    for c, name in enumerate(columns, 1):
        _put(ws, 1, c, name).font = HEADER_FONT
    for r, values in enumerate(rows, 2):
        for c, value in enumerate(values, 1):
            _put(ws, r, c, value).alignment = WRAP
    column, options = dropdown
    letter = ws.cell(row=1, column=columns.index(column) + 1).column_letter
    validation = DataValidation(type="list", formula1='"' + ",".join(options) + '"', allow_blank=True,
                                showErrorMessage=True, errorTitle="Nilai tidak sah",
                                error="Pilih salah satu nilai dari daftar.")
    ws.add_data_validation(validation)
    if rows:
        validation.add(f"{letter}2:{letter}{len(rows) + 1}")
    for name in (column, "catatan"):
        idx = columns.index(name) + 1
        for r in range(2, len(rows) + 2):
            ws.cell(row=r, column=idx).fill = INPUT_FILL
    for c, name in enumerate(columns, 1):
        ws.column_dimensions[ws.cell(row=1, column=c).column_letter].width = widths.get(name, 14)
    ws.freeze_panes = "A2"
    return ws


def _guide(wb: Workbook, lines: list[list[str]]):
    ws = wb.create_sheet("Panduan")
    for r, values in enumerate(lines, 1):
        for c, value in enumerate(values, 1):
            _put(ws, r, c, value).alignment = WRAP
    for letter, width in zip("ABCD", (34, 18, 50, 80)):
        ws.column_dimensions[letter].width = width
    return ws


def build_phase_a(sample: pd.DataFrame, ids: list[str], seed: int, path: Path) -> list[str]:
    by_id = sample.set_index("id")
    order = _shuffled(ids, seed)
    rows = [[k, i, *(by_id.at[i, c] if pd.notna(by_id.at[i, c]) else "" for c in COLUMNS_A[2:6]), "", ""]
            for k, i in enumerate(order, 1)]
    wb = Workbook()
    _sheet(wb, "Anotasi", COLUMNS_A, rows, ("label_anotator", list(CLASSES)),
           {"no": 6, "id": 24, "raw_log_masked": 70, "path_norm": 40, "query_norm": 40, "ua_norm": 40,
            "label_anotator": 20, "catatan": 30})
    guide = [["FASE A — LABEL KELAS"], [""], ["Definisi kelas (Tabel 1 manuskrip)"], *[list(r) for r in TABLE_1], [""],
             ["Aturan pelabelan"], *[[f"{k}. {rule}"] for k, rule in enumerate(RULES_A, 1)], [""], ["Cara mengisi"],
             *[[f"- {line}"] for line in HOWTO_A]]
    _guide(wb, guide)
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return order


def evidence_items(results: dict[str, Path], ids: list[str]) -> list[dict]:
    """Butir unik (id, label_prediksi, evidence_item) beserta asal metodenya, urut id lalu kemunculan."""
    wanted, items, index = set(ids), [], {}
    for method, path in results.items():
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row["id"] not in wanted:
                continue
            for k, item in enumerate(e for e in row.get("evidence") or [] if isinstance(e, str)):
                key = (row["id"], row["label"], item)
                if key not in index:
                    index[key] = len(items)
                    items.append({"id": row["id"], "label_prediksi": row["label"], "evidence_item": item, "asal": []})
                items[index[key]]["asal"].append({"metode": method, "run": path.stem, "indeks_item": k})
    position = {i: k for k, i in enumerate(ids)}
    items.sort(key=lambda x: position[x["id"]])
    for k, item in enumerate(items, 1):
        item["butir"] = f"B{k:04d}"
    return items


def build_phase_b(sample: pd.DataFrame, items: list[dict], seed: int, path: Path) -> list[str]:
    logs = dict(zip(sample["id"], sample["raw_log_masked"]))
    order = _shuffled(items, seed)
    rows = [[k, x["id"], logs[x["id"]], x["label_prediksi"], x["evidence_item"], "", ""] for k, x in enumerate(order, 1)]
    wb = Workbook()
    _sheet(wb, "Anotasi", COLUMNS_B, rows, ("skor", [str(s) for s in SCORES]),
           {"no": 6, "id": 24, "raw_log_masked": 70, "label_prediksi": 18, "evidence_item": 40, "skor": 8, "catatan": 30})
    guide = [["FASE B — RELEVANSI BUKTI"], [""], ["Skala skor"], *[[s, d] for s, d in SCALE_B], [""], ["Cara menilai"],
             *[[f"- {line}"] for line in HOWTO_B], [""], ["Contoh netral (baris rekaan, bukan dari data audit)"]]
    for k, (line, label, cases) in enumerate(EXAMPLES_B, 1):
        guide += [[f"Contoh {k}", f"label_prediksi: {label}"], ["baris log", line],
                  *[[f'item "{item}"', f"skor {score}", reason] for item, score, reason in cases], [""]]
    guide += [["Definisi kelas (Tabel 1 manuskrip)"], *[list(r) for r in TABLE_1]]
    _guide(wb, guide)
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return [x["butir"] for x in order]


def prepare(sample_path: Path = SAMPLE_PATH, out_dir: Path = OUT_DIR, ids_path: Path = IDS_PATH,
            key_path: Path = KEY_PATH, results: dict[str, Path] | None = None, quota: dict[str, int] = QUOTA) -> dict:
    sample = load_sample(sample_path)
    ids = select_ids(sample, quota)
    source_sha = hashlib.sha256(sample_path.read_bytes()).hexdigest()
    ids_path.parent.mkdir(parents=True, exist_ok=True)
    ids_path.write_text(json.dumps({"ids": ids, "kuota": quota, "random_state": RANDOM_STATE,
                                    "sumber": str(sample_path.relative_to(ROOT)) if sample_path.is_relative_to(ROOT)
                                    else str(sample_path), "sumber_sha256": source_sha}, indent=1) + "\n",
                        encoding="utf-8")
    files_a = {who: out_dir / f"anotasi_A_{who}.xlsx" for who in SEEDS_A}
    for who, path in files_a.items():
        build_phase_a(sample, ids, SEEDS_A[who], path)
    results = results or {m: RESULTS / f"{run}.jsonl" for m, run in METHOD_RUNS.items()}
    items = evidence_items(results, ids)
    files_b = {who: out_dir / f"anotasi_B_{who}.xlsx" for who in SEEDS_B}
    orders = {who: build_phase_b(sample, items, SEEDS_B[who], path) for who, path in files_b.items()}
    key = {"keterangan": "Kunci Fase B: jangan dibagikan ke anotator. 'urutan' memberi butir untuk setiap nomor baris "
                         "(no = posisi + 1) di berkas anotator.",
           "seed_fase_a": SEEDS_A, "seed_fase_b": SEEDS_B, "run": {m: p.stem for m, p in results.items()},
           "butir": items, "urutan": orders}
    key_path.write_text(json.dumps(key, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return {"ids": ids, "fase_a": files_a, "fase_b": files_b, "kunci": key_path, "butir": len(items)}


# ------------------------------------------------------------------------------------------------- hitung


def read_sheet(path: Path, columns: tuple[str, ...]) -> list[dict]:
    ws = load_workbook(path, data_only=True)["Anotasi"]
    header = [str(c.value).strip() if c.value is not None else "" for c in ws[1]]
    missing = [c for c in columns if c not in header]
    if missing:
        raise ValueError(f"{path.name}: kolom hilang {missing}")
    pos = {c: header.index(c) for c in columns}
    rows = []
    for values in ws.iter_rows(min_row=2, values_only=True):
        if all(v is None or str(v).strip() == "" for v in values):
            continue
        rows.append({c: values[pos[c]] for c in columns})
    return rows


def _label(value) -> str | None:
    text = re.sub(r"\s+", "", str(value or "")).upper()
    return text if text in CLASSES else None


def _score(value) -> int | None:
    try:
        number = float(str(value).strip())
    except ValueError:
        return None
    return int(number) if number in SCORES else None


def labels_a(path: Path, ids: list[str]) -> dict[str, str]:
    rows = read_sheet(path, COLUMNS_A)
    found = Counter(str(r["id"]) for r in rows)
    problems = [f"id ganda {i}" for i, n in found.items() if n > 1]
    problems += [f"id tidak dikenal {i}" for i in found if i not in set(ids)]
    problems += [f"id hilang {i}" for i in ids if i not in found]
    out = {}
    for r in rows:
        label = _label(r["label_anotator"])
        if label is None:
            problems.append(f"no {r['no']} ({r['id']}): label kosong/tidak sah {r['label_anotator']!r}")
        out[str(r["id"])] = label
    if problems:
        raise ValueError(f"{path.name}: " + "; ".join(problems[:20]) + (" ..." if len(problems) > 20 else ""))
    return out


def scores_b(path: Path, key: dict, who: str) -> dict[str, int]:
    rows = read_sheet(path, COLUMNS_B)
    items = {x["butir"]: x for x in key["butir"]}
    order = key["urutan"][who]
    out, problems = {}, []
    for r in rows:
        try:
            butir = order[int(r["no"]) - 1]
        except (TypeError, ValueError, IndexError):
            problems.append(f"no tidak sah {r['no']!r}")
            continue
        x = items[butir]
        if (str(r["id"]), str(r["label_prediksi"]), str(r["evidence_item"])) != \
                (x["id"], x["label_prediksi"], str(_clean(x["evidence_item"]))):
            problems.append(f"no {r['no']}: isi baris tidak cocok dengan kunci")
            continue
        score = _score(r["skor"])
        if score is None:
            problems.append(f"no {r['no']}: skor kosong/tidak sah {r['skor']!r}")
        if butir in out:
            problems.append(f"no {r['no']}: baris ganda")
        out[butir] = score
    problems += [f"butir hilang {b}" for b in order if b not in out]
    if problems:
        raise ValueError(f"{path.name}: " + "; ".join(problems[:20]) + (" ..." if len(problems) > 20 else ""))
    return out


def phase_a_report(first: dict[str, str], second: dict[str, str], gate: dict[str, str], ids: list[str]) -> dict:
    l1, l2, g = ([d[i] for i in ids] for d in (first, second, gate))
    consensus = {i: (a if a == b else DISCUSS) for i, a, b in zip(ids, l1, l2)}
    return {
        "n": len(ids),
        "kappa_antar_anotator": float(cohen_kappa_score(l1, l2)),
        "persen_setuju": 100 * float(np.mean([a == b for a, b in zip(l1, l2)])),
        "kappa_anotator1_vs_gerbang": float(cohen_kappa_score(l1, g)),
        "kappa_anotator2_vs_gerbang": float(cohen_kappa_score(l2, g)),
        "perlu_diskusi": [{"id": i, "anotator1": first[i], "anotator2": second[i]} for i in ids
                          if consensus[i] == DISCUSS],
        "konsensus_beda_gerbang": [{"id": i, "konsensus": consensus[i], "gerbang": gate[i]} for i in ids
                                   if consensus[i] not in (DISCUSS, gate[i])],
        "konsensus": consensus,
    }


def phase_b_report(key: dict, s1: dict[str, int], s2: dict[str, int], gate: dict[str, str]) -> dict:
    butir = list(s1)
    out = {"butir": len(butir), "kappa_berbobot_kuadratik": float(cohen_kappa_score(
        [s1[b] for b in butir], [s2[b] for b in butir], weights="quadratic", labels=list(SCORES))), "metode": {}}
    methods = sorted({a["metode"] for x in key["butir"] for a in x["asal"]})
    for method in methods:
        inst = [(x, a) for x in key["butir"] for a in x["asal"] if a["metode"] == method]
        mean_both = [(s1[x["butir"]] + s2[x["butir"]]) / 2 for x, _ in inst]
        correct = [(s1[x["butir"]] + s2[x["butir"]]) / 2 for x, _ in inst if x["label_prediksi"] == gate[x["id"]]]
        wrong = [(s1[x["butir"]] + s2[x["butir"]]) / 2 for x, _ in inst if x["label_prediksi"] != gate[x["id"]]]
        out["metode"][method] = {
            "item": len(inst), "baris": len({x["id"] for x, _ in inst}),
            "rerata_anotator1": statistics.mean(s1[x["butir"]] for x, _ in inst),
            "rerata_anotator2": statistics.mean(s2[x["butir"]] for x, _ in inst),
            "rerata": statistics.mean(mean_both),
            "distribusi_anotator1": {s: sum(s1[x["butir"]] == s for x, _ in inst) for s in SCORES},
            "distribusi_anotator2": {s: sum(s2[x["butir"]] == s for x, _ in inst) for s in SCORES},
            "rerata_label_benar": statistics.mean(correct) if correct else None, "item_label_benar": len(correct),
            "rerata_label_salah": statistics.mean(wrong) if wrong else None, "item_label_salah": len(wrong),
        }
    return out


def _f(x, digits: int = 3) -> str:
    return "–" if x is None else f"{x:.{digits}f}"


def render(a: dict, b: dict, files: dict[str, Path]) -> str:
    out = ["# Audit manusia — hasil anotasi", "", "Berkas: " + ", ".join(f"{k} = {v.name}" for k, v in files.items()), "",
           "## Fase A — label kelas (100 baris)", ""]
    out += [f"- Cohen's κ antar anotator (tak berbobot): {_f(a['kappa_antar_anotator'])}; persen setuju "
            f"{_f(a['persen_setuju'], 1)}%.",
            f"- κ anotator 1 vs label gerbang bukti: {_f(a['kappa_anotator1_vs_gerbang'])}; κ anotator 2 vs label gerbang: "
            f"{_f(a['kappa_anotator2_vs_gerbang'])}.",
            f"- Perlu diskusi (anotator tidak setuju): {len(a['perlu_diskusi'])} baris.",
            f"- Konsensus berbeda dari label gerbang: {len(a['konsensus_beda_gerbang'])} baris.", ""]
    if a["perlu_diskusi"]:
        out += ["Baris yang perlu diskusi (label gerbang sengaja tidak ditampilkan):", "",
                "| id | anotator 1 | anotator 2 |", "|---|---|---|",
                *[f"| {x['id']} | {x['anotator1']} | {x['anotator2']} |" for x in a["perlu_diskusi"]], ""]
    if a["konsensus_beda_gerbang"]:
        out += ["Baris yang konsensusnya berbeda dari label gerbang:", "", "| id | konsensus | label gerbang |",
                "|---|---|---|", *[f"| {x['id']} | {x['konsensus']} | {x['gerbang']} |" for x in a["konsensus_beda_gerbang"]],
                ""]
        counts = Counter((x["gerbang"], x["konsensus"]) for x in a["konsensus_beda_gerbang"])
        out += ["Ringkasan per kelas (gerbang -> konsensus): " + "; ".join(f"{g} -> {c}: {n}" for (g, c), n in
                                                                          sorted(counts.items())), ""]
    out += ["## Fase B — relevansi bukti (skala 0–2)", "",
            f"- Butir unik: {b['butir']}; κ berbobot kuadratik antar anotator: {_f(b['kappa_berbobot_kuadratik'])}.", "",
            "| metode | item | baris | rerata (2 anotator) | rerata anotator 1 | rerata anotator 2 | skor 0/1/2 anotator 1 "
            "| skor 0/1/2 anotator 2 | rerata, label benar (item) | rerata, label salah (item) |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for method, x in b["metode"].items():
        d1, d2 = x["distribusi_anotator1"], x["distribusi_anotator2"]
        out.append(f"| {method} | {x['item']} | {x['baris']} | {_f(x['rerata'], 2)} | {_f(x['rerata_anotator1'], 2)} | "
                   f"{_f(x['rerata_anotator2'], 2)} | {d1[0]}/{d1[1]}/{d1[2]} | {d2[0]}/{d2[1]}/{d2[2]} | "
                   f"{_f(x['rerata_label_benar'], 2)} ({x['item_label_benar']}) | {_f(x['rerata_label_salah'], 2)} "
                   f"({x['item_label_salah']}) |")
    out += ["", "Rerata (2 anotator) = rerata atas item dari skor rata-rata kedua anotator. Item yang identik di kedua "
            "metode dinilai sekali dan dihitung untuk keduanya. Label benar/salah menurut label gerbang bukti."]
    return "\n".join(out) + "\n"


def compute(files: dict[str, Path], ids_path: Path = IDS_PATH, key_path: Path = KEY_PATH,
            sample_path: Path = SAMPLE_PATH) -> tuple[dict, dict, str]:
    ids = json.loads(ids_path.read_text(encoding="utf-8"))["ids"]
    key = json.loads(key_path.read_text(encoding="utf-8"))
    sample = load_sample(sample_path)
    gate = dict(zip(sample["id"], sample["label"]))
    a = phase_a_report(labels_a(files["A1"], ids), labels_a(files["A2"], ids), gate, ids)
    b = phase_b_report(key, scores_b(files["B1"], key, "anotator1"), scores_b(files["B2"], key, "anotator2"), gate)
    return a, b, render(a, b, files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Paket audit manusia (Fase A label, Fase B relevansi bukti)")
    sub = parser.add_subparsers(dest="perintah", required=True)
    sub.add_parser("siapkan", help="buat daftar id, empat berkas anotasi, dan kunci Fase B")
    count = sub.add_parser("hitung", help="hitung hasil dari berkas yang sudah diisi")
    for name in ("a1", "a2", "b1", "b2"):
        count.add_argument(f"--{name}", type=Path, required=True)
    count.add_argument("--out", type=Path, default=ROOT / "reports" / "revisi_anotasi.md")
    args = parser.parse_args(argv)
    if args.perintah == "siapkan":
        done = prepare()
        print(f"[anotasi] {len(done['ids'])} baris, {done['butir']} butir Fase B; berkas: "
              + ", ".join(str(p.relative_to(ROOT)) for p in [*done["fase_a"].values(), *done["fase_b"].values()])
              + f"; kunci {done['kunci'].relative_to(ROOT)}")
        return 0
    files = {"A1": args.a1, "A2": args.a2, "B1": args.b1, "B2": args.b2}
    a, b, text = compute(files)
    print(text)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    args.out.with_suffix(".json").write_text(json.dumps({"fase_a": a, "fase_b": b}, ensure_ascii=False, indent=1) + "\n",
                                             encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
