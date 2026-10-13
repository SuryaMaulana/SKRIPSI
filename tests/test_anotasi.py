import json

import pytest
from openpyxl import load_workbook

from src.data.config import CLASSES
from src.eval import anotasi as an

QUOTA = dict.fromkeys(CLASSES, 1)


def _sample(tmp_path):
    rows = []
    for k, label in enumerate(CLASSES):
        for j in range(2):
            i = f"srbh-{k}{j}"
            rows.append({"id": i, "label": label, "template_key": f"t{k}", "raw_log_masked": f"1.2.3.4 - - [x] \"GET /{i}?q=1\"",
                         "path_norm": f"/{i}", "query_norm": "=cmd|' /C calc'!A0" if k == 0 else "q=1", "ua_norm": "UA"})
    path = tmp_path / "sample.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path, rows


def _results(tmp_path, rows):
    single, agent = [], []
    for r in rows:
        single.append({"id": r["id"], "label": r["label"], "evidence": [f"/{r['id']}", "GET", 7, ""]})
        agent.append({"id": r["id"], "label": "NORMAL" if r["label"] == "XSS" else r["label"], "evidence": [f"/{r['id']}"]})
    paths = {"llm_single": tmp_path / "llm_single_r1.jsonl", "agent": tmp_path / "agent_r1.jsonl"}
    for method, data in (("llm_single", single), ("agent", agent)):
        paths[method].write_text("".join(json.dumps(x) + "\n" for x in data), encoding="utf-8")
    return paths


@pytest.fixture
def package(tmp_path):
    sample_path, rows = _sample(tmp_path)
    results = _results(tmp_path, rows)
    done = an.prepare(sample_path, tmp_path / "audit", tmp_path / "ids.json", tmp_path / "key.json", results, QUOTA)
    return {"tmp": tmp_path, "sample": sample_path, "rows": {r["id"]: r for r in rows}, "done": done}


def _data(path):
    ws = load_workbook(path)["Anotasi"]
    header = [c.value for c in ws[1]]
    return ws, header, [dict(zip(header, (c.value for c in row))) for row in ws.iter_rows(min_row=2)]


def test_selection_is_stratified_deterministic_and_saved_without_labels(package):
    ids_file = json.loads((package["tmp"] / "ids.json").read_text())
    assert len(ids_file["ids"]) == 6 and ids_file["random_state"] == 42 and "label" not in json.dumps(ids_file["ids"])
    assert sorted(package["rows"][i]["label"] for i in ids_file["ids"]) == sorted(CLASSES)
    again = an.select_ids(an.load_sample(package["sample"]), QUOTA)
    assert again == ids_file["ids"]
    assert sum(an.QUOTA.values()) == 100 and list(an.QUOTA.values()) == [17, 17, 17, 17, 16, 16]


def test_phase_a_files_have_the_requested_columns_no_labels_or_model_output_and_a_dropdown(package):
    files = package["done"]["fase_a"]
    orders = []
    for who, path in files.items():
        ws, header, rows = _data(path)
        assert tuple(header) == an.COLUMNS_A
        assert all(r["label_anotator"] is None and r["catatan"] is None for r in rows)
        values = {str(v) for r in rows for k, v in r.items() if k not in ("label_anotator", "catatan")}
        assert not values & set(CLASSES)  # tidak ada label kelas di data
        assert not any("GET" == v for v in values)  # tidak ada item evidence model
        (validation,) = ws.data_validations.dataValidation
        assert validation.formula1 == '"' + ",".join(CLASSES) + '"' and "G2:G7" in str(validation.sqref)
        formula_cell = [c for c in ws["E"] if isinstance(c.value, str) and c.value.startswith("=cmd")]
        assert formula_cell and formula_cell[0].data_type == "s"  # payload berawalan '=' tetap teks
        guide = [[c.value for c in row] for row in load_workbook(path)["Panduan"].iter_rows()]
        assert [list(r) for r in an.TABLE_1] == [g[:4] for g in guide if g[0] in {r[0] for r in an.TABLE_1}]
        assert all(any(rule in str(g[0]) for g in guide) for rule in an.RULES_A)
        orders.append([r["id"] for r in rows])
    assert sorted(orders[0]) == sorted(orders[1]) and orders[0] != orders[1]


def test_phase_b_hides_methods_merges_identical_items_and_keeps_the_key_separate(package):
    key = json.loads((package["tmp"] / "key.json").read_text())
    items = {x["butir"]: x for x in key["butir"]}
    shared = [x for x in key["butir"] if len(x["asal"]) == 2]
    assert shared and {a["metode"] for a in shared[0]["asal"]} == {"llm_single", "agent"}
    assert all(isinstance(x["evidence_item"], str) for x in key["butir"])  # item non-string dibuang
    for who, path in package["done"]["fase_b"].items():
        ws, header, rows = _data(path)
        assert tuple(header) == an.COLUMNS_B and "metode" not in header
        assert [r["id"] for r in rows] == [items[b]["id"] for b in key["urutan"][who]]
        assert [r["no"] for r in rows] == list(range(1, len(rows) + 1))
        (validation,) = ws.data_validations.dataValidation
        assert validation.formula1 == '"0,1,2"'
    assert key["urutan"]["anotator1"] != key["urutan"]["anotator2"]


def _fill(path, column, values_by_row):
    wb = load_workbook(path)
    ws = wb["Anotasi"]
    header = [c.value for c in ws[1]]
    col = header.index(column) + 1
    for r in range(2, ws.max_row + 1):
        ws.cell(row=r, column=col, value=values_by_row(dict(zip(header, (c.value for c in ws[r])))))
    wb.save(path)


def test_compute_reports_kappa_consensus_and_relevance_from_filled_files(package):
    rows, done, tmp = package["rows"], package["done"], package["tmp"]
    gate = {i: r["label"] for i, r in rows.items()}
    ids = json.loads((tmp / "ids.json").read_text())["ids"]
    disagree, both_wrong = ids[0], ids[1]
    _fill(done["fase_a"]["anotator1"], "label_anotator",
          lambda r: "NORMAL" if r["id"] == both_wrong else gate[r["id"]])
    _fill(done["fase_a"]["anotator2"], "label_anotator",
          lambda r: "NORMAL" if r["id"] in (both_wrong, disagree) else gate[r["id"]].lower())
    _fill(done["fase_b"]["anotator1"], "skor", lambda r: 2)
    _fill(done["fase_b"]["anotator2"], "skor", lambda r: "1" if r["evidence_item"] == "GET" else 2)
    files = {"A1": done["fase_a"]["anotator1"], "A2": done["fase_a"]["anotator2"],
             "B1": done["fase_b"]["anotator1"], "B2": done["fase_b"]["anotator2"]}
    a, b, text = an.compute(files, tmp / "ids.json", tmp / "key.json", package["sample"])
    assert a["n"] == 6 and a["persen_setuju"] == pytest.approx(100 * 5 / 6)
    assert [x["id"] for x in a["perlu_diskusi"]] == [disagree]
    assert a["konsensus_beda_gerbang"] == [{"id": both_wrong, "konsensus": "NORMAL", "gerbang": gate[both_wrong]}]
    assert a["kappa_anotator1_vs_gerbang"] == pytest.approx(an.cohen_kappa_score(
        [gate[i] if i != both_wrong else "NORMAL" for i in ids], [gate[i] for i in ids]))
    single, agent = b["metode"]["llm_single"], b["metode"]["agent"]
    assert single["item"] == 18 and agent["item"] == 6  # 6 baris x (path + GET + item kosong) / 6 baris x path
    shown = [r["evidence_item"] for r in _data(done["fase_b"]["anotator1"])[2]]
    assert shown.count(an.EMPTY_ITEM) == 6 and None not in shown
    assert single["rerata_anotator1"] == 2 and single["rerata_anotator2"] == pytest.approx((6 * 1 + 12 * 2) / 18)
    assert single["distribusi_anotator2"] == {0: 0, 1: 6, 2: 12} and agent["rerata"] == 2
    assert agent["item_label_salah"] == 1 and single["item_label_salah"] == 0  # agent memberi NORMAL pada XSS
    assert "Cohen's κ antar anotator" in text and "κ berbobot kuadratik" in text
    # label gerbang per id hanya di results/: laporan reports/ memuat agregat dan daftar "perlu diskusi" saja
    assert both_wrong not in text and disagree in text and "results/revisi_anotasi_per_baris.json" in text
    an.write_outputs(a, b, text, tmp / "reports" / "anotasi.md", tmp / "results" / "per_baris.json")
    public = json.loads((tmp / "reports" / "anotasi.json").read_text())
    assert "konsensus" not in public["fase_a"] and "konsensus_beda_gerbang" not in public["fase_a"]
    assert both_wrong not in json.dumps(public) and public["fase_a"]["jumlah_konsensus_beda_gerbang"] == 1
    assert public["fase_a"]["konsensus_beda_gerbang_per_kelas"] == {f"{gate[both_wrong]} -> NORMAL": 1}
    per_row = json.loads((tmp / "results" / "per_baris.json").read_text())
    assert per_row["konsensus_beda_gerbang"] == a["konsensus_beda_gerbang"] and len(per_row["konsensus"]) == 6
    assert "asal" not in json.dumps(per_row) and "metode" not in json.dumps(per_row)  # kunci Fase B tidak ikut


def test_compute_refuses_incomplete_or_edited_files(package):
    done, tmp = package["done"], package["tmp"]
    files = {"A1": done["fase_a"]["anotator1"], "A2": done["fase_a"]["anotator2"],
             "B1": done["fase_b"]["anotator1"], "B2": done["fase_b"]["anotator2"]}
    with pytest.raises(ValueError, match="label kosong"):
        an.compute(files, tmp / "ids.json", tmp / "key.json", package["sample"])
    for who in ("anotator1", "anotator2"):
        _fill(done["fase_a"][who], "label_anotator", lambda r: "SQLI")
        _fill(done["fase_b"][who], "skor", lambda r: 2)
    _fill(done["fase_b"]["anotator2"], "evidence_item", lambda r: r["evidence_item"] + " (diubah)")
    with pytest.raises(ValueError, match="tidak cocok dengan kunci"):
        an.compute(files, tmp / "ids.json", tmp / "key.json", package["sample"])
