import json
from pathlib import Path

import numpy as np
import pytest

from src.data.config import CLASSES
from src.eval import revisi_tambahan as rt
from src.eval.evaluate import Method, Truth, _indices, macro_f1
from src.eval.replikasi import aggregate


def _method(name, preds, rows=None):
    rows = rows if rows is not None else [{"id": i, "label": label} for i, label in preds.items()]
    return Method(name, Path(f"/tmp/{name}.jsonl"), dict(preds), False, {}, rows)


def _entry(truth, methods):
    return {"methods": methods, "group": aggregate(methods, truth)}


def _truth(labels, keys=None):
    keys = keys or {i: f"t{i}" for i in labels}
    return Truth(dict(labels), keys, "uji", {i: "GET / HTTP/1.1" for i in labels})


def _two_per_class(prefix=""):
    labels = {f"{prefix}{c[:2]}{j}": c for c in CLASSES for j in range(2)}
    keys = {i: ("V1:MOVE" if c == "WEB_SCANNING" else f"t{i}") for i, c in labels.items()}
    return _truth(labels, keys), labels


def test_without_pilot_drops_the_pilot_ids_and_recomputes_metrics_and_paired_tests(tmp_path):
    truth, labels = _two_per_class()
    pilot = [i for i in labels if i.endswith("0")]
    (tmp_path / "pilot.json").write_text(json.dumps({"ids": pilot}))
    good = {i: c for i, c in labels.items()}
    bad = {i: ("NORMAL" if i.endswith("1") and c == "SQLI" else c) for i, c in labels.items()}
    data = {"llm_single": _entry(truth, [_method("c1", good), _method("c2", good)]),
            "agent": _entry(truth, [_method("e1", bad), _method("e2", bad)])}
    out = rt.without_pilot(truth, data, n_paired=20, pilot_path=tmp_path / "pilot.json")
    assert out["pilot"] == 6 and out["n"] == 6 and set(out["per_kelas"].values()) == {1}
    assert out["metode"]["llm_single"]["macro_f1"]["mean"] == 1.0
    rest = [i for i in labels if i not in pilot]
    t, p = _indices([labels[i] for i in rest], [bad[i] for i in rest])
    assert out["metode"]["agent"]["macro_f1"]["mean"] == pytest.approx(macro_f1(t, p))
    (test,) = out["uji_berpasangan"]
    assert (test["a"], test["b"]) == ("llm_single", "agent") and test["selisih"] == pytest.approx(1 - macro_f1(t, p))
    _, t_all, clusters, preds = rt.arrays(truth, data)
    (full,) = out["uji_berpasangan_500"]
    assert full == {"a": "llm_single", "b": "agent", **rt.paired(t_all, preds["llm_single"], preds["agent"], clusters, 20)}
    assert out["metode"]["agent"]["akurasi_pilot"]["mean"] == 1.0  # baris pilot (akhiran 0) semuanya benar
    (tmp_path / "pilot.json").write_text(json.dumps({"ids": ["tidak-ada"]}))
    with pytest.raises(ValueError, match="tidak ada di sampel"):
        rt.without_pilot(truth, data, n_paired=20, pilot_path=tmp_path / "pilot.json")


def _llm_rows(preds, cost=0.001):
    return [{"id": i, "label": label, "evidence": [], "status": "ok", "prompt_tokens": 100, "completion_tokens": 10,
             "cost_usd": cost, "latency_s": 1.0} for i, label in preds.items()]


def test_cascade_keeps_attack_labels_of_the_first_layer_and_sends_only_normal_lines_to_the_llm():
    truth, labels = _two_per_class()
    regex = {i: (c if c in ("XSS", "CMD_INJECTION") else "NORMAL") for i, c in labels.items()}
    regex["CM1"] = "PATH_TRAVERSAL"  # salah kelas regex tetap dipakai
    llm = {i: ("NORMAL" if c == "XSS" else c) for i, c in labels.items()}
    data = {"regex": _entry(truth, [_method("regex", regex)]),
            "llm_single": _entry(truth, [_method("c1", llm, _llm_rows(llm)), _method("c2", llm, _llm_rows(llm, 0.003))])}
    out = rt.cascade(truth, data, n_paired=20)["lapis_pertama"]["regex"]
    sent = {i for i, label in regex.items() if label == "NORMAL"}
    assert out["baris_ke_llm"] == len(sent) == 8
    assert out["baris_ke_llm_per_kelas"] == {"SQLI": 2, "XSS": 0, "PATH_TRAVERSAL": 2, "CMD_INJECTION": 0,
                                             "WEB_SCANNING": 2, "NORMAL": 2}
    expected = {i: (llm[i] if i in sent else regex[i]) for i in labels}
    t, p = _indices([labels[i] for i in labels], [expected[i] for i in labels])
    assert out["metrik"]["macro_f1"]["values"] == [pytest.approx(macro_f1(t, p))] * 2
    assert out["biaya_per_1000_baris_usd"]["values"] == [pytest.approx(1000 * 8 * c / 12) for c in (0.001, 0.003)]
    assert out["biaya_list_per_1000_baris_usd"]["mean"] == pytest.approx(1000 * 8 * (100 * 0.1 + 10 * 0.4) / 1e6 / 12)
    assert [x["b"] for x in out["uji_berpasangan"]] == ["llm_single", "regex"]
    assert out["baris_ke_llm_dipulihkan_per_kelas"]["SQLI"]["values"] == [2, 2]  # LLM benar pada kedua SQLI
    assert out["baris_ke_llm_dipulihkan_per_kelas"]["NORMAL"]["mean"] == 2
    assert out["recall_sub_tipe_ws"] == {"V1": rt.summarize([1.0, 1.0])}
    assert "regex_930" not in rt.cascade(truth, data, n_paired=20)["lapis_pertama"]  # tanpa matched_rules


def test_ws_subtypes_report_recall_per_gate_rule_and_the_regex_rules_that_fired():
    keys = {"v1": "V1:MKCOL", "v2": "V1:MOVE", "w1": "W1:Nmap", "p1": "P1:.bak", "t1": "T3:.git", "t2": "T3:lainnya",
            "n1": "GET /"}
    labels = {i: ("NORMAL" if i == "n1" else "WEB_SCANNING") for i in keys}
    truth = _truth(labels, keys)
    full = {i: label for i, label in labels.items()}
    rules = {"v1": ["911100"], "v2": ["911100", "BS-METHOD"], "w1": ["913100"], "p1": ["920440"], "t1": ["930130"]}
    full_rows = [{"id": i, "label": full[i], "matched_rules": [{"rule": r, "class": "WEB_SCANNING"} for r in rules.get(i, [])]
                  + [{"rule": "941100", "class": "XSS"}]} for i in keys]
    r1 = {**labels, "v1": "NORMAL", "v2": "NORMAL", "p1": "NORMAL"}
    r2 = {**labels, "v1": "NORMAL", "p1": "PARSE_ERROR"}
    data = {"regex_full": {"methods": [_method("regex_full", full, full_rows)]},
            "llm_single": {"methods": [_method("c1", r1), _method("c2", r2)]}}
    inputs = [{"id": "t2", "path": "/blog/%2Ehtaccess"}]
    out = rt.ws_subtypes(truth, data, inputs)
    assert out["n"] == {"V1": 2, "W1": 1, "P1": 1, "T3": 2}
    assert out["rincian"]["V1"] == {"V1:MKCOL": 1, "V1:MOVE": 1}
    assert out["rincian"]["T3"] == {"T3:.git": 1, "T3:.htaccess": 1}  # T3:lainnya dirinci menurut nama berkas
    assert out["metode"]["llm_single"]["V1"]["recall"]["values"] == [0.0, 0.5]
    assert out["recall_per_rincian"]["llm_single"]["V1:MOVE"]["values"] == [0.0, 1.0]
    assert out["metode"]["llm_single"]["P1"]["prediksi_rerata"] == {"NORMAL": 0.5, "invalid": 0.5}
    assert out["metode"]["regex_full"]["T3"]["recall"]["mean"] == 1.0
    assert out["aturan_regex"]["regex_full"]["V1"] == {"911100": 2, "BS-METHOD": 1}
    assert "941100" not in json.dumps(out["aturan_regex"])
    with pytest.raises(ValueError, match="tanpa nama"):
        rt.ws_subtypes(_truth(labels, {**keys, "w1": "X9:baru"}), data)


def test_label_changes_count_lines_by_gate_class_and_label_sets_like_aggregate():
    labels = {"a": "SQLI", "b": "CMD_INJECTION", "c": "WEB_SCANNING", "d": "NORMAL"}
    truth = _truth(labels)
    runs = [{"a": "SQLI", "b": "PATH_TRAVERSAL", "c": "NORMAL", "d": "NORMAL"},
            {"a": "SQLI", "b": "CMD_INJECTION", "c": "NORMAL", "d": "PARSE_ERROR"},
            {"a": "SQLI", "b": "PATH_TRAVERSAL", "c": "WEB_SCANNING", "d": "NORMAL"}]
    methods = [_method(f"r{k}", r) for k, r in enumerate(runs)]
    out = rt.label_changes(truth, {"agent": {"methods": methods}, "regex": {"methods": methods[:1]}})
    assert list(out) == ["agent"]  # metode satu run tidak dihitung
    x = out["agent"]
    assert x["baris"] == 3 == aggregate(methods, truth)["baris_label_berubah_antar_run"]
    assert x["per_kelas_gerbang"] == {"SQLI": 0, "XSS": 0, "PATH_TRAVERSAL": 0, "CMD_INJECTION": 1, "WEB_SCANNING": 1,
                                      "NORMAL": 1}
    assert x["memuat_label"]["NORMAL"] == 2 and x["memuat_label"]["invalid"] == 1
    assert (x["melibatkan_invalid"], x["antar_kelas_valid"]) == (1, 2)
    assert x["himpunan_label"] == {"PATH_TRAVERSAL / CMD_INJECTION": 1, "WEB_SCANNING / NORMAL": 1, "NORMAL / invalid": 1}


@pytest.mark.parametrize("row, expected", [
    ({"path": "/blog%27+AND+1234%3D1234--+-/x", "query": "", "user_agent": "Mozilla", "referer": ""}, {"path"}),
    ({"path": "/a.css", "query": "ver=4.9.5%27+OR+%271%27%3D%271%27+--+", "user_agent": "", "referer": ""}, {"query"}),
    ({"path": "/a.js", "query": "ver=1", "user_agent": "Mozilla' UNION ALL SELECT NULL-- -", "referer": ""},
     {"user_agent"}),
    ({"path": "/x", "query": "", "user_agent": "", "referer": "http://h/?q=1 or 1=1"}, {"referer"}),
    ({"path": "/index.php", "query": "id=1", "user_agent": "Mozilla", "referer": None}, set()),
])
def test_sql_carriers_locate_the_gate_s1_families_per_field(row, expected):
    assert rt.sql_carriers(row) == expected


def test_sqli_missed_separates_payload_in_path_from_lines_without_query_string():
    labels = {"a": "SQLI", "b": "SQLI", "c": "SQLI", "d": "SQLI", "e": "NORMAL"}
    inputs = [
        {"id": "a", "path": "/blog%27+AND+1234%3D1234--+-/x", "query": "", "user_agent": "", "referer": ""},
        {"id": "b", "path": "/blog+AND+1%3D1/x", "query": "mode=grid", "user_agent": "", "referer": ""},
        {"id": "c", "path": "/a.css", "query": "ver=1%27+OR+%271%27%3D%271%27+--+", "user_agent": "", "referer": ""},
        {"id": "d", "path": "/blog%27+AND+1234%3D1234--+-/x", "query": "", "user_agent": "", "referer": ""},
        {"id": "e", "path": "/", "query": "", "user_agent": "", "referer": ""},
    ]
    inputs.append({"id": "f", "path": "/blog+AND+1%3D1/x", "query": "id=1%27+OR+%271%27%3D%271", "user_agent": "",
                   "referer": ""})
    labels["f"] = "SQLI"
    regex = {"a": "NORMAL", "b": "NORMAL", "c": "NORMAL", "d": "SQLI", "e": "NORMAL", "f": "NORMAL"}
    rows = [{"id": i, "label": label, "matched_rules": [{"rule": "942160", "class": "SQLI"}] if i == "d" else []}
            for i, label in regex.items()]
    out = rt.sqli_missed(_truth(labels), {"regex": {"methods": [_method("regex", regex, rows)]}}, inputs,
                         {"memeriksa_path": [942160, 942550]})
    assert out["sqli"] == 5 and out["terlewat"] == 4 and out["prediksi_regex"] == {"NORMAL": 4, "SQLI": 1}
    assert out["payload_di_path"] == 3 and out["tanpa_query_string"] == 1 and out["payload_hanya_di_path"] == 2
    assert out["payload_di_path_query_string_tanpa_sql"] == 1  # f: payload juga di query string, tidak dihitung
    assert out["payload_di_query_string"] == 2
    assert out["aturan_pada_sqli_terdeteksi"] == {"942160": 1}
    assert out["baris_dengan_aturan_path"] == {"942160": 1, "942550": 0}


def test_regex_labels_rescore_matched_rules_and_remap_restricted_files_to_their_category():
    config = {"restricted_files": {"rules": [930130]}, "class_map": {"930": "PATH_TRAVERSAL"},
              "scoring": {"tie_break": ["CMD_INJECTION", "SQLI", "XSS", "PATH_TRAVERSAL", "WEB_SCANNING"]}}
    hit = lambda rule, cls, points, source="CRS 4.30.0": {"rule": rule, "class": cls, "points": points, "source": source}
    rows = [{"id": "a", "matched_rules": [hit("930130", "WEB_SCANNING", 5)]},
            {"id": "b", "matched_rules": [hit("930130", "WEB_SCANNING", 5), hit("BS-METHOD", "WEB_SCANNING", 3, "BS")]},
            {"id": "c", "matched_rules": [hit("942160", "SQLI", 5), hit("932130", "CMD_INJECTION", 5)]},
            {"id": "d", "matched_rules": [hit("BS-METHOD", "WEB_SCANNING", 0, "BS")]}]
    assert rt.regex_labels(rows, config) == {"a": "WEB_SCANNING", "b": "WEB_SCANNING", "c": "CMD_INJECTION", "d": "NORMAL"}
    remapped = rt.regex_labels(rows, config, restricted_as_category=True)
    assert remapped == {"a": "PATH_TRAVERSAL", "b": "PATH_TRAVERSAL", "c": "CMD_INJECTION", "d": "NORMAL"}


def test_render_shows_only_aggregates_and_keeps_tables_separated(tmp_path):
    truth, labels = _two_per_class("srbh-")
    (tmp_path / "pilot.json").write_text(json.dumps({"ids": [i for i in labels if i.endswith("0")]}))
    llm = {i: c for i, c in labels.items()}
    regex = {i: (c if c == "XSS" else "NORMAL") for i, c in labels.items()}
    data = {"regex": _entry(truth, [_method("regex", regex)]),
            "llm_single": _entry(truth, [_method("c1", llm, _llm_rows(llm)), _method("c2", llm, _llm_rows(llm))]),
            "agent": _entry(truth, [_method("e1", llm, _llm_rows(llm)), _method("e2", regex, _llm_rows(regex))])}
    inputs = [{"id": i, "path": "/x", "query": "", "user_agent": "", "referer": ""} for i in labels]
    result = {"tanpa_pilot": rt.without_pilot(truth, data, 20, tmp_path / "pilot.json"),
              "kaskade": rt.cascade(truth, data, 20), "sub_tipe_web_scanning": rt.ws_subtypes(truth, data, inputs),
              "label_berubah_antar_run": rt.label_changes(truth, data),
              "sqli_terlewat_regex": rt.sqli_missed(truth, data, inputs, {"aturan_942_dipakai": 2, "memeriksa_path": [942160],
                                                                        "variabel_path": ["REQUEST_FILENAME"]}),
              "dedup_persis": {"md5": "x", "baris_mentah": 10, "baris_6_kelas": 9, "paritas": "cocok", "batas_templat_rfi": 2,
                               "dedup_isi": {"duplicates_dropped": 3, "conflict_rows_dropped": 0, "rows_out": 6},
                               "dedup_persis": {"duplicates_dropped": 1, "conflict_rows_dropped": 0, "rows_out": 8,
                                                "duplicates_dropped_by_class": {"NORMAL": 1}},
                               "kontrafaktual": {k: {"train": 5, "uji": 2, "uji_berkembaran": 1, "persen": 50.0,
                                                     "persen_normal": 100.0, "persen_serangan": 0.0,
                                                     "per_kelas": {"NORMAL": [1, 1], "SQLI": [0, 1]}}
                                                 for k in ("dengan_batas_rfi", "tanpa_batas_rfi")}}}
    text = rt.render(result)
    assert "srbh-" not in text and "srbh-" not in json.dumps(result)  # id fixture berawalan srbh-: tidak boleh muncul
    assert "942160" in text and "jumlah baris dari 12 yang memicunya" in text and "1 dari 2 (50.00%)" in text
    assert "† = identik di ketiga run" in text and "lebih dari satu label" in text
    lines = text.splitlines()
    starts = [k for k, line in enumerate(lines) if line.startswith("|") and (k == 0 or not lines[k - 1].startswith("|"))]
    assert starts and all(lines[k - 1] == "" for k in starts)  # setiap tabel diawali baris kosong
    ends = [k for k, line in enumerate(lines[:-1]) if line.startswith("|") and not lines[k + 1].startswith("|")]
    assert all(lines[k + 1] == "" for k in ends)  # dan diakhiri baris kosong


@pytest.fixture(scope="module")
def real():
    if not (rt.RESULTS_DIR / "agent_r1.jsonl").exists() or not rt.SAMPLE_PATH.exists():
        pytest.skip("butuh results/ resmi dan data/processed/test_sample_500.jsonl")
    truth = rt.load_truth("sample")
    data = rt.collect(truth)
    return rt.build(truth, data, rt.load_inputs(rt.SAMPLE_PATH), dedup=False), data, truth


@pytest.mark.slow
def test_report_reproduces_the_numbers_in_the_manuscript_text(real):
    result, data, truth = real
    dumped = json.dumps(result) + rt.render({**result, "dedup_persis": {"dilewati": "uji"}})
    assert not any(i in dumped for i in truth.labels)  # tidak ada id per baris di laporan
    n, f = rt._n, lambda stat, d=3: rt.cell(stat, d, runs=len(stat["values"]))
    x = result["tanpa_pilot"]
    assert x["n"] == 470 and set(x["pilot_per_kelas"].values()) == {5}
    assert (n(x["metode"]["llm_single"]["macro_f1"]["mean"]), n(x["metode"]["agent"]["macro_f1"]["mean"])) == ("0.834", "0.752")
    (y,) = [y for y in x["uji_berpasangan"] if (y["a"], y["b"]) == ("llm_single", "agent")]
    assert (n(y["selisih"]), n(y["ik_bawah"]), n(y["ik_atas"])) == ("0.082", "0.040", "0.147")
    c = result["kaskade"]["lapis_pertama"]
    assert c["regex"]["baris_ke_llm"] == 236 and f(c["regex"]["metrik"]["macro_f1"]) == "0.900(0.898–0.902)"
    (y,) = [y for y in c["regex"]["uji_berpasangan"] if y["b"] == "llm_single"]
    assert (n(y["selisih"]), n(y["ik_bawah"]), n(y["ik_atas"])) == ("0.071", "0.040", "0.118")
    assert n(c["regex"]["metrik"]["biner_fpr"]["mean"]) == "0.030"
    assert n(c["regex"]["biaya_per_1000_baris_usd"]["mean"]) == "0.062"
    assert n(c["regex_full"]["metrik"]["macro_f1"]["mean"]) == "0.975"
    w = result["sub_tipe_web_scanning"]
    assert w["n"] == {"V1": 41, "W1": 18, "P1": 16, "T3": 14}
    recall = {(m, r): n(w["metode"][m][r]["recall"]["mean"], 2) for m in ("llm_single", "agent") for r in w["n"]}
    assert recall == {("llm_single", "V1"): "0.21", ("agent", "V1"): "0.05", ("llm_single", "W1"): "1.00",
                      ("agent", "W1"): "1.00", ("llm_single", "P1"): "0.52", ("agent", "P1"): "0.06",
                      ("llm_single", "T3"): "0.36", ("agent", "T3"): "0.00"}
    assert all(w["metode"]["regex_full"][r]["recall"]["mean"] == 1.0 for r in w["n"])
    changed = result["label_berubah_antar_run"]
    assert {m: changed[m]["baris"] for m in changed} == {"llm_single": 16, "agent": 26, "llm_single_verified": 37}
    assert all(changed[m]["baris"] == data[m]["group"]["baris_label_berubah_antar_run"] for m in changed)
    s = result["sqli_terlewat_regex"]
    assert (s["terlewat"], s["payload_di_path"], s["tanpa_query_string"]) == (67, 65, 62)
    assert s["payload_di_path_query_string_tanpa_sql"] == 3 and s["aturan_pada_sqli_terdeteksi"] == {"942160": 20}
    assert s["aturan_942_memeriksa_path"]["memeriksa_path"] == [942160, 942550]
    assert s["baris_dengan_aturan_path"] == {"942160": 20, "942550": 0}
    # tambahan dari verifikasi independen
    assert [n(x["metode"][m]["akurasi_pilot"]["mean"]) for m in ("llm_single", "agent")] == ["0.767", "0.733"]
    (y,) = [y for y in x["uji_berpasangan"] if (y["a"], y["b"]) == ("agent", "regex_full")]
    (z,) = [z for z in x["uji_berpasangan_500"] if (z["a"], z["b"]) == ("agent", "regex_full")]
    assert (rt._p(y["p"]), rt._p(z["p"]), n(y["ik_atas"]), n(z["ik_atas"])) == ("0.071", "0.047", "0.005", "−0.001")
    sens = c["regex_930"]
    assert f(sens["metrik"]["macro_f1"]) == "0.865(0.863–0.867)"
    (y,) = [y for y in sens["uji_berpasangan"] if y["b"] == "llm_single"]
    assert (n(y["selisih"]), n(y["ik_bawah"]), n(y["ik_atas"])) == ("0.035", "0.002", "0.071")
    recovered = c["regex"]["baris_ke_llm_dipulihkan_per_kelas"]
    assert recovered["SQLI"]["values"] == [66, 66, 66] and recovered["WEB_SCANNING"]["mean"] == 13
    assert w["rincian"]["T3"] == {"T3:.svn": 5, "T3:.htaccess": 5, "T3:.git": 4}
    assert changed["agent"]["melibatkan_invalid"] == 14
    (mc,) = [y for y in x["mcnemar"] if (y["a"], y["b"]) == ("llm_single", "agent")]
    assert [(q["a_benar_b_salah"], q["b_benar_a_salah"]) for q in mc["pasangan"]] == [(49, 9), (52, 9), (49, 10)]
    json.dumps(result)


@pytest.mark.slow
def test_exact_dedup_counterfactual_reproduces_the_manuscript():
    from src.data.config import SRBH_CSV

    if not SRBH_CSV.exists() or not rt.split_path("test").exists():
        pytest.skip("butuh data/raw (make download) dan data/processed (make data)")
    out = rt.exact_dedup()
    assert out["paritas"] and out["baris_6_kelas"] == 691_768
    assert out["dedup_isi"]["duplicates_dropped"] == 387_099 and out["dedup_isi"]["rows_out"] == 304_669
    assert out["dedup_persis"]["duplicates_dropped"] + out["dedup_persis"]["conflict_rows_dropped"] == 14_257
    y = out["kontrafaktual"]["dengan_batas_rfi"]
    assert f"{y['persen']:.1f}" == "61.6" and (y["uji_berkembaran"], y["uji"]) == (59_366, 96_404)
    assert (f"{y['persen_normal']:.1f}", f"{y['persen_serangan']:.1f}") == ("91.7", "13.9")
    assert np.isclose(sum(a for a, _ in out["kontrafaktual"]["dengan_batas_rfi"]["per_kelas"].values()),
                      out["kontrafaktual"]["dengan_batas_rfi"]["uji_berkembaran"])


def test_regex_930_layer_refuses_a_reconstruction_that_differs_from_the_regex_results():
    truth, labels = _two_per_class()
    hit = {"rule": "942160", "class": "SQLI", "points": 5, "source": "CRS 4.30.0"}
    rows = [{"id": i, "label": "NORMAL", "matched_rules": [hit] if c == "SQLI" else []} for i, c in labels.items()]
    regex = {r["id"]: r["label"] for r in rows}  # SQLI berhit tetapi berlabel NORMAL: tidak konsisten
    with pytest.raises(RuntimeError, match="rekonstruksi"):
        rt._first_layers({"regex": {"methods": [_method("regex", regex, rows)]}})


def test_rules_digest_matches_tree_digest_and_ignores_finder_metadata(tmp_path):
    from src.baselines.crs import tree_digest

    (tmp_path / "a.conf").write_text("SecRule ARGS")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.data").write_text("x")
    before = rt._rules_digest(tmp_path)
    assert before == tree_digest(tmp_path)
    (tmp_path / ".DS_Store").write_bytes(b"finder")
    assert rt._rules_digest(tmp_path) == before != tree_digest(tmp_path)


def test_sqli_rules_on_path_reads_the_extracted_rules_and_checks_the_run_digest(tmp_path):
    from src.baselines.crs import EXTERNAL_DIR

    if not (EXTERNAL_DIR / "coreruleset-4.30.0" / "rules").is_dir() or not rt.REGEX_RUN.exists():
        pytest.skip("butuh aturan CRS terekstrak (data/external/crs) dan results/regex.run.json")
    out = rt.sqli_rules_on_path()
    assert out["aturan_942_dipakai"] == 19 and out["memeriksa_path"] == [942160, 942550]
    run = json.loads(rt.REGEX_RUN.read_text())
    run["ruleset"]["rules_dir_sha256"] = "0" * 64
    (tmp_path / "regex.run.json").write_text(json.dumps(run))
    with pytest.raises(RuntimeError, match="rules_dir_sha256"):
        rt.sqli_rules_on_path(tmp_path / "regex.run.json")
