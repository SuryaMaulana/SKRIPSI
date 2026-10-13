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


def _two_per_class():
    labels = {f"{c[:2]}{j}": c for c in CLASSES for j in range(2)}
    return _truth(labels), labels


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


def test_ws_subtypes_report_recall_per_gate_rule_and_the_regex_rules_that_fired():
    keys = {"v1": "V1:MKCOL", "v2": "V1:MOVE", "w1": "W1:Nmap", "p1": "P1:.bak", "t1": "T3:.git", "n1": "GET /"}
    labels = {i: ("NORMAL" if i == "n1" else "WEB_SCANNING") for i in keys}
    truth = _truth(labels, keys)
    full = {i: label for i, label in labels.items()}
    rules = {"v1": ["911100"], "v2": ["911100", "BS-METHOD"], "w1": ["913100"], "p1": ["920440"], "t1": ["930130"]}
    full_rows = [{"id": i, "label": full[i], "matched_rules": [{"rule": r, "class": "WEB_SCANNING"} for r in rules.get(i, [])]
                  + [{"rule": "941100", "class": "XSS"}]} for i in keys]
    r1 = {**labels, "v1": "NORMAL", "v2": "NORMAL", "p1": "NORMAL"}
    r2 = {**labels, "v1": "NORMAL", "p1": "PATH_TRAVERSAL"}
    data = {"regex_full": {"methods": [_method("regex_full", full, full_rows)]},
            "llm_single": {"methods": [_method("c1", r1), _method("c2", r2)]}}
    out = rt.ws_subtypes(truth, data)
    assert out["n"] == {"V1": 2, "W1": 1, "P1": 1, "T3": 1}
    assert out["rincian"]["V1"] == {"V1:MKCOL": 1, "V1:MOVE": 1}
    assert out["metode"]["llm_single"]["V1"]["recall"]["values"] == [0.0, 0.5]
    assert out["metode"]["llm_single"]["P1"]["prediksi_rerata"] == {"NORMAL": 0.5, "PATH_TRAVERSAL": 0.5}
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
    regex = {"a": "NORMAL", "b": "NORMAL", "c": "NORMAL", "d": "SQLI", "e": "NORMAL"}
    out = rt.sqli_missed(_truth(labels), {"regex": {"methods": [_method("regex", regex)]}}, inputs, {"memeriksa_path": []})
    assert out["sqli"] == 4 and out["terlewat"] == 3 and out["prediksi_regex"] == {"NORMAL": 3, "SQLI": 1}
    assert out["payload_di_path"] == 2 and out["tanpa_query_string"] == 1
    assert out["payload_di_path_dengan_query_string"] == 1 and out["payload_di_query_string"] == 1


@pytest.fixture(scope="module")
def real():
    if not (rt.RESULTS_DIR / "agent_r1.jsonl").exists() or not rt.SAMPLE_PATH.exists():
        pytest.skip("butuh results/ resmi dan data/processed/test_sample_500.jsonl")
    truth = rt.load_truth("sample")
    data = rt.collect(truth)
    return rt.build(truth, data, rt.load_inputs(rt.SAMPLE_PATH), dedup=False), data


@pytest.mark.slow
def test_report_reproduces_the_numbers_in_the_manuscript_text(real):
    result, data = real
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
    json.dumps(result)


@pytest.mark.slow
def test_exact_dedup_counterfactual_reproduces_the_manuscript():
    from src.data.config import SRBH_CSV

    if not SRBH_CSV.exists() or not rt.split_path("test").exists():
        pytest.skip("butuh data/raw (make download) dan data/processed (make data)")
    out = rt.exact_dedup()
    assert out["paritas_split_uji_resmi"] and out["baris_6_kelas"] == 691_768
    assert out["dedup_isi"]["duplicates_dropped"] == 387_099 and out["dedup_isi"]["rows_out"] == 304_669
    assert out["dedup_persis"]["duplicates_dropped"] + out["dedup_persis"]["conflict_rows_dropped"] == 14_257
    assert f"{out['kontrafaktual']['dengan_batas_rfi']['persen']:.1f}" == "61.6"
    assert np.isclose(sum(a for a, _ in out["kontrafaktual"]["dengan_batas_rfi"]["per_kelas"].values()),
                      out["kontrafaktual"]["dengan_batas_rfi"]["uji_berkembaran"])
