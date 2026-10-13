import json
from pathlib import Path

import numpy as np
import pytest

from src.eval import revisi as rv
from src.eval.evaluate import Method, Truth


def _method(rows, name="m"):
    return Method(name, Path(f"/tmp/{name}.jsonl"), {r["id"]: r["label"] for r in rows}, False, {}, rows)


def _truth(labels, logs=None):
    return Truth(labels, {i: "t" for i in labels}, "uji", logs or {i: "GET / HTTP/1.1" for i in labels})


def test_lexicon_covers_every_attack_class_and_compiles():
    main, kb = rv.load_lexicon(), rv.load_lexicon(with_kb=True)
    assert set(main) == set(kb) == set(rv.ATTACK)
    assert all(main[c] for c in rv.ATTACK) and all(len(kb[c]) >= len(main[c]) for c in rv.ATTACK)


@pytest.mark.parametrize("item, label, expected", [
    ("%3Cscript%3Ealert(1)%3C/script%3E", "XSS", True),
    ("1%27%20OR%201=1--", "SQLI", True),
    ("UNION%20ALL%20SELECT%20NULL", "SQLI", True),
    ("../../../../etc/passwd", "PATH_TRAVERSAL", True),
    ("?page=http://example.org/shell.txt", "PATH_TRAVERSAL", True),
    (";cat /etc/passwd", "CMD_INJECTION", True),
    ("-d allow_url_include=1", "CMD_INJECTION", True),
    ("MKCOL", "WEB_SCANNING", True),
    ("Nmap Scripting Engine", "WEB_SCANNING", True),
    ("GET", "SQLI", False),
    ("/etc/passwd", "SQLI", False),
    ("injeksi SQL pada parameter", "SQLI", False),
])
def test_class_consistency_uses_decoded_forms_and_the_predicted_class_only(item, label, expected):
    assert rv.class_consistent(item, label, rv.load_lexicon()) is expected


def test_extra_metrics_fpr_without_invalid_first_output_and_consistency():
    labels = {"a": "NORMAL", "b": "NORMAL", "c": "NORMAL", "d": "SQLI"}
    logs = {"a": "GET /x", "b": "GET /y", "c": "GET /z", "d": "GET /?id=1%27%20OR%201=1"}
    rows = [
        {"id": "a", "label": "XSS", "evidence": ["/x"], "status": "ok", "prompt_tokens": 10, "completion_tokens": 2},
        {"id": "b", "label": "PARSE_ERROR", "evidence": [], "status": "PARSE_ERROR", "prompt_tokens": 10,
         "completion_tokens": 2},
        {"id": "c", "label": "NORMAL", "evidence": ["/z"], "status": "ok", "prompt_tokens": 10, "completion_tokens": 2},
        {"id": "d", "label": "SQLI", "evidence": ["' OR 1=1", "tautologi"], "status": "ok", "prompt_tokens": 10,
         "completion_tokens": 2},
    ]
    out = rv.extra_metrics(_method(rows), _truth(labels, logs), {"utama": rv.load_lexicon()})
    assert out["biner_fpr_tanpa_invalid"] == pytest.approx(1 / 2)  # baris b (invalid) dibuang
    assert out["parse_error"] == 1
    assert out["keluaran_pertama_lolos"] == pytest.approx(3 / 4)  # d punya item non-literal; b tanpa evidence = lolos
    assert out["konsisten_item_utama"] == pytest.approx(1 / 3)  # prediksi serangan: a (1 item), d (2 item)
    assert out["konsisten_baris_utama"] == pytest.approx(1 / 2) and out["tanpa_konsisten_utama"] == pytest.approx(1 / 2)
    assert out["biaya_list_per_1000_baris_usd"] == pytest.approx(1000 * (10 * 0.1 + 2 * 0.4) / 1e6)


def test_first_output_for_verified_methods_uses_the_first_verdict():
    rows = [{"id": i, "label": "SQLI", "evidence": [], "status": "ok", "prompt_tokens": 1, "completion_tokens": 1,
             "verifikasi": {"putaran": len(v), "penolakan": sum(not x for x in v),
                            "putusan": [{"lolos": x} for x in v]}} for i, v in
            (("a", [True]), ("b", [False, True]), ("c", [False, False]), ("d", []))]
    out = rv.extra_metrics(_method(rows), _truth(dict.fromkeys("abcd", "SQLI")), {})
    assert out["keluaran_pertama_lolos"] == pytest.approx(1 / 3)  # d tidak pernah diverifikasi
    assert out["putaran_rerata"] == pytest.approx(5 / 4) and out["baris_ditolak"] == 2


def _toy():
    t = np.array([0, 0, 0, 0, 5, 5, 5, 5])
    clusters = ["SQLI|a", "SQLI|a", "SQLI|b", "SQLI|c", "NORMAL|x", "NORMAL|y", "NORMAL|y", "NORMAL|z"]
    good = [np.array([0, 0, 0, 5, 5, 5, 5, 5])] * 3
    bad = [np.array([5, 5, 0, 5, 5, 0, 5, 5])]
    return t, clusters, good, bad


def test_paired_tests_are_deterministic_antisymmetric_and_accept_a_single_run_method():
    t, clusters, good, bad = _toy()
    first = rv.paired_bootstrap(t, good, bad, clusters, n=200)
    assert first == rv.paired_bootstrap(t, good, bad, clusters, n=200)
    reverse = rv.paired_bootstrap(t, bad, good, clusters, n=200)
    assert reverse["selisih"] == pytest.approx(-first["selisih"]) and first["selisih"] > 0
    assert reverse["ik_bawah"] == pytest.approx(-first["ik_atas"]) and 0 <= first["p"] <= 1
    perm = rv.paired_permutation(t, good, bad, clusters, n=200)
    assert perm == rv.paired_permutation(t, good, bad, clusters, n=200) and 0 <= perm["p"] <= 1
    assert rv.paired_permutation(t, good, good, clusters, n=50)["p"] == 1.0  # metode identik


def test_mcnemar_counts_discordant_lines_per_same_index_run_pair():
    t = np.array([0, 1, 2, 3])
    a = [np.array([0, 1, 2, 0]), np.array([0, 1, 0, 0])]
    b = [np.array([0, 0, 0, 3]), np.array([0, 1, 0, 3])]
    pairs = rv.mcnemar_pairs(t, a, b)
    assert [(q["a_benar_b_salah"], q["b_benar_a_salah"]) for q in pairs] == [(2, 1), (0, 1)]
    assert pairs[0]["p"] == pytest.approx(1.0)


def test_cell_format_matches_the_manuscript():
    stat = {"mean": 20807.33, "min": 20576.0, "max": 21157.0}
    assert rv.cell(stat, 0, thousands=True, runs=3) == "20,807(20,576–21,157)"
    assert rv.cell({"mean": 1.27, "min": 1.25, "max": 1.28}, 2, space=True, runs=3) == "1.27 (1.25–1.28)"
    assert rv.cell({"mean": 0.8443, "min": 0.8441, "max": 0.8444}, runs=3, dagger=True) == "0.844†"
    assert rv.cell({"mean": -0.0712, "min": -0.0712, "max": -0.0712}) == "−0.071"
    assert rv.cell(None) == "–"


def test_decomposition_splits_the_gap_into_loop_and_orchestration():
    group = lambda lit, f1: {"group": {"metrics": {"evidence_literal": {"mean": lit}, "macro_f1": {"mean": f1}}}}
    data = {"llm_single": group(0.762, 0.830), "agent": group(0.897, 0.750), "llm_single_verified": group(0.862, 0.820)}
    d = rv.decomposition(data)["evidence_literal"]
    assert d["selisih_total"] == pytest.approx(0.135) and d["bagian_loop"] == pytest.approx(0.100)
    assert d["persen_loop"] + d["persen_orkestrasi"] == pytest.approx(100)


MANUSCRIPT = {  # revisi_v2.docx, angka yang sudah dicek tereproduksi (Tabel 4, 5, 6, 9, 10, 11 kolom 1-2)
    ("agent", "biner_fpr_tanpa_invalid"): "0.012", ("llm_single", "biner_fpr_tanpa_invalid"): "0.030(0.023–0.034)",
    ("agent", "biaya_list_per_1000_baris_usd"): "2.609(2.598–2.626)", ("agent", "token_cache_persen"): "62.7(61.5–63.6)",
    ("llm_single", "keluaran_pertama_lolos"): "0.677(0.662–0.690)", ("agent", "keluaran_pertama_lolos"): "0.799(0.789–0.811)",
}
TABLE_6 = {("llm_single", "agent"): ("0.080", "[0.037, 0.142]", "<0.001", "<0.001"),
           ("llm_single", "regex"): ("0.113", "[0.038, 0.190]", "0.002", "0.004"),
           ("agent", "regex"): ("0.033", "[−0.055, 0.103]", "0.500", "0.471"),
           ("llm_single", "regex_full"): ("0.010", "[−0.068, 0.073]", "0.879", "0.820"),
           ("agent", "regex_full"): ("−0.071", "[−0.163, −0.001]", "0.047", "0.127")}


@pytest.mark.slow
def test_revision_report_reproduces_the_published_single_llm_and_agent_values():
    if not (rv.RESULTS_DIR / "agent_r1.jsonl").exists() or not Path(rv.ROOT / "data/processed/test_sample_500.jsonl").exists():
        pytest.skip("butuh results/ resmi dan data/processed/test_sample_500.jsonl")
    truth = rv.load_truth("sample")
    data = {k: v for k, v in rv.collect(truth).items() if k != "llm_single_verified"}
    result = rv.build(truth, data)
    for (method, key), expected in MANUSCRIPT.items():
        assert rv.cell(result["metode"][method]["metrik_revisi"][key], 1 if "persen" in key else 3, runs=3) == expected
    got = {(x["a"], x["b"]): (rv._n(x["selisih"]), f"[{rv._n(x['ik_bawah'])}, {rv._n(x['ik_atas'])}]", rv._p(x["p"]),
                              rv._p(x["p_permutasi"])) for x in result["uji_berpasangan"]}
    assert got == TABLE_6
    (mc,) = [x for x in result["mcnemar"] if (x["a"], x["b"]) == ("llm_single", "agent")]
    assert [q["a_benar_b_salah"] for q in mc["pasangan"]] == [50, 53, 50]
    assert [q["b_benar_a_salah"] for q in mc["pasangan"]] == [9, 9, 10]
    json.dumps(result)  # laporan JSON harus bisa diserialkan


def test_relabel_metrics_count_changes_after_a_rejection():
    labels = {"a": "XSS", "b": "SQLI", "c": "NORMAL", "d": "PATH_TRAVERSAL"}
    verdict = lambda ok, missing=(): {"lolos": ok, "skema_valid": True, "evidence_hilang": list(missing)}
    rows = [
        {"id": "a", "label": "NORMAL", "riwayat_label": ["XSS", "NORMAL"], "verifikasi": {"putusan": [verdict(False, [""])]}},
        {"id": "b", "label": "SQLI", "riwayat_label": ["PARSE_ERROR", "SQLI"], "verifikasi": {"putusan": [verdict(False, ["x"])]}},
        {"id": "c", "label": "NORMAL", "riwayat_label": ["NORMAL"], "verifikasi": {"putusan": [verdict(True)]}},
        {"id": "d", "label": "XSS", "riwayat_label": ["XSS", "XSS"], "verifikasi": {"putusan": [verdict(False, [" ", "y"])]}},
    ]
    out = rv.relabel_metrics(rows, _truth(labels))
    assert out == {"klasifikasi_ulang_baris": 3, "label_berubah": 2, "benar_ke_salah": 1, "salah_ke_benar": 1,
                   "serangan_ke_normal": 1, "ditolak_hanya_item_kosong": 1}
