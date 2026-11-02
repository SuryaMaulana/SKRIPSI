# Revisi jurnal — angka Tabel 4–11 termasuk ablasi

Laporan revisi-20261102T061704Z-3279757 (commit 3279757, dirty=False)

Format angka mengikuti manuskrip (titik desimal; metode LLM: rerata tiga run dengan rentang min–maks; † = identik di ketiga run). Definisi setiap kolom: docstring src/eval/revisi.py.

## Tabel 4 — Binary detection (S1)

| Method | Accuracy | Precision | Recall | F1 | FPR | FPR excl. invalid |
|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.704 | 1.000 | 0.641 | 0.781 | 0.000 | 0.000 |
| Full regex (all categories; post hoc) | 0.836 | 1.000 | 0.801 | 0.889 | 0.000 | 0.000 |
| Single LLM (zero-shot) | 0.902(0.898–0.906) | 0.993(0.992–0.995) | 0.888(0.883–0.891) | 0.937(0.935–0.940) | 0.030(0.023–0.034) | 0.030(0.023–0.034) |
| Deep agent | 0.837(0.836–0.838) | 0.989(0.985–0.991) | 0.811(0.808–0.813) | 0.891(0.890–0.892) | 0.042(0.034–0.057) | 0.012 |
| Single LLM + verifier loop (ablation) | 0.871(0.864–0.876) | 0.993(0.991–0.994) | 0.850(0.842–0.854) | 0.916(0.911–0.919) | 0.027(0.023–0.034) | 0.027(0.023–0.034) |
| Single LLM + tool context (ablation) | 0.861(0.860–0.862) | 0.997 | 0.833(0.833–0.835) | 0.908(0.907–0.909) | 0.011 | 0.011 |

## Tabel 5 — Six-class classification (S2)

| Method | Accuracy | Macro-P | Macro-R | Macro-F1 | 95% CI of macro-F1 |
|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.698 | 0.889 | 0.717 | 0.717 | [0.621, 0.778] |
| Full regex (all categories; post hoc) | 0.828 | 0.912 | 0.839 | 0.820 | [0.755, 0.858] |
| Single LLM (zero-shot) | 0.831(0.828–0.832) | 0.860(0.859–0.862) | 0.841(0.839–0.843) | 0.830(0.828–0.832) | [0.751, 0.877] |
| Deep agent | 0.747(0.740–0.752) | 0.853(0.850–0.857) | 0.763(0.756–0.768) | 0.750(0.745–0.753) | [0.645, 0.814] |
| Single LLM + verifier loop (ablation) | 0.804(0.794–0.810) | 0.850(0.844–0.854) | 0.811(0.802–0.817) | 0.804(0.796–0.810) | [0.724, 0.854] |
| Single LLM + tool context (ablation) | 0.771(0.770–0.772) | 0.860(0.860–0.861) | 0.786(0.785–0.786) | 0.771(0.770–0.772) | [0.666, 0.834] |

## Tabel 6 — Paired comparisons of mean-of-runs macro-F1 (10,000 template-level draws)

| Comparison (A − B) | Difference | 95% CI | p, bootstrap | p, Holm | p, permutation |
|---|---|---|---|---|---|
| Single LLM − deep agent | 0.080 | [0.037, 0.142] | <0.001 | 0.005 | <0.001 |
| Single LLM − regex | 0.113 | [0.038, 0.190] | 0.002 | 0.017 | 0.004 |
| Deep agent − regex | 0.033 | [−0.055, 0.103] | 0.500 | 1.000 | 0.471 |
| Single LLM − full regex (post hoc) | 0.010 | [−0.068, 0.073] | 0.879 | 1.000 | 0.820 |
| Deep agent − full regex (post hoc) | −0.071 | [−0.163, −0.001] | 0.047 | 0.140 | 0.127 |
| Loop ablation − single LLM | −0.026 | [−0.051, −0.004] | 0.013 | 0.063 | 0.032 |
| Loop ablation − deep agent | 0.054 | [0.009, 0.116] | 0.019 | 0.077 | 0.020 |
| Tool-context ablation − single LLM | −0.059 | [−0.116, −0.017] | 0.005 | 0.031 | 0.004 |
| Deep agent − tool-context ablation | −0.022 | [−0.045, −0.008] | <0.001 | 0.004 | 0.002 |
p, Holm = p bootstrap dikoreksi Holm–Bonferroni atas keluarga 9 perbandingan; hanya single LLM − deep agent (H1) yang konfirmatori, sisanya eksploratori.

## Tabel 7 — Per-class F1

| Method | SQLI | XSS | PT | CMD | WS | NORMAL |
|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.367 | 1.000 | 0.894 | 0.898 | 0.598 | 0.543 |
| Full regex (all categories; post hoc) | 0.367 | 1.000 | 0.894 | 0.983 | 0.994 | 0.682 |
| Single LLM (zero-shot) | 0.967(0.961–0.972) | 0.952(0.949–0.957) | 0.850(0.835–0.860) | 0.844† | 0.590(0.578–0.597) | 0.777(0.769–0.785) |
| Deep agent | 0.971(0.960–0.983) | 0.991† | 0.699(0.696–0.706) | 0.772(0.746–0.797) | 0.382(0.367–0.396) | 0.682(0.678–0.688) |
| Single LLM + verifier loop (ablation) | 0.970(0.967–0.972) | 0.897(0.887–0.911) | 0.814(0.785–0.832) | 0.847(0.844–0.852) | 0.568(0.554–0.591) | 0.727(0.714–0.735) |
| Single LLM + tool context (ablation) | 0.983† | 0.991† | 0.706(0.705–0.709) | 0.797† | 0.434(0.425–0.439) | 0.715(0.713–0.716) |

## Tabel 8 — Confusion matrices (rows = true class; LLM methods: mean of three runs)

Regex (CRS PL1, 6 categories)

| True \ Predicted | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | Invalid |
|---|---|---|---|---|---|---|---|
| SQLI (89) | 20 | 0 | 0 | 2 | 0 | 67 | 0 |
| XSS (56) | 0 | 56 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL (89) | 0 | 0 | 72 | 1 | 0 | 16 | 0 |
| CMD_INJECTION (89) | 0 | 0 | 0 | 75 | 0 | 14 | 0 |
| WEB_SCANNING (89) | 0 | 0 | 0 | 0 | 38 | 51 | 0 |
| NORMAL (88) | 0 | 0 | 0 | 0 | 0 | 88 | 0 |

Full regex (all categories; post hoc)

| True \ Predicted | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | Invalid |
|---|---|---|---|---|---|---|---|
| SQLI (89) | 20 | 0 | 0 | 2 | 0 | 67 | 0 |
| XSS (56) | 0 | 56 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL (89) | 0 | 0 | 72 | 1 | 1 | 15 | 0 |
| CMD_INJECTION (89) | 0 | 0 | 0 | 89 | 0 | 0 | 0 |
| WEB_SCANNING (89) | 0 | 0 | 0 | 0 | 89 | 0 | 0 |
| NORMAL (88) | 0 | 0 | 0 | 0 | 0 | 88 | 0 |

Single LLM (zero-shot)

| True \ Predicted | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | Invalid |
|---|---|---|---|---|---|---|---|
| SQLI (89) | 87.0 | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 |
| XSS (56) | 0.0 | 56.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| PATH_TRAVERSAL (89) | 0.0 | 0.3 | 82.0 | 0.0 | 2.0 | 4.7 | 0.0 |
| CMD_INJECTION (89) | 4.0 | 0.3 | 13.7 | 65.0 | 4.7 | 1.3 | 0.0 |
| WEB_SCANNING (89) | 0.0 | 1.3 | 8.3 | 0.0 | 40.0 | 39.3 | 0.0 |
| NORMAL (88) | 0.0 | 2.7 | 0.0 | 0.0 | 0.0 | 85.3 | 0.0 |

Deep agent

| True \ Predicted | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | Invalid |
|---|---|---|---|---|---|---|---|
| SQLI (89) | 85.0 | 0.0 | 0.3 | 0.0 | 0.0 | 3.3 | 0.3 |
| XSS (56) | 0.0 | 56.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| PATH_TRAVERSAL (89) | 0.0 | 0.0 | 71.3 | 0.0 | 0.0 | 17.7 | 0.0 |
| CMD_INJECTION (89) | 1.0 | 0.0 | 30.3 | 56.0 | 0.0 | 0.0 | 1.7 |
| WEB_SCANNING (89) | 0.0 | 0.0 | 13.0 | 0.0 | 21.0 | 54.0 | 1.0 |
| NORMAL (88) | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 84.3 | 2.7 |

Single LLM + verifier loop (ablation)

| True \ Predicted | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | Invalid |
|---|---|---|---|---|---|---|---|
| SQLI (89) | 87.0 | 1.0 | 0.0 | 0.0 | 0.0 | 1.0 | 0.0 |
| XSS (56) | 0.0 | 51.0 | 0.0 | 0.0 | 0.0 | 5.0 | 0.0 |
| PATH_TRAVERSAL (89) | 0.0 | 0.0 | 76.0 | 0.0 | 1.3 | 11.7 | 0.0 |
| CMD_INJECTION (89) | 3.3 | 2.3 | 12.7 | 65.3 | 3.0 | 2.3 | 0.0 |
| WEB_SCANNING (89) | 0.0 | 1.3 | 8.7 | 0.0 | 37.0 | 42.0 | 0.0 |
| NORMAL (88) | 0.0 | 2.0 | 0.3 | 0.0 | 0.0 | 85.7 | 0.0 |

Single LLM + tool context (ablation)

| True \ Predicted | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | Invalid |
|---|---|---|---|---|---|---|---|
| SQLI (89) | 86.0 | 0.0 | 1.0 | 0.0 | 0.0 | 2.0 | 0.0 |
| XSS (56) | 0.0 | 56.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| PATH_TRAVERSAL (89) | 0.0 | 0.0 | 73.0 | 0.0 | 0.0 | 16.0 | 0.0 |
| CMD_INJECTION (89) | 0.0 | 0.0 | 30.0 | 59.0 | 0.0 | 0.0 | 0.0 |
| WEB_SCANNING (89) | 0.0 | 0.0 | 13.7 | 0.0 | 24.7 | 50.3 | 0.3 |
| NORMAL (88) | 0.0 | 1.0 | 0.0 | 0.0 | 0.0 | 87.0 | 0.0 |

## Tabel 9 — Tokens, calls, and cost per log line

| Method | Input tokens/line | Output tokens/line | LLM calls/line | USD per 1,000 lines, billed | USD per 1,000 lines, list price | % input tokens cached |
|---|---|---|---|---|---|---|
| Single LLM (zero-shot) | 940 | 94(93–94) | 1.0 | 0.131(0.131–0.132) | 0.131(0.131–0.132) | 0.0 |
| Deep agent | 20,807(20,576–21,157) | 1,322(1,276–1,367) | 11.8(11.7–11.9) | 1.630(1.611–1.655) | 2.609(2.598–2.626) | 62.7(61.5–63.6) |
| Single LLM + verifier loop (ablation) | 1,279(1,276–1,281) | 131(124–139) | 1.3 | 0.180(0.178–0.183) | 0.180(0.178–0.183) | 0.2(0.0–0.3) |
| Single LLM + tool context (ablation) | 1,657(1,654–1,660) | 110(99–125) | 1.0 | 0.142(0.107–0.209) | 0.210(0.205–0.216) | 54.4(5.3–81.6) |

## Tabel 10 — Latency in seconds

| Method | Per line, median | Per line, p95 | Per call, median | Per call, p95 |
|---|---|---|---|---|
| Single LLM (zero-shot) | 1.27 (1.25–1.28) | 1.98 (1.94–2.06) | 1.27 (1.25–1.28) | 1.98 (1.94–2.06) |
| Deep agent | 18.39 (18.08–18.68) | 41.34 (38.11–43.87) | 1.49 (1.48–1.50) | 4.13 (4.05–4.28) |
| Single LLM + verifier loop (ablation) | 1.43 (1.39–1.46) | 3.13 (3.03–3.24) | 1.26 (1.23–1.29) | 1.94 (1.85–2.07) |
| Single LLM + tool context (ablation) | 1.30 (1.27–1.32) | 1.83 (1.75–1.89) | 1.30 (1.27–1.32) | 1.83 (1.75–1.89) |
Ablasi: latensi per baris = jumlah latensi panggilan baris itu (konvensi LLM tunggal).

## Tabel 11 — Evidence traceability

| Method | Literal items (all predictions) | Lines with all items literal, first output | Literal and class-consistent items (attack predictions) | Attack lines with ≥ 1 literal, class-consistent item |
|---|---|---|---|---|
| Single LLM (zero-shot) | 0.762(0.750–0.768) | 0.677(0.662–0.690) | 0.485(0.474–0.498) | 0.625(0.612–0.638) |
| Deep agent | 0.897(0.890–0.901) | 0.799(0.789–0.811) | 0.692(0.678–0.710) | 0.752(0.737–0.760) |
| Single LLM + verifier loop (ablation) | 0.892(0.888–0.895) | 0.677(0.674–0.680) | 0.602(0.601–0.604) | 0.693(0.688–0.697) |
| Single LLM + tool context (ablation) | 0.830(0.818–0.844) | 0.767(0.758–0.778) | 0.704(0.699–0.713) | 0.768(0.759–0.777) |
Keluaran pertama: deep agent dan ablasi = porsi baris terverifikasi yang klasifikasi pertamanya lolos verifikasi; LLM tunggal = porsi baris yang semua item evidence-nya literal. Class-consistent: leksikon configs/leksikon_kelas.yaml bagian utama (indikator Tabel 1).

Sensitivitas leksikon (utama + tambahan_kb) dan porsi prediksi serangan tanpa item class-consistent:

| Method | Literal & consistent items (utama+kb) | Attack lines ≥ 1 (utama+kb) | Attack lines without consistent item (utama) | (utama+kb) |
|---|---|---|---|---|
| Single LLM (zero-shot) | 0.528(0.520–0.541) | 0.658(0.648–0.668) | 0.138(0.136–0.144) | 0.102(0.100–0.106) |
| Deep agent | 0.782(0.770–0.802) | 0.795(0.782–0.802) | 0.132(0.129–0.137) | 0.087(0.084–0.092) |
| Single LLM + verifier loop (ablation) | 0.656(0.654–0.658) | 0.726(0.720–0.729) | 0.147(0.144–0.151) | 0.107(0.102–0.114) |
| Single LLM + tool context (ablation) | 0.777(0.772–0.786) | 0.811(0.802–0.820) | 0.124(0.122–0.125) | 0.080(0.078–0.081) |

## Verifikasi, keluaran degeneratif, dan stabilitas (per run)

| Method | verification_failed lines (r1 / r2 / r3) | Verification rounds/line | Lines with ≥ 1 rejection | TRUNCATED calls | Lines with TRUNCATED | PARSE_ERROR | Lines whose label changed across runs |
|---|---|---|---|---|---|---|---|
| Single LLM (zero-shot) | – | – | – | 0.0 (0 / 0 / 0) | 0.0 (0 / 0 / 0) | 0.0 (0 / 0 / 0) | 16 of 500 |
| Deep agent | 68.7 (65 / 65 / 76) | 1.19 (1.17–1.20) | 99.3 (100 / 93 / 105) | 24.0 (25 / 31 / 16) | 18.0 (18 / 23 / 13) | 5.7 (7 / 7 / 3) | 26 of 500 |
| Single LLM + verifier loop (ablation) | 74.0 (72 / 75 / 75) | 1.32 (1.32–1.33) | 161.3 (160 / 163 / 161) | 1.0 (1 / 0 / 2) | 0.7 (1 / 0 / 1) | 0.0 (0 / 0 / 0) | 37 of 500 |
| Single LLM + tool context (ablation) | – | – | – | 1.3 (3 / 0 / 1) | 1.0 (2 / 0 / 1) | 0.3 (1 / 0 / 0) | 6 of 500 |

Perubahan label setelah klasifikasi ulang (baris yang ditolak lalu diklasifikasi lagi; rerata per run, nilai per run dalam kurung):

| Method | Re-classified lines | Label changed | Correct → wrong | Wrong → correct | Attack → NORMAL | First rejection only for empty evidence items |
|---|---|---|---|---|---|---|
| Deep agent | 100.3 (101 / 94 / 106) | 7.0 (7 / 5 / 9) | 6.7 (7 / 4 / 9) | 0.0 (0 / 0 / 0) | 6.7 (7 / 4 / 9) | 11.0 (13 / 9 / 11) |
| Single LLM + verifier loop (ablation) | 161.3 (160 / 163 / 161) | 18.0 (20 / 16 / 18) | 15.7 (18 / 13 / 16) | 1.7 (1 / 2 / 2) | 16.3 (18 / 15 / 16) | 33.7 (33 / 37 / 31) |
Perubahan = label klasifikasi pertama dibandingkan label akhir; benar/salah menurut label gerbang. Untuk deep agent, klasifikasi pertama bisa PARSE_ERROR (dihitung salah).

## Dekomposisi §3.4 — loop verifikasi, konteks alat, dan orkestrasi

| Metric | Single LLM | + tool context | + verifier loop | Deep agent | Gap (agent − single) | Loop part (loop abl. − single) | Tool-context part (toolctx abl. − single) | Orchestration part (agent − toolctx abl.) |
|---|---|---|---|---|---|---|---|---|
| Literal-evidence rate | 0.762 | 0.830 | 0.892 | 0.897 | 0.135 | 0.130 (95.9%) | 0.068 (50.2%) | 0.067 (49.8%) |
| Macro-F1 | 0.830 | 0.771 | 0.804 | 0.750 | −0.080 | −0.026 (32.4%) | −0.059 (73.2%) | −0.022 (26.8%) |
Loop and tool-context parts are each measured against the single LLM and are not additive; orchestration = deep agent − tool-context ablation. 95% CIs for all three differences are in Table 6.
Persen = bagian / selisih total, dihitung dari rerata tiga run sebelum pembulatan.

## Run yang dipakai

| Method | run_id | commit |
|---|---|---|
| Regex (CRS PL1, 6 categories) | regex-20261007T150817Z-497dc3d | b4ee3af |
| Full regex (all categories; post hoc) | regex_full-20261007T161037Z-d7fd371 | b3cff37 |
| Single LLM (zero-shot) | llm_single_r1-20261007T221846Z-ed0941b | 32f0ef0 |
| Single LLM (zero-shot) | llm_single_r2-20261007T221846Z-ed0941b | 32f0ef0 |
| Single LLM (zero-shot) | llm_single_r3-20261007T221846Z-ed0941b | 32f0ef0 |
| Deep agent | agent_r1-20261007T223039Z-53ec4d2 | 9a5a771 |
| Deep agent | agent_r2-20261007T223039Z-53ec4d2 | 9a5a771 |
| Deep agent | agent_r3-20261007T223039Z-53ec4d2 | 9a5a771 |
| Single LLM + verifier loop (ablation) | llm_single_verified_r1-20261013T072431Z-22841cb | 22841cb |
| Single LLM + verifier loop (ablation) | llm_single_verified_r2-20261013T072431Z-22841cb | 22841cb |
| Single LLM + verifier loop (ablation) | llm_single_verified_r3-20261013T072431Z-22841cb | 22841cb |
| Single LLM + tool context (ablation) | llm_single_toolctx_r1-20261018T021304Z-245ccc0 | 245ccc0 |
| Single LLM + tool context (ablation) | llm_single_toolctx_r2-20261018T022519Z-245ccc0 | 245ccc0 |
| Single LLM + tool context (ablation) | llm_single_toolctx_r3-20261018T023633Z-245ccc0 | 245ccc0 |
