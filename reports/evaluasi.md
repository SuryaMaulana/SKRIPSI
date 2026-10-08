Agregasi replikasi replikasi-20261008T033139Z-ee70404 (commit ee70404, dirty=False)

Nilai sel: rerata atas run (min–maks bila run lebih dari satu dan nilainya berbeda). Tabel utama memakai rerata.
Run lama, run yang dihentikan, dan run yang diganti (C tanpa batas token, pilot E v1, validasi v2, E 500 tanpa batas parsial, run E 1693ae3, set C 56b9e2c, run C dengan run_id sama) ada di results/archive/ dan tidak masuk tabel; lihat reports/catatan_rekayasa.md.

Tabel 4.2 — deteksi biner (serangan vs NORMAL)

| metode | accuracy | precision | recall | F1 | FPR |
|---|---|---|---|---|---|
| regex | 0,704 | 1,000 | 0,641 | 0,781 | 0,000 |
| regex_full (post hoc) | 0,836 | 1,000 | 0,801 | 0,889 | 0,000 |
| llm_single (rerata 3 run) | 0,902 (0,898–0,906) | 0,993 (0,992–0,995) | 0,888 (0,883–0,891) | 0,937 (0,935–0,940) | 0,030 (0,023–0,034) |
| agent (rerata 3 run) | 0,837 (0,836–0,838) | 0,989 (0,985–0,991) | 0,811 (0,808–0,813) | 0,891 (0,890–0,892) | 0,042 (0,034–0,057) |

Tabel 4.3 — klasifikasi 6 kelas

| metode | accuracy | macro-P | macro-R | macro-F1 | IK 95% macro-F1 (rerata run) |
|---|---|---|---|---|---|
| regex | 0,698 | 0,889 | 0,717 | 0,717 | [0,622; 0,779] |
| regex_full (post hoc) | 0,828 | 0,912 | 0,839 | 0,820 | [0,752; 0,859] |
| llm_single (rerata 3 run) | 0,831 (0,828–0,832) | 0,860 (0,859–0,862) | 0,841 (0,839–0,843) | 0,830 (0,828–0,832) | [0,752; 0,878] |
| agent (rerata 3 run) | 0,747 (0,740–0,752) | 0,853 (0,850–0,857) | 0,763 (0,756–0,768) | 0,750 (0,745–0,753) | [0,644; 0,814] |

F1 per kelas

| metode | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| regex | 0,367 | 1,000 | 0,894 | 0,898 | 0,598 | 0,543 |
| regex_full (post hoc) | 0,367 | 1,000 | 0,894 | 0,983 | 0,994 | 0,682 |
| llm_single (rerata 3 run) | 0,967 (0,961–0,972) | 0,952 (0,949–0,957) | 0,850 (0,835–0,860) | 0,844 | 0,590 (0,578–0,597) | 0,777 (0,769–0,785) |
| agent (rerata 3 run) | 0,971 (0,960–0,983) | 0,991 | 0,699 (0,696–0,706) | 0,772 (0,746–0,797) | 0,382 (0,367–0,396) | 0,682 (0,678–0,688) |

Tabel 4.5 — evidence literal (proporsi item evidence yang ada harfiah di raw_log_masked)

| metode | proporsi literal |
|---|---|
| llm_single (rerata 3 run) | 0,762 (0,750–0,768) |
| agent (rerata 3 run) | 0,897 (0,890–0,901) |

Tabel 4.4 — token, latensi, dan biaya per baris (deskriptif)

| metode | token masuk | token keluar | panggilan LLM | latensi baris median (s) | latensi baris p95 (s) | latensi per panggilan median (s) | latensi per panggilan p95 (s) | biaya per 1.000 baris ($) |
|---|---|---|---|---|---|---|---|---|
| llm_single (rerata 3 run) | 940 | 94 (93–94) | 1,0 | 1,27 (1,25–1,28) | 1,98 (1,94–2,06) | 1,27 (1,25–1,28) | 1,98 (1,94–2,06) | 0,1314 (0,1313–0,1316) |
| agent (rerata 3 run) | 20807 (20576–21157) | 1322 (1276–1367) | 11,8 (11,7–11,9) | 18,39 (18,08–18,68) | 41,34 (38,11–43,87) | 1,49 (1,48–1,50) | 4,13 (4,05–4,28) | 1,6304 (1,6105–1,6552) |
Latensi baris = waktu dinding satu baris (E: seluruh orkestrasi, termasuk jeda ulang galat layanan); latensi per panggilan = satu panggilan LLM dari log panggilan.
agent: panggilan dari percobaan baris yang dibatalkan galat API sebelum --resume tidak dihitung (per run 5/1/13 panggilan, total $0.0025); baris itu diulang penuh setelah resume.

Keluaran degeneratif — panggilan LLM terpotong di max_tokens (TRUNCATED), per run

| metode | kejadian | baris terdampak | outcome: ok | outcome: verification_failed | outcome: verification_skipped | outcome: PARSE_ERROR | label benar (baris terdampak) |
|---|---|---|---|---|---|---|---|
| llm_single (rerata 3 run) | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| agent (rerata 3 run) | 24,0 (16,0–31,0) | 18,0 (13,0–23,0) | 10,7 (7,0–16,0) | 1,7 (0,0–3,0) | 0,0 | 5,7 (3,0–7,0) | 7,0 (6,0–8,0) |
regex: prediksi tidak valid 0,0.
regex_full (post hoc): prediksi tidak valid 0,0.

llm_single: label berubah antar run pada 16 dari 500 baris.
llm_single: prediksi tidak valid 0,0.

agent: label berubah antar run pada 26 dari 500 baris.
agent: prediksi tidak valid 5,7 (3,0–7,0); verification failed 68,7 (65,0–76,0); delegasi keempat subagen 468,7 (465,0–475,0); pemanggilan alat rerata 15,4 (15,4–15,5).

Confusion matrix — regex

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 20 | 0 | 0 | 2 | 0 | 67 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 72 | 1 | 0 | 16 |
| CMD_INJECTION | 0 | 0 | 0 | 75 | 0 | 14 |
| WEB_SCANNING | 0 | 0 | 0 | 0 | 38 | 51 |
| NORMAL | 0 | 0 | 0 | 0 | 0 | 88 |

Confusion matrix — regex_full (post hoc)

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 20 | 0 | 0 | 2 | 0 | 67 |
| XSS | 0 | 56 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 0 | 0 | 72 | 1 | 1 | 15 |
| CMD_INJECTION | 0 | 0 | 0 | 89 | 0 | 0 |
| WEB_SCANNING | 0 | 0 | 0 | 0 | 89 | 0 |
| NORMAL | 0 | 0 | 0 | 0 | 0 | 88 |

Confusion matrix — llm_single (rerata 3 run)

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| SQLI | 87,0 | 1,0 | 0,0 | 0,0 | 0,0 | 1,0 |
| XSS | 0,0 | 56,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| PATH_TRAVERSAL | 0,0 | 0,3 | 82,0 | 0,0 | 2,0 | 4,7 |
| CMD_INJECTION | 4,0 | 0,3 | 13,7 | 65,0 | 4,7 | 1,3 |
| WEB_SCANNING | 0,0 | 1,3 | 8,3 | 0,0 | 40,0 | 39,3 |
| NORMAL | 0,0 | 2,7 | 0,0 | 0,0 | 0,0 | 85,3 |

Confusion matrix — agent (rerata 3 run)

| benar \ prediksi | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | tidak valid |
|---|---|---|---|---|---|---|---|
| SQLI | 85,0 | 0,0 | 0,3 | 0,0 | 0,0 | 3,3 | 0,3 |
| XSS | 0,0 | 56,0 | 0,0 | 0,0 | 0,0 | 0,0 | 0,0 |
| PATH_TRAVERSAL | 0,0 | 0,0 | 71,3 | 0,0 | 0,0 | 17,7 | 0,0 |
| CMD_INJECTION | 1,0 | 0,0 | 30,3 | 56,0 | 0,0 | 0,0 | 1,7 |
| WEB_SCANNING | 0,0 | 0,0 | 13,0 | 0,0 | 21,0 | 54,0 | 1,0 |
| NORMAL | 0,0 | 1,0 | 0,0 | 0,0 | 0,0 | 84,3 | 2,7 |

Run yang dirata-rata

| metode | berkas | run_id | commit | dirty |
|---|---|---|---|---|
| regex | results/regex.jsonl | regex-20261007T150817Z-497dc3d | b4ee3af | False |
| regex_full (post hoc) | results/regex_full.jsonl | regex_full-20261007T161037Z-d7fd371 | b3cff37 | False |
| llm_single | results/llm_single_r1.jsonl | llm_single_r1-20261007T221846Z-ed0941b | 32f0ef0 | False |
| llm_single | results/llm_single_r2.jsonl | llm_single_r2-20261007T221846Z-ed0941b | 32f0ef0 | False |
| llm_single | results/llm_single_r3.jsonl | llm_single_r3-20261007T221846Z-ed0941b | 32f0ef0 | False |
| agent | results/agent_r1.jsonl | agent_r1-20261007T223039Z-53ec4d2 | 9a5a771 | False |
| agent | results/agent_r2.jsonl | agent_r2-20261007T223039Z-53ec4d2 | 9a5a771 | False |
| agent | results/agent_r3.jsonl | agent_r3-20261007T223039Z-53ec4d2 | 9a5a771 | False |
