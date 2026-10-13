# Revisi jurnal — analisis tambahan untuk angka di teks naskah

Laporan revisi_tambahan-20261013T094558Z-71c9347 (commit 71c9347, dirty=False)

Format angka mengikuti manuskrip (titik desimal; metode LLM: rerata tiga run dengan rentang min–maks). Definisi: docstring src/eval/revisi_tambahan.py. Laporan hanya memuat jumlah agregat (tanpa id per baris).

## 1. Tanpa 30 baris pilot (470 baris)

Pilot: `results/archive/pilot/pilot_ids.json` (SQLI 5, XSS 5, PATH_TRAVERSAL 5, CMD_INJECTION 5, WEB_SCANNING 5, NORMAL 5). Sisa 470 baris: SQLI 84, XSS 51, PATH_TRAVERSAL 84, CMD_INJECTION 84, WEB_SCANNING 84, NORMAL 83.

| Method | Macro-F1 (470) | 95% CI | Macro-F1 (500) | Binary F1 | FPR | FPR excl. invalid | Literal items |
|---|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.713 | [0.610, 0.776] | 0.717 | 0.775 | 0.000 | 0.000 | – |
| Full regex (all categories; post hoc) | 0.818 | [0.751, 0.856] | 0.820 | 0.886 | 0.000 | 0.000 | – |
| Single LLM (zero-shot) | 0.834(0.833–0.836) | [0.753, 0.882] | 0.830(0.828–0.832) | 0.936(0.933–0.939) | 0.032(0.024–0.036) | 0.032(0.024–0.036) | 0.759(0.745–0.767) |
| Deep agent | 0.752(0.747–0.756) | [0.651, 0.822] | 0.750(0.745–0.753) | 0.890(0.889–0.890) | 0.044(0.036–0.060) | 0.012(0.012–0.013) | 0.897(0.888–0.902) |
| Single LLM + verifier loop (ablation) | 0.809(0.800–0.815) | [0.724, 0.860] | 0.804(0.796–0.810) | 0.915(0.911–0.918) | 0.028(0.024–0.036) | 0.028(0.024–0.036) | 0.892(0.888–0.896) |

F1 per kelas pada 470 baris:

| Method | SQLI | XSS | PT | CMD | WS | NORMAL |
|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.353 | 1.000 | 0.895 | 0.904 | 0.588 | 0.539 |
| Full regex (all categories; post hoc) | 0.353 | 1.000 | 0.895 | 0.988 | 0.994 | 0.678 |
| Single LLM (zero-shot) | 0.970(0.965–0.976) | 0.947(0.944–0.953) | 0.860(0.846–0.873) | 0.857† | 0.595(0.583–0.603) | 0.775(0.766–0.783) |
| Deep agent | 0.970(0.958–0.982) | 0.990† | 0.705(0.701–0.712) | 0.782(0.756–0.809) | 0.385(0.369–0.400) | 0.680(0.675–0.687) |
| Single LLM + verifier loop (ablation) | 0.974(0.970–0.976) | 0.898(0.887–0.913) | 0.821(0.789–0.839) | 0.860(0.857–0.865) | 0.572(0.557–0.597) | 0.727(0.714–0.733) |

Uji berpasangan pada 470 baris (10,000 draw; definisi Tabel 6):

| Comparison (A − B) | Difference | 95% CI | p, bootstrap | p, permutation |
|---|---|---|---|---|
| Single LLM − deep agent | 0.082 | [0.040, 0.147] | <0.001 | <0.001 |
| Single LLM − regex | 0.121 | [0.053, 0.196] | <0.001 | 0.002 |
| Deep agent − regex | 0.039 | [−0.045, 0.108] | 0.382 | 0.383 |
| Single LLM − full regex (post hoc) | 0.016 | [−0.060, 0.080] | 0.702 | 0.698 |
| Deep agent − full regex (post hoc) | −0.066 | [−0.157, 0.005] | 0.071 | 0.161 |
| Ablation − single LLM | −0.026 | [−0.050, −0.005] | 0.013 | 0.030 |
| Ablation − deep agent | 0.057 | [0.011, 0.120] | 0.013 | 0.014 |

## 2. Kaskade §3.6 (post hoc): baris NORMAL menurut regex diteruskan ke LLM tunggal

| Configuration | Lines sent to the LLM | Macro-F1 | 95% CI | Binary F1 | FPR | FPR excl. invalid | USD per 1,000 lines, billed | USD per 1,000 lines, list price |
|---|---|---|---|---|---|---|---|---|
| Cascade: regex → single LLM | 236 | 0.900(0.898–0.902) | [0.838, 0.939] | 0.946(0.944–0.948) | 0.030(0.023–0.034) | 0.030(0.023–0.034) | 0.062 | 0.062 |
| Cascade: full regex (post hoc) → single LLM | 170 | 0.975(0.972–0.978) | [0.943, 0.987] | 0.991(0.989–0.993) | 0.030(0.023–0.034) | 0.030(0.023–0.034) | 0.045 | 0.045 |

Baris yang diteruskan ke LLM menurut kelas gerbang: regex SQLI 67, PATH_TRAVERSAL 16, CMD_INJECTION 14, WEB_SCANNING 51, NORMAL 88; regex_full SQLI 67, PATH_TRAVERSAL 15, NORMAL 88.
Pembanding: LLM tunggal sendiri 0.131(0.131–0.132) USD per 1,000 baris (billed).

| Comparison (A − B) | Difference | 95% CI | p, bootstrap | p, permutation |
|---|---|---|---|---|
| Cascade: regex → single LLM − single LLM | 0.071 | [0.040, 0.118] | <0.001 | <0.001 |
| Cascade: regex → single LLM − regex | 0.184 | [0.129, 0.253] | <0.001 | <0.001 |
| Cascade: full regex (post hoc) → single LLM − single LLM | 0.145 | [0.099, 0.214] | <0.001 | <0.001 |
| Cascade: full regex (post hoc) → single LLM − full regex (post hoc) | 0.154 | [0.115, 0.205] | <0.001 | <0.001 |

F1 per kelas kaskade: regex SQLI 0.983, XSS 0.966, PATH_TRAVERSAL 0.946(0.936–0.960), CMD_INJECTION 0.983, WEB_SCANNING 0.723(0.714–0.732), NORMAL 0.801(0.794–0.808); regex_full SQLI 0.983, XSS 0.977(0.974–0.982), PATH_TRAVERSAL 0.959(0.953–0.965), CMD_INJECTION 0.983, WEB_SCANNING 0.989, NORMAL 0.957(0.950–0.966).

## 3. Recall WEB_SCANNING per sub-tipe (aturan gerbang)

| Sub-type (gate rule) | Lines | Regex (CRS PL1, 6 categories) | Full regex (all categories; post hoc) | Single LLM (zero-shot) | Deep agent | Single LLM + verifier loop (ablation) |
|---|---|---|---|---|---|---|
| Method sweeps (V1) | 41 | 0.15 | 1.00 | 0.21(0.20–0.22) | 0.05(0.02–0.07) | 0.20(0.20–0.22) |
| Scanner user agents (W1) | 18 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Backup/forbidden extensions (P1) | 16 | 0.00 | 1.00 | 0.52(0.50–0.56) | 0.06 | 0.44(0.38–0.50) |
| VCS or forbidden files (T3) | 14 | 1.00 | 1.00 | 0.36 | 0.00 | 0.26(0.21–0.29) |

Rincian template_key per sub-tipe:

- V1: MOVE 7, PATCH 6, LOCK 5, PROPPATCH 4, COPY 4, TRACK 4, UNLOCK 3, MKCOL 3, PUT 3, PROPFIND 2
- W1: Nmap 18
- P1: .bak 5, .log 4, .backup 4, .swp 3
- T3: .svn 5, lainnya 5, .git 4

Prediksi pada baris sub-tipe (rerata per run):

- Regex (CRS PL1, 6 categories): V1 NORMAL 35.0, WEB_SCANNING 6.0; W1 WEB_SCANNING 18.0; P1 NORMAL 16.0; T3 WEB_SCANNING 14.0
- Full regex (all categories; post hoc): V1 WEB_SCANNING 41.0; W1 WEB_SCANNING 18.0; P1 WEB_SCANNING 16.0; T3 WEB_SCANNING 14.0
- Single LLM (zero-shot): V1 NORMAL 30.3, WEB_SCANNING 8.7, PATH_TRAVERSAL 1.7, XSS 0.3; W1 WEB_SCANNING 18.0; P1 WEB_SCANNING 8.3, NORMAL 5.7, PATH_TRAVERSAL 1.0, XSS 1.0; T3 PATH_TRAVERSAL 5.7, WEB_SCANNING 5.0, NORMAL 3.3
- Deep agent: V1 NORMAL 38.0, WEB_SCANNING 2.0, PARSE_ERROR 1.0; W1 WEB_SCANNING 18.0; P1 NORMAL 15.0, WEB_SCANNING 1.0; T3 PATH_TRAVERSAL 13.0, NORMAL 1.0
- Single LLM + verifier loop (ablation): V1 NORMAL 30.7, WEB_SCANNING 8.3, PATH_TRAVERSAL 1.7, XSS 0.3; W1 WEB_SCANNING 18.0; P1 NORMAL 7.0, WEB_SCANNING 7.0, PATH_TRAVERSAL 1.0, XSS 1.0; T3 PATH_TRAVERSAL 6.0, NORMAL 4.3, WEB_SCANNING 3.7

Aturan regex berkelas WEB_SCANNING yang cocok (jumlah baris per aturan):

- Regex (CRS PL1, 6 categories): V1 BS-METHOD 6; W1 913100 18; P1 tidak ada; T3 930130 14
- Full regex (all categories; post hoc): V1 911100 41, BS-METHOD 6; W1 913100 18, 920440 1; P1 920440 16; T3 930130 14, 920440 3

## 4. Label berubah antar run, menurut kelas gerbang

| Method | Lines | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|---|
| Single LLM (zero-shot) | 16 | 0 | 0 | 5 | 6 | 4 | 1 |
| Deep agent | 26 | 2 | 0 | 4 | 10 | 4 | 6 |
| Single LLM + verifier loop (ablation) | 37 | 0 | 0 | 13 | 9 | 14 | 1 |

Baris berubah yang memuat label tertentu di salah satu run (satu baris bisa dihitung di dua label):

| Method | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | invalid |
|---|---|---|---|---|---|---|---|
| Single LLM (zero-shot) | 2 | 4 | 11 | 2 | 5 | 9 | 0 |
| Deep agent | 4 | 0 | 11 | 8 | 2 | 15 | 14 |
| Single LLM + verifier loop (ablation) | 1 | 4 | 23 | 5 | 14 | 27 | 0 |

Himpunan label yang muncul di ketiga run:

- Single LLM (zero-shot): PATH_TRAVERSAL / NORMAL 5, WEB_SCANNING / NORMAL 3, XSS / PATH_TRAVERSAL 2, PATH_TRAVERSAL / CMD_INJECTION / WEB_SCANNING 1, PATH_TRAVERSAL / CMD_INJECTION 1, SQLI / PATH_TRAVERSAL 1, XSS / NORMAL 1, SQLI / XSS 1, PATH_TRAVERSAL / WEB_SCANNING 1
- Deep agent: NORMAL / invalid 8, PATH_TRAVERSAL / NORMAL 4, PATH_TRAVERSAL / CMD_INJECTION 3, SQLI / CMD_INJECTION 2, CMD_INJECTION / invalid 2, PATH_TRAVERSAL / invalid 2, WEB_SCANNING / NORMAL 2, SQLI / PATH_TRAVERSAL / NORMAL 1, PATH_TRAVERSAL / CMD_INJECTION / invalid 1, SQLI / invalid 1
- Single LLM + verifier loop (ablation): PATH_TRAVERSAL / NORMAL 18, WEB_SCANNING / NORMAL 8, PATH_TRAVERSAL / WEB_SCANNING 3, CMD_INJECTION / WEB_SCANNING 2, XSS / CMD_INJECTION 2, XSS / WEB_SCANNING 1, SQLI / PATH_TRAVERSAL 1, CMD_INJECTION / NORMAL 1, XSS / PATH_TRAVERSAL 1

## 5. SQLI yang terlewat regex utama: letak payload

- SQLI di sampel: 89; prediksi regex utama: NORMAL 67, SQLI 20, CMD_INJECTION 2. Terlewat (NORMAL): 67.
- Payload SQL (famili S1 gerbang) di path: **65 dari 67** (hanya di path: 65; tanpa query string: 62; dengan query string tanpa payload SQL: 3).
- Tanpa query string sama sekali: 62 dari 67.
- Payload di query string: 1; di User-Agent: 1; di Referer: 0; tanpa famili S1 terlihat: 0.
- Aturan 942 (PL1, regex) di konfigurasi utama: 19; yang memeriksa path (REQUEST_FILENAME, REQUEST_BASENAME, REQUEST_URI, REQUEST_URI_RAW, REQUEST_LINE): 942160, 942550.

## 6. Dedup persis vs dedup isi (kontrafaktual dari data/raw)

- Bingkai 6 kelas dibangun ulang dari data/raw (MD5 `173ec515308bdce5aec19cfd5b792596`): 691,768 baris dari 907,815. Paritas dengan split uji resmi: cocok.
- Dedup isi (resmi, kunci raw_log_masked): dibuang 387,099 (konflik label 0), sisa 304,669.
- Dedup persis (raw_log utuh dengan stempel waktu): dibuang **14,257** (konflik label 0), sisa 677,511; per kelas: NORMAL 12,223, SQLI 1,693, WEB_SCANNING 245, PATH_TRAVERSAL 54, CMD_INJECTION 41, XSS 1.
- Kontrafaktual dedup persis -> batas templat RFI (200) -> split: baris uji yang punya kembaran isi di train **59,366 dari 96,404 (61.58%)**; per kelas: SQLI 4,599/32,141, XSS 0/56, PATH_TRAVERSAL 417/2,908, CMD_INJECTION 10/457, WEB_SCANNING 148/1,715, NORMAL 54,192/59,127.
- Kontrafaktual dedup persis -> split (tanpa batas templat RFI): baris uji yang punya kembaran isi di train **59,442 dari 101,627 (58.49%)**; per kelas: SQLI 4,429/32,141, XSS 0/56, PATH_TRAVERSAL 790/8,131, CMD_INJECTION 11/457, WEB_SCANNING 139/1,715, NORMAL 54,073/59,127.
