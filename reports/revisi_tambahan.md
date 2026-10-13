# Revisi jurnal — analisis tambahan untuk angka di teks naskah

Laporan revisi_tambahan-20261013T104338Z-e9361d4 (commit e9361d4, dirty=False)

Format angka mengikuti manuskrip (titik desimal; metode LLM: rerata tiga run dengan rentang min–maks; † = identik di ketiga run pada presisi yang ditampilkan). Definisi: docstring src/eval/revisi_tambahan.py. Laporan hanya memuat jumlah agregat (tanpa id per baris).

## 1. Tanpa 30 baris pilot (470 baris)

Pilot: `results/archive/pilot/pilot_ids.json` (SQLI 5, XSS 5, PATH_TRAVERSAL 5, CMD_INJECTION 5, WEB_SCANNING 5, NORMAL 5). Sisa 470 baris: SQLI 84, XSS 51, PATH_TRAVERSAL 84, CMD_INJECTION 84, WEB_SCANNING 84, NORMAL 83.

Tabel 4 pada 470 baris:

| Method | Accuracy | Precision | Recall | F1 | FPR | FPR excl. invalid |
|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.698 | 1.000 | 0.633 | 0.775 | 0.000 | 0.000 |
| Full regex (all categories; post hoc) | 0.832 | 1.000 | 0.796 | 0.886 | 0.000 | 0.000 |
| Single LLM (zero-shot) | 0.901(0.896–0.904) | 0.992(0.991–0.994) | 0.886(0.881–0.889) | 0.936(0.933–0.939) | 0.032(0.024–0.036) | 0.032(0.024–0.036) |
| Deep agent | 0.835(0.834–0.836) | 0.988(0.984–0.991) | 0.809(0.806–0.811) | 0.890(0.889–0.890) | 0.044(0.036–0.060) | 0.012(0.012–0.013) |
| Single LLM + verifier loop (ablation) | 0.871(0.864–0.874) | 0.993(0.991–0.994) | 0.849(0.842–0.853) | 0.915(0.911–0.918) | 0.028(0.024–0.036) | 0.028(0.024–0.036) |

Tabel 5 dan literal evidence pada 470 baris (IK: bootstrap templat 1,000 draw, definisi Tabel 5):

| Method | Accuracy | Macro-P | Macro-R | Macro-F1 (470) | 95% CI | Macro-F1 (500) | Literal items |
|---|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.694 | 0.890 | 0.714 | 0.713 | [0.610, 0.776] | 0.717 | – |
| Full regex (all categories; post hoc) | 0.826 | 0.913 | 0.837 | 0.818 | [0.751, 0.856] | 0.820 | – |
| Single LLM (zero-shot) | 0.835(0.832–0.836) | 0.864(0.862–0.867) | 0.846(0.843–0.847) | 0.834(0.833–0.836) | [0.753, 0.882] | 0.830(0.828–0.832) | 0.759(0.745–0.767) |
| Deep agent | 0.748(0.740–0.753) | 0.854(0.850–0.858) | 0.765(0.758–0.770) | 0.752(0.747–0.756) | [0.651, 0.822] | 0.750(0.745–0.753) | 0.897(0.888–0.902) |
| Single LLM + verifier loop (ablation) | 0.809(0.798–0.815) | 0.855(0.848–0.859) | 0.816(0.806–0.822) | 0.809(0.800–0.815) | [0.724, 0.860] | 0.804(0.796–0.810) | 0.892(0.888–0.896) |

F1 per kelas pada 470 baris:

| Method | SQLI | XSS | PT | CMD | WS | NORMAL |
|---|---|---|---|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.353 | 1.000 | 0.895 | 0.904 | 0.588 | 0.539 |
| Full regex (all categories; post hoc) | 0.353 | 1.000 | 0.895 | 0.988 | 0.994 | 0.678 |
| Single LLM (zero-shot) | 0.970(0.965–0.976) | 0.947(0.944–0.953) | 0.860(0.846–0.873) | 0.857† | 0.595(0.583–0.603) | 0.775(0.766–0.783) |
| Deep agent | 0.970(0.958–0.982) | 0.990† | 0.705(0.701–0.712) | 0.782(0.756–0.809) | 0.385(0.369–0.400) | 0.680(0.675–0.687) |
| Single LLM + verifier loop (ablation) | 0.974(0.970–0.976) | 0.898(0.887–0.913) | 0.821(0.789–0.839) | 0.860(0.857–0.865) | 0.572(0.557–0.597) | 0.727(0.714–0.733) |

Uji berpasangan (10,000 draw; definisi Tabel 6) pada 470 baris, dengan 500 baris sebagai pembanding:

| Comparison (A − B) | Difference (470) | 95% CI | p, bootstrap / permutation | Difference (500) | 95% CI (500) | p (500), bootstrap / permutation |
|---|---|---|---|---|---|---|
| Single LLM − deep agent | 0.082 | [0.040, 0.147] | <0.001 / <0.001 | 0.080 | [0.037, 0.142] | <0.001 / <0.001 |
| Single LLM − regex | 0.121 | [0.053, 0.196] | <0.001 / 0.002 | 0.113 | [0.038, 0.190] | 0.002 / 0.004 |
| Deep agent − regex | 0.039 | [−0.045, 0.108] | 0.382 / 0.383 | 0.033 | [−0.055, 0.103] | 0.500 / 0.471 |
| Single LLM − full regex (post hoc) | 0.016 | [−0.060, 0.080] | 0.702 / 0.698 | 0.010 | [−0.068, 0.073] | 0.879 / 0.820 |
| Deep agent − full regex (post hoc) | −0.066 | [−0.157, 0.005] | 0.071 / 0.161 | −0.071 | [−0.163, −0.001] | 0.047 / 0.127 |
| Ablation − single LLM | −0.026 | [−0.050, −0.005] | 0.013 / 0.030 | −0.026 | [−0.051, −0.004] | 0.013 / 0.032 |
| Ablation − deep agent | 0.057 | [0.011, 0.120] | 0.013 / 0.014 | 0.054 | [0.009, 0.116] | 0.019 / 0.020 |

McNemar eksak pada 470 baris per pasangan run berindeks sama (mengabaikan klaster templat):

| A − B | run | A benar, B salah | B benar, A salah | p eksak |
|---|---|---|---|---|
| single LLM − deep agent | r1–r1 | 49 | 9 | 8.96e-08 |
| single LLM − deep agent | r2–r2 | 52 | 9 | 1.80e-08 |
| single LLM − deep agent | r3–r3 | 49 | 10 | 2.71e-07 |
| ablation − single LLM | r1–r1 | 2 | 20 | 1.21e-04 |
| ablation − single LLM | r2–r2 | 5 | 13 | 9.63e-02 |
| ablation − single LLM | r3–r3 | 5 | 16 | 2.66e-02 |
| ablation − deep agent | r1–r1 | 42 | 20 | 7.15e-03 |
| ablation − deep agent | r2–r2 | 51 | 16 | 2.17e-05 |
| ablation − deep agent | r3–r3 | 44 | 16 | 3.94e-04 |

Akurasi 6 kelas pada 30 baris pilot vs 470 baris lain (baris pilot lebih mudah bila akurasinya lebih tinggi):

| Method | Pilot (30) | Lain (470) |
|---|---|---|
| Regex (CRS PL1, 6 categories) | 0.767 | 0.694 |
| Full regex (all categories; post hoc) | 0.867 | 0.826 |
| Single LLM (zero-shot) | 0.767† | 0.835(0.832–0.836) |
| Deep agent | 0.733† | 0.748(0.740–0.753) |
| Single LLM + verifier loop (ablation) | 0.733† | 0.809(0.798–0.815) |

## 2. Kaskade §3.6 (post hoc): baris NORMAL menurut regex diteruskan ke LLM tunggal

| Configuration | Lines sent to the LLM | Macro-F1 | 95% CI | Binary F1 | FPR | FPR excl. invalid | USD per 1,000 lines, billed | USD per 1,000 lines, list price |
|---|---|---|---|---|---|---|---|---|
| Cascade: regex → single LLM | 236 | 0.900(0.898–0.902) | [0.838, 0.939] | 0.946(0.944–0.948) | 0.030(0.023–0.034) | 0.030(0.023–0.034) | 0.062† | 0.062† |
| Cascade: full regex (post hoc) → single LLM | 170 | 0.975(0.972–0.978) | [0.943, 0.987] | 0.991(0.989–0.993) | 0.030(0.023–0.034) | 0.030(0.023–0.034) | 0.045† | 0.045† |
| Sensitivity: regex with restricted files → PATH_TRAVERSAL (class_map 930) → single LLM | 236 | 0.865(0.863–0.867) | [0.788, 0.917] | 0.946(0.944–0.948) | 0.030(0.023–0.034) | 0.030(0.023–0.034) | 0.062† | 0.062† |

Pembanding: LLM tunggal sendiri 0.131(0.131–0.132) USD per 1,000 baris (billed). FPR kaskade = FPR LLM tunggal bila lapis pertama tidak menandai satu pun baris NORMAL.

Baris yang diteruskan ke LLM per kelas gerbang, dan yang diberi kelas gerbangnya oleh LLM (rerata run):

| Configuration | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|
| Cascade: regex → single LLM | 66.0† / 67 | 0.0† / 0 | 10.3(9.0–12.0) / 16 | 14.0† / 14 | 13.0(12.0–14.0) / 51 | 85.3(85.0–86.0) / 88 |
| Cascade: full regex (post hoc) → single LLM | 66.0† / 67 | 0.0† / 0 | 10.0(9.0–11.0) / 15 | 0.0† / 0 | 0.0† / 0 | 85.3(85.0–86.0) / 88 |
| Sensitivity: regex with restricted files → PATH_TRAVERSAL (class_map 930) → single LLM | 66.0† / 67 | 0.0† / 0 | 10.3(9.0–12.0) / 16 | 14.0† / 14 | 13.0(12.0–14.0) / 51 | 85.3(85.0–86.0) / 88 |

F1 dan recall per kelas kaskade:

| Configuration | Metric | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL |
|---|---|---|---|---|---|---|---|
| Cascade: regex → single LLM | F1 | 0.983† | 0.966† | 0.946(0.936–0.960) | 0.983† | 0.723(0.714–0.732) | 0.801(0.794–0.808) |
| Cascade: regex → single LLM | Recall | 0.966† | 1.000† | 0.925(0.910–0.944) | 1.000† | 0.573(0.562–0.584) | 0.970(0.966–0.977) |
| Cascade: full regex (post hoc) → single LLM | F1 | 0.983† | 0.977(0.974–0.982) | 0.959(0.953–0.965) | 0.983† | 0.989† | 0.957(0.950–0.966) |
| Cascade: full regex (post hoc) → single LLM | Recall | 0.966† | 1.000† | 0.921(0.910–0.933) | 1.000† | 1.000† | 0.970(0.966–0.977) |
| Sensitivity: regex with restricted files → PATH_TRAVERSAL (class_map 930) → single LLM | F1 | 0.983† | 0.966† | 0.876(0.866–0.889) | 0.983† | 0.583(0.571–0.594) | 0.801(0.794–0.808) |
| Sensitivity: regex with restricted files → PATH_TRAVERSAL (class_map 930) → single LLM | Recall | 0.966† | 1.000† | 0.925(0.910–0.944) | 1.000† | 0.416(0.404–0.427) | 0.970(0.966–0.977) |

Recall WEB_SCANNING per sub-tipe kaskade:

| Configuration | Non-standard methods (V1) | Scanner user agent (W1) | Backup/forbidden extensions (P1) | VCS or forbidden files (T3) |
|---|---|---|---|---|
| Cascade: regex → single LLM | 0.26(0.24–0.27) | 1.00† | 0.52(0.50–0.56) | 1.00† |
| Cascade: full regex (post hoc) → single LLM | 1.00† | 1.00† | 1.00† | 1.00† |
| Sensitivity: regex with restricted files → PATH_TRAVERSAL (class_map 930) → single LLM | 0.26(0.24–0.27) | 1.00† | 0.52(0.50–0.56) | 0.00† |

Uji berpasangan (10,000 draw; definisi Tabel 6):

| Comparison (A − B) | Difference | 95% CI | p, bootstrap | p, permutation |
|---|---|---|---|---|
| Cascade (regex → single LLM) − single LLM | 0.071 | [0.040, 0.118] | <0.001 | <0.001 |
| Cascade (regex → single LLM) − regex | 0.184 | [0.129, 0.253] | <0.001 | <0.001 |
| Cascade (full regex → single LLM) − single LLM | 0.145 | [0.099, 0.214] | <0.001 | <0.001 |
| Cascade (full regex → single LLM) − full regex (post hoc) | 0.154 | [0.115, 0.205] | <0.001 | <0.001 |
| Sensitivity cascade (restricted files → PATH_TRAVERSAL) − single LLM | 0.035 | [0.002, 0.071] | 0.039 | 0.026 |
| Sensitivity cascade (restricted files → PATH_TRAVERSAL) − regex with restricted files → PATH_TRAVERSAL | 0.189 | [0.133, 0.262] | <0.001 | <0.001 |

## 3. Recall WEB_SCANNING per sub-tipe (aturan gerbang)

| Sub-type (gate rule) | Lines | Regex (CRS PL1, 6 categories) | Full regex (all categories; post hoc) | Single LLM (zero-shot) | Deep agent | Single LLM + verifier loop (ablation) |
|---|---|---|---|---|---|---|
| Non-standard methods (V1) | 41 | 0.15 | 1.00 | 0.21(0.20–0.22) | 0.05(0.02–0.07) | 0.20(0.20–0.22) |
| Scanner user agent (W1) | 18 | 1.00 | 1.00 | 1.00† | 1.00† | 1.00† |
| Backup/forbidden extensions (P1) | 16 | 0.00 | 1.00 | 0.52(0.50–0.56) | 0.06† | 0.44(0.38–0.50) |
| VCS or forbidden files (T3) | 14 | 1.00 | 1.00 | 0.36† | 0.00† | 0.26(0.21–0.29) |

Recall per template_key (T3:lainnya dirinci menurut nama berkas):

| Template | Lines | Regex (CRS PL1, 6 categories) | Full regex (all categories; post hoc) | Single LLM (zero-shot) | Deep agent | Single LLM + verifier loop (ablation) |
|---|---|---|---|---|---|---|
| V1:MOVE | 7 | 0.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| V1:PATCH | 6 | 0.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| V1:LOCK | 5 | 0.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| V1:PROPPATCH | 4 | 0.00 | 1.00 | 0.42(0.25–0.50) | 0.00† | 0.50† |
| V1:COPY | 4 | 0.00 | 1.00 | 0.00† | 0.25† | 0.00† |
| V1:TRACK | 4 | 1.00 | 1.00 | 0.50† | 0.00† | 0.33(0.25–0.50) |
| V1:UNLOCK | 3 | 0.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| V1:MKCOL | 3 | 0.00 | 1.00 | 1.00† | 0.11(0.00–0.33) | 1.00† |
| V1:PUT | 3 | 0.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| V1:PROPFIND | 2 | 1.00 | 1.00 | 1.00† | 0.33(0.00–0.50) | 1.00† |
| W1:Nmap | 18 | 1.00 | 1.00 | 1.00† | 1.00† | 1.00† |
| P1:.bak | 5 | 0.00 | 1.00 | 0.80† | 0.00† | 0.67(0.60–0.80) |
| P1:.log | 4 | 0.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| P1:.backup | 4 | 0.00 | 1.00 | 0.33(0.25–0.50) | 0.00† | 0.17(0.00–0.25) |
| P1:.swp | 3 | 0.00 | 1.00 | 1.00† | 0.33† | 1.00† |
| T3:.svn | 5 | 1.00 | 1.00 | 0.60† | 0.00† | 0.47(0.40–0.60) |
| T3:.htaccess | 5 | 1.00 | 1.00 | 0.00† | 0.00† | 0.00† |
| T3:.git | 4 | 1.00 | 1.00 | 0.50† | 0.00† | 0.33(0.25–0.50) |

Prediksi pada baris sub-tipe (rerata per run):

- Regex (CRS PL1, 6 categories): V1 NORMAL 35.0, WEB_SCANNING 6.0; W1 WEB_SCANNING 18.0; P1 NORMAL 16.0; T3 WEB_SCANNING 14.0
- Full regex (all categories; post hoc): V1 WEB_SCANNING 41.0; W1 WEB_SCANNING 18.0; P1 WEB_SCANNING 16.0; T3 WEB_SCANNING 14.0
- Single LLM (zero-shot): V1 NORMAL 30.3, WEB_SCANNING 8.7, PATH_TRAVERSAL 1.7, XSS 0.3; W1 WEB_SCANNING 18.0; P1 WEB_SCANNING 8.3, NORMAL 5.7, PATH_TRAVERSAL 1.0, XSS 1.0; T3 PATH_TRAVERSAL 5.7, WEB_SCANNING 5.0, NORMAL 3.3
- Deep agent: V1 NORMAL 38.0, WEB_SCANNING 2.0, invalid 1.0; W1 WEB_SCANNING 18.0; P1 NORMAL 15.0, WEB_SCANNING 1.0; T3 PATH_TRAVERSAL 13.0, NORMAL 1.0
- Single LLM + verifier loop (ablation): V1 NORMAL 30.7, WEB_SCANNING 8.3, PATH_TRAVERSAL 1.7, XSS 0.3; W1 WEB_SCANNING 18.0; P1 NORMAL 7.0, WEB_SCANNING 7.0, PATH_TRAVERSAL 1.0, XSS 1.0; T3 PATH_TRAVERSAL 6.0, NORMAL 4.3, WEB_SCANNING 3.7

Aturan regex berkelas WEB_SCANNING yang cocok (jumlah baris per aturan):

- Regex (CRS PL1, 6 categories): V1 BS-METHOD 6; W1 913100 18; P1 tidak ada; T3 930130 14
- Full regex (all categories; post hoc): V1 911100 41, BS-METHOD 6; W1 913100 18, 920440 1; P1 920440 16; T3 930130 14, 920440 3

## 4. Label berubah antar run, menurut kelas gerbang

| Method | Lines | SQLI | XSS | PATH_TRAVERSAL | CMD_INJECTION | WEB_SCANNING | NORMAL | With an invalid output | Between valid classes only |
|---|---|---|---|---|---|---|---|---|---|
| Single LLM (zero-shot) | 16 | 0 | 0 | 5 | 6 | 4 | 1 | 0 | 16 |
| Deep agent | 26 | 2 | 0 | 4 | 10 | 4 | 6 | 14 | 12 |
| Single LLM + verifier loop (ablation) | 37 | 0 | 0 | 13 | 9 | 14 | 1 | 0 | 37 |

Baris berubah yang memuat label tertentu di salah satu run (satu baris bisa dihitung di lebih dari satu label):

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
- Aturan 942 terpakai (PL1, regex) di konfigurasi utama: 19; yang memeriksa path (REQUEST_FILENAME, REQUEST_BASENAME, REQUEST_URI, REQUEST_URI_RAW, REQUEST_LINE): 942160, 942550 (jumlah baris dari 500 yang memicunya: 942160 20, 942550 0).
- Aturan 942 pada baris SQLI yang diprediksi SQLI (jumlah baris): 942160 20.

## 6. Dedup persis vs dedup isi (kontrafaktual dari data/raw)

- Bingkai 6 kelas dibangun ulang dari data/raw (MD5 `173ec515308bdce5aec19cfd5b792596`): 691,768 baris dari 907,815. Paritas: srbh_train/val/test.parquet dan baris RFI_TEMPLATE_CAP srbh_excluded.parquet cocok.
- Dedup isi (resmi, kunci raw_log_masked = baris log tanpa stempel waktu dan protokol): dibuang 387,099 (konflik label 0), sisa 304,669.
- Dedup persis (raw_log utuh dengan stempel waktu): dibuang **14,257** (konflik label 0), sisa 677,511; duplikat per kelas (tanpa baris konflik): NORMAL 12,223, SQLI 1,693, WEB_SCANNING 245, PATH_TRAVERSAL 54, CMD_INJECTION 41, XSS 1.
- Kontrafaktual dedup persis -> batas templat RFI (200) -> split (split baru: train 449,881, uji 96,404): baris uji yang punya kembaran isi (kunci audit.content_key = baris log tanpa stempel waktu) di train **59,366 dari 96,404 (61.58%)**; NORMAL 91.7%, kelas serangan 13.9%; per kelas: SQLI 4,599/32,141, XSS 0/56, PATH_TRAVERSAL 417/2,908, CMD_INJECTION 10/457, WEB_SCANNING 148/1,715, NORMAL 54,192/59,127.
- Kontrafaktual dedup persis -> split (tanpa batas templat RFI) (split baru: train 474,257, uji 101,627): baris uji yang punya kembaran isi (kunci audit.content_key = baris log tanpa stempel waktu) di train **59,442 dari 101,627 (58.49%)**; NORMAL 91.5%, kelas serangan 12.6%; per kelas: SQLI 4,429/32,141, XSS 0/56, PATH_TRAVERSAL 790/8,131, CMD_INJECTION 11/457, WEB_SCANNING 139/1,715, NORMAL 54,073/59,127.
