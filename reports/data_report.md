# Laporan Data — SR-BH 2020 (Langkah 1–10)

Dihasilkan otomatis oleh `make data` (`python -m src.data.prepare`). Alamat IPv4 pada contoh disamarkan (a.b.x.x).

## 1. Sumber

- SR-BH 2020, Harvard Dataverse doi:10.7910/DVN/OGOIXX (versi 1.2, CC0 1.0), berkas `data_capec_multilabel.csv`, MD5 `173ec515308bdce5aec19cfd5b792596`.
- 907.815 baris, 24 fitur + 14 kolom label (1 normal + 13 CAPEC). Inspeksi lengkap: `reports/srbh_inspection.md`.
- Usulan dan bukti pemetaan label: `reports/label_mapping_proposal.md`; pemetaan yang dipakai: `configs/label_mapping.yaml`.

## 2. Jumlah baris per tahap

| tahap | baris |
|---|---|
| CSV mentah | 907.815 |
| dikeluarkan oleh gerbang bukti (EXCLUDED) | 216.047 |
| masuk dataset 6 kelas | 691.768 |
| dibuang: duplikat isi (`raw_log_masked`: tanpa waktu dan protokol) | 387.099 |
| dibuang: isi identik berlabel berbeda | 0 |
| setelah dedup | 304.669 |
| dibuang: batas 200 per templat RFI (label 194) | 32.562 |
| setelah batas templat (masuk split) | 272.107 |
| srbh_train / srbh_val / srbh_test | 190.474 / 40.816 / 40.817 |
| test_sample_500 | 500 |

Duplikat yang dibuang per kelas: NORMAL 358.018, SQLI 23.433, PATH_TRAVERSAL 4.494, WEB_SCANNING 1.054, CMD_INJECTION 97, XSS 3.

Kunci dedup = `raw_log_masked` (stempel waktu dikonstankan dan protokol diseragamkan; keputusan penulis), sehingga permintaan yang sama pada detik berbeda hanya disimpan sekali, yaitu kemunculan pertamanya di berkas. 272.107 baris yang masuk split berisi 272.107 isi berbeda (tanpa stempel waktu).

## 3. Pemetaan label dan gerbang bukti

Kelas akhir sebuah baris harus (1) berasal dari salah satu label SR-BH miliknya dan (2) buktinya terlihat di field Combined Log Format. Baris yang tidak memenuhi dikeluarkan dengan kode alasan dan disimpan di `data/processed/srbh_excluded.parquet`.

| kelas | baris (sebelum dedup) |
|---|---|
| SQLI | 215.963 |
| XSS | 378 |
| PATH_TRAVERSAL | 54.260 |
| CMD_INJECTION | 3.089 |
| WEB_SCANNING | 11.678 |
| NORMAL | 406.400 |
| EXCLUDED | 216.047 |

SQLI berbukti lemah (aturan S2: hanya probe metakarakter 1–2 karakter tanpa sintaks SQL, yaitu salah satu dari ' " ( ) ; % | atau NULL, atau pasangan kutip '" / "'): 28.625 baris, ditandai `weak_evidence=True`.

Multi-label: setiap label aktif menyumbang kandidat kelas, alasan eksklusi, atau tidak keduanya (netral). Bila ada beberapa kandidat, berlaku prioritas CMD_INJECTION > SQLI > XSS > PATH_TRAVERSAL > WEB_SCANNING; bila tidak ada kandidat, alasan dipilih dengan urutan LABEL_MISMATCH > OUT_OF_SCOPE > RFI_SCHEMELESS > HIDDEN_EVIDENCE > NO_EVIDENCE. Hanya 962 baris yang punya lebih dari satu kandidat: CMD_INJECTION vs PATH_TRAVERSAL 935, PATH_TRAVERSAL vs WEB_SCANNING 23, SQLI vs WEB_SCANNING 2, WEB_SCANNING vs XSS 2.

### Jumlah dikeluarkan per label (syarat K1)

Kolom "kelas akhir" dan "alasan akhir" menunjukkan hasil akhir baris, yang bisa ditentukan label lain pada baris yang sama. Contohnya label 33 dan 248 (target sendiri UNMAPPED) tetap tampak punya baris CMD_INJECTION/WEB_SCANNING karena label pendampingnya. Satu baris multi-label dihitung di setiap labelnya. Tabel paritas di bawah sebaliknya hanya menghitung aturan milik label itu sendiri, sehingga kedua tabel bisa berbeda tipis. Angka K2a (118.793) adalah N1+N2+N3; dua baris kosong (EMPTY_ROW) membuat total eksklusi label Normal menjadi 118.795.

| label | target label sendiri | baris berlabel | kelas akhir baris-baris itu | dikeluarkan | alasan akhir dikeluarkan |
|---|---|---|---|---|---|
| 000 - Normal | NORMAL | 525.195 | NORMAL 406.400 | 118.795 | LABELER_BLIND 71.431, SCANNER_PROBE 29.984, INSPECTED_VISIBLE_PAYLOAD 17.378, EMPTY_ROW 2 |
| 272 - Protocol Manipulation | WEB_SCANNING | 9.153 | SQLI 124, PATH_TRAVERSAL 23, CMD_INJECTION 26, WEB_SCANNING 4.106 | 4.874 | NO_EVIDENCE 3.623, OUT_OF_SCOPE 636, HIDDEN_EVIDENCE 613, LABEL_MISMATCH 2 |
| 242 - Code Injection | XSS | 15.827 | XSS 378, CMD_INJECTION 683, WEB_SCANNING 1 | 14.765 | OUT_OF_SCOPE 13.742, HIDDEN_EVIDENCE 1.023 |
| 88 - OS Command Injection | CMD_INJECTION | 7.482 | PATH_TRAVERSAL 344, CMD_INJECTION 3.089, WEB_SCANNING 1 | 4.048 | HIDDEN_EVIDENCE 3.792, OUT_OF_SCOPE 254, NO_EVIDENCE 2 |
| 126 - Path Traversal | PATH_TRAVERSAL | 20.992 | PATH_TRAVERSAL 16.430, CMD_INJECTION 935, WEB_SCANNING 1.356 | 2.271 | HIDDEN_EVIDENCE 2.271 |
| 66 - SQL Injection | SQLI | 250.311 | SQLI 215.963, XSS 203, PATH_TRAVERSAL 1, CMD_INJECTION 170, WEB_SCANNING 5 | 33.969 | LABEL_MISMATCH 22.473, OUT_OF_SCOPE 5.530, HIDDEN_EVIDENCE 5.355, NO_EVIDENCE 611 |
| 16 - Dictionary-based Password Attack | UNMAPPED | 1.847 | SQLI 144, XSS 2, PATH_TRAVERSAL 10, CMD_INJECTION 4, WEB_SCANNING 9 | 1.678 | HIDDEN_EVIDENCE 1.039, OUT_OF_SCOPE 633, LABEL_MISMATCH 6 |
| 310 - Scanning for Vulnerable Software | WEB_SCANNING | 2.718 | SQLI 2, XSS 2, PATH_TRAVERSAL 23, WEB_SCANNING 2.691 | 0 | – |
| 153 - Input Data Manipulation | UNMAPPED | 2.272 | WEB_SCANNING 1 | 2.271 | HIDDEN_EVIDENCE 2.271 |
| 248 - Command Injection | UNMAPPED | 1 | WEB_SCANNING 1 | 0 | – |
| 274 - HTTP Verb Tampering | WEB_SCANNING | 5.437 | WEB_SCANNING 5.437 | 0 | – |
| 194 - Fake the Source of Data | PATH_TRAVERSAL | 56.145 | PATH_TRAVERSAL 37.830 | 18.315 | RFI_SCHEMELESS 12.262, OUT_OF_SCOPE 3.237, HIDDEN_EVIDENCE 2.280, NO_EVIDENCE 536 |
| 34 - HTTP Response Splitting | UNMAPPED | 19.738 | – | 19.738 | OUT_OF_SCOPE 14.448, LABEL_MISMATCH 4.624, HIDDEN_EVIDENCE 666 |
| 33 - HTTP Request Smuggling | UNMAPPED | 1.059 | CMD_INJECTION 513 | 546 | OUT_OF_SCOPE 510, HIDDEN_EVIDENCE 36 |

Total dikeluarkan per alasan: LABELER_BLIND 71.431, OUT_OF_SCOPE 38.022, SCANNER_PROBE 29.984, LABEL_MISMATCH 27.097, INSPECTED_VISIBLE_PAYLOAD 17.378, HIDDEN_EVIDENCE 15.099, RFI_SCHEMELESS 12.262, NO_EVIDENCE 4.772, EMPTY_ROW 2.

Arti kode alasan (dari `configs/label_mapping.yaml`):

| kode | arti |
|---|---|
| EMPTY_ROW | Semua field kosong. |
| LABELER_BLIND | Baris berlabel NORMAL yang path mentahnya (sebelum '?') mengandung %2F, atau bermetode TRACE. Fakta teramati: Apache menjawab 404 untuk semua 125.868 permintaan ber-%2F dan 405 untuk semua 2.340 TRACE; 56.729 permintaan ber-%2F dan 48 TRACE justru berlabel serangan, sedangkan keluarga payload yang sama dilabeli tidak konsisten (mis. \<script> di path: 2.335 dari 2.385 baris ber-%2F berlabel NORMAL, 0 dari 124 baris tanpa %2F). Label NORMAL pada kelompok ini karena itu tidak andal. Aturan ini tidak melihat isi payload. (Revisi 2026-10-07: penjelasan awal "Apache menolak sebelum WAF memeriksa" dicabut karena dibantah data.) |
| INSPECTED_VISIBLE_PAYLOAD | Baris berlabel NORMAL dengan payload serangan eksplisit yang terlihat di baris log. |
| SCANNER_PROBE | Baris berlabel NORMAL yang jelas buatan pemindai tanpa payload eksploit. |
| LABEL_MISMATCH | Payload yang terlihat adalah kelas lain yang labelnya tidak dimiliki baris itu. |
| OUT_OF_SCOPE | Payload di luar taksonomi 6 kelas (injeksi kode PHP/EL, CRLF, open redirect, XPath, dll.). |
| RFI_SCHEMELESS | Templat RFI tanpa skema http(s)://; nama host polos tidak bisa dibaca sebagai inklusi berkas. |
| HIDDEN_EVIDENCE | Bukti hanya ada di body POST, cookie, atau header yang tidak tercatat di log akses. |
| NO_EVIDENCE | Tidak ada bukti untuk label tersebut di field mana pun. |

### Independensi dan sirkularitas terhadap metode berbasis pola (§3.4–§3.5 skripsi)

Asal-usul pola gerbang (`src/data/gate/`): pola ditulis dari templat payload yang teramati di SR-BH (analisis bukti 2026-10-07), dan alternatif yang tidak pernah cocok di data dibuang. CRS menjadi rujukan diagnosis di analisis bukti, yaitu untuk memahami aturan mana yang memicu label (daftar restricted_extensions 920440, daftar UA pemindai 913, pola mirip 921xxx, semantik 930130). Satu-satunya daftar turunan CRS yang dipakai gerbang adalah daftar ekstensi aturan P1.

Tumpang-tindih yang perlu dinyatakan sebelum baseline §3.5 (CRS 941/942/930/931/932/913 + aturan pemindaian Baş Seyyar dkk.) dibangun:

- P1 (label 272): 11 ekstensi berkas cadangan/terlarang yang muncul di SR-BH, subset restricted_extensions CRS 920440. Kategori 920 tidak termasuk baseline, tetapi bila 920440 kelak ditambahkan, tumpang-tindih ini harus disebut.
- W1 (label 310): UA "Nmap Scripting Engine" dan "zgrab". Polanya tidak disalin dari CRS, tetapi daftar UA kategori 913 juga memuat keduanya, sehingga baris WEB_SCANNING dari label 310 terlihat oleh baseline secara konsep.
- T1/T3 (label 126): keluarga berkas OS (etc/passwd, win.ini, boot.ini) dan berkas terlarang (.git, .svn, .htaccess, cadangan wp-config) adalah sasaran kategori 930 (LFI). Gerbang memetakan berkas terlarang tanpa traversal (T3) ke WEB_SCANNING, sedangkan semantik CRS 930130 menganggapnya LFI. Pemetaan kelas baseline untuk hit 930130 harus diputuskan dan dicatat sebelum penilaian, agar baseline tidak dinilai salah karena pilihan taksonomi.
- V1/P1/T3/W1 (WEB_SCANNING) belum dibandingkan dengan aturan pemindaian Baş Seyyar dkk. karena baseline belum ada.

Larangan impor/salin modul gerbang berlaku untuk baseline §3.5 **dan** untuk alat `pattern_match`/`lookup_owasp` sub-agen Analisis Payload deep agent (§3.4), karena keduanya juga diturunkan dari CRS.

Sirkularitas yang tidak bisa dihilangkan: label SR-BH adalah keluaran CRS (ditinjau penulis dataset), sehingga komponen apa pun yang diturunkan dari CRS (baseline maupun alat agen) diuntungkan sejak awal. Selain itu, gerbang memilih baris serangan yang buktinya terlihat oleh pola dan membersihkan NORMAL dari pola payload/probe. Bila aturan pembersih NORMAL (N1–N3) dijalankan tanpa label pada sampel uji, aturan itu menandai SQLI 21/89, XSS 56/56, PATH_TRAVERSAL 89/89, CMD_INJECTION 89/89, WEB_SCANNING 39/89, NORMAL 0/88. Untuk kelas yang hampir seluruhnya tertandai, pemisahan serangan vs normal pada data uji praktis sama dengan himpunan pola gerbang itu sendiri. Recall dan FPR komponen berbasis pola karena itu batas atas, dan ketahanan terhadap obfuscation di luar keluarga payload ini tidak teruji.

### Paritas aturan terhadap angka yang disetujui

| label | aturan | rows_expected (disetujui) | aktual | cocok |
|---|---|---|---|---|
| 000 - Normal | N0 | 2 | 2 | ✓ |
| 000 - Normal | N1 | 71.431 | 71.431 | ✓ |
| 000 - Normal | N2 | 17.378 | 17.378 | ✓ |
| 000 - Normal | N3 | 29.984 | 29.984 | ✓ |
| 000 - Normal | N4 | 406.400 | 406.400 | ✓ |
| 66 - SQL Injection | S1 | 187.338 | 187.338 | ✓ |
| 66 - SQL Injection | S2 | 28.625 | 28.625 | ✓ |
| 66 - SQL Injection | S3 | 22.847 | 22.847 | ✓ |
| 66 - SQL Injection | S4 | 5.529 | 5.529 | ✓ |
| 66 - SQL Injection | S5 | 5.340 | 5.340 | ✓ |
| 66 - SQL Injection | S6 | 629 | 629 | ✓ |
| 66 - SQL Injection | S7 | 3 | 3 | ✓ |
| 242 - Code Injection | K1 | 378 | 378 | ✓ |
| 242 - Code Injection | K2 | 170 | 170 | ✓ |
| 242 - Code Injection | K3 | 13.717 | 13.717 | ✓ |
| 242 - Code Injection | K4 | 539 | 539 | ✓ |
| 242 - Code Injection | K5 | 1.023 | 1.023 | ✓ |
| 88 - OS Command Injection | C1 | 3.089 | 3.089 | ✓ |
| 88 - OS Command Injection | C2 | 344 | 344 | ✓ |
| 88 - OS Command Injection | C3 | 254 | 254 | ✓ |
| 88 - OS Command Injection | C4 | 3.792 | 3.792 | ✓ |
| 88 - OS Command Injection | C5 | 3 | 3 | ✓ |
| 248 - Command Injection | C0 | 1 | 1 | ✓ |
| 126 - Path Traversal | T1 | 16.430 | 16.430 | ✓ |
| 126 - Path Traversal | T2 | 935 | 935 | ✓ |
| 126 - Path Traversal | T3 | 1.356 | 1.356 | ✓ |
| 126 - Path Traversal | T4 | 2.271 | 2.271 | ✓ |
| 310 - Scanning for Vulnerable Software | W1 | 2.718 | 2.718 | ✓ |
| 310 - Scanning for Vulnerable Software | W2 | 0 | 0 | ✓ |
| 194 - Fake the Source of Data | F1 | 37.830 | 37.830 | ✓ |
| 194 - Fake the Source of Data | F2 | 12.263 | 12.263 | ✓ |
| 194 - Fake the Source of Data | F3 | 3.236 | 3.236 | ✓ |
| 194 - Fake the Source of Data | F4 | 2.280 | 2.280 | ✓ |
| 194 - Fake the Source of Data | F5 | 536 | 536 | ✓ |
| 34 - HTTP Response Splitting | R1 | 14.448 | 14.448 | ✓ |
| 34 - HTTP Response Splitting | R2 | 4.624 | 4.624 | ✓ |
| 34 - HTTP Response Splitting | R3 | 666 | 666 | ✓ |
| 33 - HTTP Request Smuggling | R0 | 513 | 513 | ✓ |
| 33 - HTTP Request Smuggling | R1 | 510 | 510 | ✓ |
| 33 - HTTP Request Smuggling | R3 | 36 | 36 | ✓ |
| 272 - Protocol Manipulation | P1 | 3.931 | 3.931 | ✓ |
| 272 - Protocol Manipulation | P2 | 3.632 | 3.632 | ✓ |
| 272 - Protocol Manipulation | P3 | 994 | 994 | ✓ |
| 272 - Protocol Manipulation | P4 | 596 | 596 | ✓ |
| 274 - HTTP Verb Tampering | V1 | 5.437 | 5.437 | ✓ |
| 16 - Dictionary-based Password Attack | B1 | 1.039 | 1.039 | ✓ |
| 16 - Dictionary-based Password Attack | B2 | 808 | 808 | ✓ |
| 153 - Input Data Manipulation | I1 | 2.272 | 2.272 | ✓ |

Semua aturan cocok dengan angka yang disetujui. Pipeline berhenti dengan galat bila ada yang tidak cocok.

### Pembanding: target per label tanpa gerbang bukti

Kelas = `target` per label di `configs/label_mapping.yaml` (termasuk 194→PATH_TRAVERSAL dan 272/274→WEB_SCANNING dari D6/D7; 248, 34, 33, 16, 153 UNMAPPED), prioritas penulis untuk multi-label, label NORMAL apa adanya, tanpa pemeriksaan bukti. Ini **bukan** Varian A di `reports/label_mapping_proposal.md` (pemetaan langsung per nama CAPEC: 194/272/274 UNMAPPED, 248→CMD_INJECTION), sehingga angka PATH_TRAVERSAL, WEB_SCANNING, CMD_INJECTION, dan EXCLUDED berbeda dari sana.

| kelas | baris |
|---|---|
| NORMAL | 525.195 |
| SQLI | 249.919 |
| PATH_TRAVERSAL | 74.192 |
| EXCLUDED | 22.027 |
| WEB_SCANNING | 15.162 |
| XSS | 13.838 |
| CMD_INJECTION | 7.482 |

## 4. Batas templat RFI (label 194 → PATH_TRAVERSAL)

Setelah dedup, setiap templat payload RFI dibatasi maksimal 200 baris (acak, random_state=42).

| templat | sebelum | sesudah |
|---|---|---|
| HTTP://www.google.com | 2.273 | 200 |
| HTTP://www.google.com/ | 2.273 | 200 |
| HTTP://www.google.com/search?q=OWASP \<w> | 2.518 | 200 |
| HTTP://www.google.com:80/ | 2.273 | 200 |
| HTTP://www.google.com:80/search?q=OWASP \<w> | 2.517 | 200 |
| http://www.google.com | 2.273 | 200 |
| http://www.google.com/ | 2.273 | 200 |
| http://www.google.com/search?q=OWASP \<w> | 2.518 | 200 |
| http://www.google.com:80/ | 2.273 | 200 |
| http://www.google.com:80/search?q=OWASP \<w> | 2.518 | 200 |
| https://www.google.com | 2.273 | 200 |
| https://www.google.com/ | 2.273 | 200 |
| https://www.google.com/search?q=OWASP \<w> | 2.516 | 200 |
| https://www.google.com:80/ | 2.273 | 200 |
| https://www.google.com:80/search?q=OWASP \<w> | 2.518 | 200 |

Total: 35.562 → 3.000 baris; porsi label 194 di PATH_TRAVERSAL setelah batas: 17,44%.

## 5. Distribusi kelas per split

| kelas | train | val | test |
|---|---|---|---|
| SQLI | 134.770 (70,76%) | 28.880 (70,76%) | 28.880 (70,75%) |
| XSS | 263 (0,14%) | 56 (0,14%) | 56 (0,14%) |
| PATH_TRAVERSAL | 12.043 (6,32%) | 2.580 (6,32%) | 2.581 (6,32%) |
| CMD_INJECTION | 2.094 (1,10%) | 449 (1,10%) | 449 (1,10%) |
| WEB_SCANNING | 7.437 (3,90%) | 1.594 (3,91%) | 1.593 (3,90%) |
| NORMAL | 33.867 (17,78%) | 7.257 (17,78%) | 7.258 (17,78%) |
| **total** | 190.474 | 40.816 | 40.817 |

Pemeriksaan kembaran isi (baris log tanpa stempel waktu) antara train dan bagian lain, per kelas. Karena dedup isi dilakukan sebelum split, semua angka harus 0:

| kelas | val: punya kembaran di train | test: punya kembaran di train | sampel 500: punya kembaran di train |
|---|---|---|---|
| SQLI | 0/28.880 (0,0%) | 0/28.880 (0,0%) | 0/89 (0,0%) |
| XSS | 0/56 (0,0%) | 0/56 (0,0%) | 0/56 (0,0%) |
| PATH_TRAVERSAL | 0/2.580 (0,0%) | 0/2.581 (0,0%) | 0/89 (0,0%) |
| CMD_INJECTION | 0/449 (0,0%) | 0/449 (0,0%) | 0/89 (0,0%) |
| WEB_SCANNING | 0/1.594 (0,0%) | 0/1.593 (0,0%) | 0/89 (0,0%) |
| NORMAL | 0/7.257 (0,0%) | 0/7.258 (0,0%) | 0/88 (0,0%) |
| **total** | 0/40.816 (0,0%) | 0/40.817 (0,0%) | 0/500 (0,0%) |

Pool few-shot (kolom `fewshot_eligible` di srbh_train): 190.474 baris layak; 0 baris dikeluarkan karena isinya muncul di srbh_test.

## 6. Sampel uji 500 baris (`test_sample_500.jsonl`)

Kolom: `id`; kolom evaluasi `label` dan `template_key` (**tidak boleh diberikan ke metode**); masukan metode `raw_log_masked`, hasil parsing tanpa time/timestamp/protocol (`ip`, `ident`, `user`, `method`, `path`, `query`, `status`, `bytes`, `referer`, `user_agent`), dan hasil normalisasi (`path_norm`, `query_norm`, `ua_norm`). raw_log asli, waktu, protokol, metadata label, dan fitur sesi hanya ada di parquet. Baris ditulis dalam urutan acak (random_state=42); id bersifat opak (§11). Setiap pengambilan acak per kelas memakai random_state=42.

| kelas | kuota (= baris di sampel) | pool yang dipakai |
|---|---|---|
| SQLI | 89 | 24.785 |
| XSS | 56 | 56 |
| PATH_TRAVERSAL | 89 | 2.581 |
| CMD_INJECTION | 89 | 449 |
| WEB_SCANNING | 89 | 1.593 |
| NORMAL | 88 | 1.623 |

Pool XSS = seluruh XSS di split uji; pool NORMAL = setelah batas templat. Pool SQLI mengikuti opsi `sample_weak_sqli = exclude`: split uji memuat 4.095 baris SQLI berbukti lemah dari 28.880 (14,2%); sesuai keputusan penulis, baris itu tidak masuk sampel. Komposisi sampel menurut aturan penentu kelas:

| kelas | aturan | baris |
|---|---|---|
| CMD_INJECTION | C1 | 89 |
| NORMAL | N4 | 88 |
| PATH_TRAVERSAL | T1 | 73 |
| PATH_TRAVERSAL | F1 | 16 |
| SQLI | S1 | 89 |
| WEB_SCANNING | V1 | 41 |
| WEB_SCANNING | W1 | 18 |
| WEB_SCANNING | P1 | 16 |
| WEB_SCANNING | T3 | 14 |
| XSS | K1 | 56 |

### Sampel NORMAL

Pool NORMAL di split uji 7.258 baris → 1.623 baris setelah batas 5 per templat (method, path tanpa query) → 88 baris diambil acak (random_state=42). Sampel mewakili **86 templat unik**; 16 baris ber-query; 0 baris `GET /`; 75 baris bertanggal 17–19 Juli, hari ketika pemindai berjalan (54 di antaranya memakai UA Firefox/70 milik alat uji).

Penyebabnya batas templat: di pool NORMAL uji, 73,78% baris bertanggal 20 Juli–1 November, tetapi baris itu hanya memuat 70 templat (method, path), sedangkan baris 17–19 Juli memuat 1.099 templat. Porsi 17–19 Juli karena itu naik dari 26,22% pool menjadi 82,81% pool setelah batas 5 per templat.

| method | baris |
|---|---|
| GET | 85 |
| OPTIONS | 3 |

Distribusi menurut keluarga path (dua segmen pertama):

| keluarga path | baris | templat |
|---|---|---|
| /blog/index.php | 46 | 44 |
| /blog/wp-content | 17 | 17 |
| /blog/wp-includes | 9 | 9 |
| /index.php/sample-page | 2 | 2 |
| /index.php/author | 1 | 1 |
| /index.php/2020 | 1 | 1 |
| /images/wp-admin | 1 | 1 |
| /dashicons.min.css/wp-includes | 1 | 1 |
| /blog/xmlrpc.php | 1 | 1 |
| /4/index.php | 1 | 1 |
| /blog | 1 | 1 |
| /blog/uploads | 1 | 1 |
| /blog/feed | 1 | 1 |
| /blog/author | 1 | 1 |
| /blog/38536cfd-4e8b-3340-b4c4-af387cc163a8.jpg | 1 | 1 |
| /blog%3B/wp-login.php | 1 | 1 |
| /blog%22/index.php | 1 | 1 |
| /index.php/search | 1 | 1 |

Templat yang muncul lebih dari sekali: `GET /blog/index.php/2020/04/04/rerum-soluta-et-quis-excepturi-labore/` (2), `GET /blog/index.php/2020/03/29/distinctio-sequi-officiis-occaecati` (2); 84 templat lain masing-masing 1 baris.

### Konsentrasi templat payload

Baris dalam satu kelas tidak saling bebas: banyak yang berasal dari templat payload pemindai yang sama. Kunci templat per kelas (hanya untuk pelaporan): XSS = potongan payload + pembawanya; PATH_TRAVERSAL = templat RFI atau bentuk traversal; CMD_INJECTION = potongan perintah; WEB_SCANNING = aturan + metode/UA/ekstensi; SQLI = potongan payload dengan angka disamakan; NORMAL = method + path. n efektif Kish = n² / Σ m² (m = baris per templat).

| kelas | baris | templat | templat terbesar | baris templat terbesar | porsi 3 teratas | n efektif (Kish) |
|---|---|---|---|---|---|---|
| SQLI | 89 | 54 | " UNION ALL SELECT NULL,NULL,NULL,NULL,N | 6 (7%) | 19% | 36,5 |
| XSS | 56 | 6 | uri:'"\<script>alert(1);\</script> | 27 (48%) | 93% | 2,8 |
| PATH_TRAVERSAL | 89 | 19 | uri:16x..%5C | 26 (29%) | 72% | 5,5 |
| CMD_INJECTION | 89 | 54 | uri:d allow_url_include=0 -d auto_p | 14 (16%) | 27% | 22,6 |
| WEB_SCANNING | 89 | 18 | W1:Nmap | 18 (20%) | 35% | 12,3 |
| NORMAL | 88 | 86 | GET /blog/index.php/2020/03/29/distinctio-sequi-officiis-occaecati | 2 (2%) | 6% | 84,2 |

Evaluasi memakai bootstrap klaster 1.000× yang meresampel templat, bukan baris (keputusan penulis), karena bootstrap per baris akan terlalu sempit untuk kelas yang didominasi satu templat. Kunci templat tiap baris disimpan di kolom `template_key` test_sample_500.jsonl.

### Waktu sebagai penanda kelas

Pemindai menjalankan satu jenis serangan dalam satu waktu, sehingga waktu permintaan menyandikan kelas. Dengan menebak label mayoritas baris train pada menit yang sama, tanpa melihat isi permintaan, sampel uji terklasifikasi dengan akurasi **92,6%** (Macro-F1 0,92). Distribusi tanggal per kelas di sampel:

| kelas | 17 Jul | 18 Jul | 19 Jul | 21 Jul | 22 Jul | 24 Jul | 25 Jul |
|---|---|---|---|---|---|---|---|
| SQLI | 0 | 76 | 13 | 0 | 0 | 0 | 0 |
| XSS | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| PATH_TRAVERSAL | 89 | 0 | 0 | 0 | 0 | 0 | 0 |
| CMD_INJECTION | 7 | 82 | 0 | 0 | 0 | 0 | 0 |
| WEB_SCANNING | 26 | 0 | 63 | 0 | 0 | 0 | 0 |
| NORMAL | 18 | 31 | 26 | 3 | 2 | 4 | 4 |

Karena itu metode hanya menerima `raw_log_masked` (waktu dikonstankan) dan kolom parsing tanpa time/timestamp/protocol (keputusan penulis); waktu asli hanya ada di parquet untuk analisis.

## 7. Rekonstruksi log (Langkah 4)

Format: `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"`. Placeholder dan aturan penulisan ada di daftar keputusan (§11). Teks waktu asli disimpan di `timestamp_original`. `raw_log_masked` = raw_log dengan [%t] diganti `[01/Jan/2020:00:00:00 +0000]` dan protokol request line diganti `HTTP/1.1`; kolom inilah yang menjadi masukan metode dan kunci dedup.

Waktu: offset di teks waktu diganti +0000 dan jam dinding dipertahankan. Rangkaian offset menurut urutan berkas:

| offset | baris pertama | baris terakhir | jumlah |
|---|---|---|---|
| +0100 | 0 | 2.919 | 2.920 |
| +0200 | 2.920 | 544.897 | 541.976 |
| +0100 | 544.898 | 907.814 | 362.917 |

Pada setiap pergantian, jam dinding berlanjut dengan langkah normal (mis. `18:59:58 +0100` → `19:00:13 +0200`). Jadi offset hanyalah label; konversi per-offset akan menciptakan tumpang-tindih 1 jam (17 Jul) dan celah 1 jam (19 Jul) palsu. Blok bertanggal 01/Nov/2020 (4.666 baris, baris 544.898–549.563): 2.920 baris pertamanya identik (jam, URI, UA) dengan baris 0–2.919, hanya tanggalnya berbeda. Ini artefak pembuat dataset.

Protokol: request line memakai `request_http_protocol` apa adanya. HTTP/1.0 hanya muncul di baris serangan dataset 6 kelas (CMD_INJECTION 1, WEB_SCANNING 451; 0 di NORMAL), sehingga protokol diseragamkan di `raw_log_masked` dan kolom `protocol` tidak diberikan ke metode.

## 8. Parsing (Langkah 5)

- Baris gagal diurai: **2** dari 907.815 (format: 2); row_id: 14410, 163884. Semuanya baris yang seluruh field-nya kosong (EMPTY_ROW).
- Gagal urai di dataset 6 kelas: 0.
- Field hasil urai dibandingkan dengan nilai asli CSV: metode, status, Referer, dan User-Agent identik untuk semua baris terurai.

## 9. Normalisasi (Langkah 6)

Kolom mentah `path`, `query`, `user_agent` dan versi ternormalisasinya `path_norm`, `query_norm`, `ua_norm` disimpan berdampingan. Aturannya ada di §11.

## 10. Fitur sesi: artefak dataset, tidak dipakai metode

Kolom `sess_req_60s`, `sess_4xx_ratio_60s`, `sess_uniq_paths_60s` (jendela 60 detik, tanpa IP; resolusi stempel waktu 1 detik sudah cukup untuk jendela ini) dihitung dan disimpan di parquet untuk analisis, tetapi **tidak dipakai metode mana pun**: klasifikasi murni per baris (keputusan penulis).

Alasannya adalah artefak dataset: median rasio status 4xx dalam jendela 60 detik adalah **0,00 untuk NORMAL** tetapi **0,65–0,96 untuk kelas serangan**. SR-BH hanya punya satu alamat IP dan seluruh serangan dikirim alat pemindai dalam jendela 17–19 Juli, sedangkan 73,31% baris NORMAL bertanggal 20 Juli–1 November. Fitur jendela waktu karena itu mengukur kapan sebuah permintaan terjadi, bukan apakah isinya serangan, sehingga akan menggelembungkan kinerja secara semu. Tabel berikut (dataset 6 kelas setelah batas templat) juga memperlihatkan penanda kelas lain di luar payload: status 404, `GET /`, HTTP/1.0, UA Firefox/70 milik alat uji, dan tanggal. Hal ini perlu dibahas sebagai keterbatasan di BAB IV.

| kelas | baris | status 404 | `GET /` | HTTP/1.0 | UA Firefox/70 | rentang tanggal | median req/60 dtk | median rasio 4xx | median path unik |
|---|---|---|---|---|---|---|---|---|---|
| SQLI | 192.530 | 90,70% | 0,00% | 0,00% | 97,34% | 17 Jul 2020 – 19 Jul 2020 | 305 | 0,93 | 239 |
| XSS | 375 | 29,07% | 0,00% | 0,00% | 75,47% | 17 Jul 2020 – 17 Jul 2020 | 716 | 0,77 | 424 |
| PATH_TRAVERSAL | 17.204 | 91,37% | 0,00% | 0,00% | 94,00% | 17 Jul 2020 – 19 Jul 2020 | 711 | 0,96 | 475 |
| CMD_INJECTION | 2.992 | 6,08% | 0,00% | 0,03% | 94,08% | 17 Jul 2020 – 19 Jul 2020 | 314 | 0,72 | 211 |
| WEB_SCANNING | 10.624 | 61,51% | 0,02% | 4,25% | 70,45% | 17 Jul 2020 – 19 Jul 2020 | 949 | 0,65 | 326 |
| NORMAL | 48.382 | 6,92% | 8,89% | 0,00% | 15,74% | 17 Jul 2020 – 01 Nov 2020 | 10 | 0,00 | 6 |

## 11. Daftar keputusan praproses

### Keputusan penulis

| # | keputusan | bagian |
|---|---|---|
| 1 | Enam kelas target dan SR-BH 2020 sebagai dataset utama | rancangan skripsi |
| 2 | K1: gerbang bukti dua kunci; pola gerbang tidak sama dengan regex pembanding §3.5 skripsi; eksklusi dilaporkan per label | §3 |
| 3 | K2a: 118.793 baris NORMAL bermasalah dikeluarkan dengan kode alasan | §3 |
| 4 | K3b: XSS hanya dari label; kuota XSS di sampel ±57; aturan split sama untuk semua kelas | §5, §6 |
| 5 | D4–D8: payload bertentangan dengan label dikeluarkan; PHP-CGI berlabel 88 → CMD; 194 → PT; probe penemuan → WEB_SCANNING; probe di luar taksonomi dikeluarkan | §3 |
| 6 | D9: SQLI berbukti lemah ditandai `weak_evidence` dan tidak dimasukkan ke sampel uji (`sample_weak_sqli = exclude`) | §3, §6 |
| 7 | Baris PT dari label 194: setelah dedup maksimal 200 baris per templat payload | §4 |
| 8 | Urutan prioritas multi-label CMD_INJECTION > SQLI > XSS > PATH_TRAVERSAL > WEB_SCANNING | §3 |
| 9 | Offset zona waktu di raw_log menjadi +0000; stempel waktu asli di kolom terpisah yang tidak dipakai metode | §7 |
| 10 | Split stratified biasa tanpa grup per IP | §5 |
| 11 | Fitur sesi (jendela 60 detik tanpa IP) tidak dipakai metode mana pun; klasifikasi murni per baris. Kolomnya tetap di parquet untuk analisis, tidak dimasukkan ke test_sample_500.jsonl | §10 |
| 12 | Sampel NORMAL: maksimal 5 baris per templat (method, path tanpa query), baris ber-query diutamakan secara proporsional, lalu diambil 88 | §6 |
| 13 | Dedup isi sebelum split: kunci = raw_log tanpa stempel waktu dan tanpa protokol (`raw_log_masked`); baris pertama dipertahankan | §2, §5 |
| 14 | `raw_log_masked`: [%t] → [01/Jan/2020:00:00:00 +0000] dan protokol → HTTP/1.1. Semua metode (regex, LLM tunggal, deep agent) hanya menerima raw_log_masked dan kolom hasil parsing tanpa time/timestamp/protocol; raw_log asli tetap di parquet | §6, §7 |
| 15 | Evaluasi nanti: bootstrap klaster 1.000× per templat payload dengan kunci templat §6; kunci disimpan di kolom `template_key` test_sample_500 | §6 |
| 16 | Few-shot: calon contoh dari train yang isinya (tanpa stempel waktu) muncul di srbh_test dikeluarkan dari pool (kolom `fewshot_eligible` di srbh_train) | §5 |

### Keputusan implementasi (wajib tercatat)

| # | keputusan | alasan/konteks |
|---|---|---|
| 1 | Dataset diunduh dari Harvard Dataverse (v1.2, berkas tunggal data_capec_multilabel.csv) karena data/raw/ belum ada; MD5 diverifikasi setiap kali pipeline berjalan; data/raw/ tidak pernah ditulis ulang | kesahihan sumber |
| 2 | Sumber kebenaran pemetaan di configs/label_mapping.yaml (ikut versi kode); data/processed/label_mapping.yaml = salinan + blok hitungan hasil run | data/ dikecualikan dari git |
| 3 | Kolom label dikenali dari isinya (hanya 0/1), bukan dari nama | permintaan inspeksi tanpa asumsi nama kolom |
| 4 | Semua 907.815 baris dipakai (publikasi menyebut 907.814); 2 baris kosong total dikeluarkan sebagai EMPTY_ROW | tidak membuang diam-diam |
| 5 | Aturan gerbang dipindahkan dari analisis bukti ke src/data/gate/ dengan paritas per baris terhadap angka yang disetujui; pola ditulis dari templat payload SR-BH dan alternatif yang tidak pernah cocok dibuang; CRS hanya rujukan diagnosis di analisis bukti, dan satu-satunya daftar turunan CRS yang dipakai adalah ekstensi aturan P1 (920440); pipeline berhenti dengan galat bila jumlah per aturan tidak sama dengan rows_expected | syarat K1, §3 |
| 6 | Rekonstruksi: %l dan %u = '-' (tidak ada di dataset); %h = src_ip; %b = response_content_length, '-' bila kosong, 0, atau metode HEAD; Referer/UA kosong = '-'; request line memakai URI mentah yang masih ter-encode dan protokol request_http_protocol apa adanya (templat spesifikasi menulis HTTP/1.1; HTTP/1.0 hanya muncul di baris serangan, §7); kutip/backslash/karakter kontrol di-escape seperti Apache | Langkah 4 |
| 7 | '+0000' diterapkan dengan mengganti teks offset; jam dinding asli dipertahankan. Offset SR-BH berganti (+0100 → +0200 → +0100) sementara jam dinding berjalan terus, sehingga konversi per-offset akan menciptakan tumpang-tindih 1 jam (17 Jul) dan celah 1 jam (19 Jul) palsu. Implementasi awal (konversi UTC) diganti setelah review | §7 |
| 8 | Parser: baris gagal urai ditandai `parse_error` (format/time/request), tidak dibuang; request line dicocokkan selagi masih ter-escape; path dan query dipisah pada '?' pertama | Langkah 5 |
| 9 | Normalisasi: maksimal 3 lapis URL-decode; '+'→spasi hanya pada lapis pertama query; entity HTML numerik dan entity bernama yang diakhiri ';' didekode (tanpa ';' dibiarkan agar parameter seperti \&copy= tidak rusak); karakter kontrol ditulis sebagai teks \\xhh; hanya 97 kata kunci (SQL, HTML/JS, shell, skema URL) yang dijadikan huruf kecil; UUID dan angka ≥6 digit yang tidak menempel huruf → \<*>; Referer tidak dinormalisasi (tidak diminta) | Langkah 6 |
| 10 | Jendela sesi = semua permintaan dengan detik dalam [t−59, t] (termasuk permintaan lain pada detik yang sama); dihitung atas seluruh aliran log terurai, termasuk baris yang nanti dikeluarkan/duplikat; 4xx = status 400–499; path unik memakai path mentah | Langkah 7 (kolom analisis saja) |
| 11 | Pada dedup isi, isi identik yang berlabel berbeda dibuang semua salinannya (jumlahnya dilaporkan di §2). Dedup awal memakai raw_log utuh (termasuk stempel waktu) dan diganti dedup isi atas keputusan penulis | Langkah 8 |
| 12 | Templat RFI = skema seperti tertulis + host[:port] + path (kata pencarian 'OWASP …' disamakan); pemilihan 200 baris acak dengan random_state=42; baris yang terpotong disimpan di srbh_excluded.parquet (RFI_TEMPLATE_CAP) | D6 |
| 13 | Split: train_test_split 30% lalu 50/50, stratified per kelas, random_state=42 | Langkah 8 |
| 14 | Sampel 500: seluruh XSS di split uji; sisa kuota dibagi rata ke lima kelas lain (kelebihan menurut urutan kelas); setiap pengambilan acak per kelas dan per templat NORMAL memakai random_state=42 | K3b |
| 15 | Tafsiran 'utamakan baris ber-query secara proporsional' (keputusan penulis #12): di setiap templat NORMAL, slot (maks. 5) dibagi proporsional antara baris ber-query dan tanpa query lalu dibulatkan ke atas untuk baris ber-query; bila salah satu jenis kurang, slot diisi jenis lain; 88 baris lalu diambil acak dari pool hasil batas. Templat = (method, path mentah tanpa query). Hanya 10 templat di pool uji yang mencampur kedua jenis baris | §6 |
| 16 | test_sample_500.jsonl = id + kolom evaluasi (label, template_key; tidak boleh diberikan ke metode) + masukan metode (raw_log_masked, hasil parsing tanpa time/timestamp/protocol, serta path_norm/query_norm/ua_norm). Kolom normalisasi diikutkan sebagai bagian 'kolom hasil parsing' karena diturunkan dari path/query/UA dan tidak memuat waktu atau protokol. raw_log asli, metadata label, dan fitur sesi hanya di parquet. Baris ditulis dalam urutan acak (random_state=42) karena urutan row_id = urutan waktu, yang mengelompokkan kelas | mencegah kebocoran |
| 17 | id = 'srbh-' + 16 heksa pertama SHA-256("srbh2020:\<row_id>"): stabil tetapi tidak membocorkan urutan berkas; row_id (posisi baris di CSV mentah) tetap di parquet untuk penelusuran | mencegah kebocoran |
| 18 | Byte NUL hasil decode tidak pernah dipakai sebagai kunci hash pandas (kunci memakai teks mentah yang bebas NUL) | bug yang ditemukan saat analisis |
| 19 | Sel tabel laporan meng-escape \\ \| \& \< agar HTML mentah dari payload (mis. \<script>) tidak ditafsirkan penampil Markdown | keterbacaan |

## 12. Contoh 3 baris per kelas (`raw_log_masked` dari sampel uji, seperti yang diterima metode; IP disamarkan)

**SQLI**

```text
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog%22+or+0+in+%28select+sleep%2815%29+%29+--+/wp-content/themes/twentyseventeen/assets/js/global.js?ver=1.0 HTTP/1.1" 404 276 "http://test-site.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020/03/22%27+AND+%28SELECT+3273+FROM%28SELECT+COUNT%28*%29%2CCONCAT%280x3a727a613a%2C%28SELECT+%28ELT%283273%3D3273%2C1%29%29%29%2C0x3a6172743a%2CFLOOR%28RAND%280%29*2%29%29x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x%29a%29+AND+%27mUth%27%3D%27mUth HTTP/1.1" 404 53918 "http://test-site.com/blog/index.php/page/2/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php%27%3BSELECT+SLEEP%285%29%23/2020/03/22 HTTP/1.1" 404 276 "http://test-site.com/blog/index.php/2020/03/22" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

**XSS**

```text
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "POST /blog/index.php/my-account/edit-password/ HTTP/1.1" 200 58056 "http://test-site.com/blog/index.php/my-account/edit-password/" "'\"<script>alert(1);</script>"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/%2527%2522%253Cscript%253Ealert%25281%2529%253B%253C%252Fscript%253E/edit-profile/%7B%7B%20data.icon HTTP/1.1" 404 53918 "http://test-site.com/blog/index.php/my-account/edit-profile/%7B%7B%20data.icon%20%7D%7D" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-content/plugins/user-registration/assets/js/frontend/my-account.min.js?ver=1.8.x.x HTTP/1.1" 200 932 "-" "'\"<script>alert(1);</script>"
```

**PATH_TRAVERSAL**

```text
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd/index.php/sample-page/feed HTTP/1.1" 404 276 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F/wp-content/plugins/user-registration/assets/js/frontend/user-registration.min.js?ver=1.8.x.x HTTP/1.1" 404 276 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-content/%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C/2020/04/40ce1958-204f-369e-bc5a-32d63da4963f.png HTTP/1.1" 404 276 "http://test-site.com/blog/index.php/sample-page/nulla-quisquam-est-ut-nemo/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

**CMD_INJECTION**

```text
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-content/plugins/user-registration/assets/js/jquery-tiptip/jquery.tipTip.min.js?ver=1.3.0%26sleep+15%26 HTTP/1.1" 200 2744 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-includes/js/mediaelement/mediaelementplayer-legacy.min.css?ver=4.2.6-78496d1%22%3Bsleep+15%3B%22 HTTP/1.1" 200 11232 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-login.php?_wpnonce=7de0abcdc2&action=logout%27%26sleep+15%26%27&redirect_to=http%3A%2F%2Ftest-site.com%2Fblog%2Fregistration HTTP/1.1" 200 3223 "http://test-site.com/blog/index.php/registration/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

**WEB_SCANNING**

```text
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/wp-admin/images/browser.backup HTTP/1.1" 404 276 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/author/tomas/.htaccess HTTP/1.1" 404 58226 "http://test-site.com/blog/index.php/2020/04/04/voluptatum-reprehenderit-maiores-ab-sequi-quaerat/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "MKCOL /blog/index.php/2020/04/04/hic-porro-nihil-non-rerum/feed/ HTTP/1.1" 200 838 "http://test-site.com/blog/index.php/2020/04/04/hic-porro-nihil-non-rerum/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
```

**NORMAL**

```text
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/xmlrpc.php HTTP/1.1" 405 42 "-" "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MAGWJS; rv:11.0) like Gecko"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog%22/index.php/wp-json/oembed/1.0/embed?format=xml&url=http%3A%2F%2Ftest-site.com%2Fblog%2Findex.php%2Fvitae-dolores-quidem-possimus-aut-voluptatibus%2F HTTP/1.1" 404 276 "http://test-site.com/blog/index.php/vitae-dolores-quidem-possimus-aut-voluptatibus/" "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
172.26.x.x - - [01/Jan/2020:00:00:00 +0000] "GET /blog/index.php/2020/04/04/hic-porro-nihil-non-rerum/feed/ HTTP/1.1" 200 454 "-" "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Mobile/11D257"
```

## 13. Berkas keluaran

| berkas | isi |
|---|---|
| data/processed/srbh_train.parquet, srbh_val.parquet, srbh_test.parquet | split 70/15/15 dengan semua kolom, termasuk metadata label, fitur sesi (analisis saja), row_id, dan timestamp_original |
| data/processed/test_sample_500.jsonl | sampel uji untuk semua metode: masukan `raw_log_masked` + kolom parsing, kolom evaluasi `label` dan `template_key`; tanpa raw_log asli, waktu, protokol, metadata label, dan fitur sesi; urutan acak |
| data/processed/srbh_excluded.parquet | baris yang dikeluarkan gerbang bukti dan batas templat, beserta alasannya |
| data/processed/label_mapping.yaml | salinan pemetaan yang dipakai + hitungan hasil run |
| reports/srbh_inspection.md | inspeksi dataset (Langkah 2) |

## 14. Keputusan atas butir terbuka

Keempat butir terbuka dari review sudah diputuskan penulis (2026-10-07) dan diterapkan di pipeline: (1) `sample_weak_sqli = exclude`; (2) dedup isi memakai `raw_log_masked` sebelum split; (3) metode hanya menerima `raw_log_masked` dan kolom parsing tanpa time/timestamp/protocol; (4) protokol diseragamkan HTTP/1.1 di `raw_log_masked`. Ditambah: bootstrap klaster 1.000× per `template_key`, dan pool few-shot hanya dari baris train yang isinya tidak muncul di srbh_test (`fewshot_eligible`).
