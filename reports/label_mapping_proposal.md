# Usulan Pemetaan Label CAPEC → 6 Kelas (Langkah 3)

**Status: DISETUJUI 2026-10-07** dengan keputusan: K1 ya (pola gerbang bukti tidak sama dengan regex pembanding §3.5;
jumlah dikeluarkan dilaporkan per label), K2 a, K3 **b** (XSS hanya dari label; kuota XSS ±57; aturan split sama untuk
semua kelas), D4–D9 sesuai default, ditambah batas maksimal 200 baris per templat payload untuk label 194 setelah dedup.
Opsi K3 (a) dan (c) di bawah tidak dipakai. **Koreksi:** penjelasan bahwa permintaan ber-`%2F` "ditolak Apache sebelum diperiksa WAF" dicabut karena dibantah data (56.729 dari 125.868 permintaan ber-`%2F` berlabel serangan); yang teramati hanyalah semua dijawab 404 dan pelabelannya tidak konsisten. Aturan LABELER_BLIND tidak berubah. Dokumen ini dipertahankan sebagai catatan usulan; angka akhir hasil pipeline
ada di `reports/data_report.md`, dan pemetaan yang dipakai ada di `configs/label_mapping.yaml`.

## Ringkasan

1. SR-BH 2020 memiliki 1 label Normal + 13 label CAPEC. **Tidak ada label XSS (CAPEC-63)** dan tidak ada CAPEC-193.
2. Label SR-BH adalah keluaran aturan ModSecurity CRS (lalu ditinjau penulis dataset) atas **seluruh** permintaan HTTP:
   body, cookie, dan semua header. Penelitian ini hanya melihat **baris log akses** (Combined Log Format). Akibatnya,
   banyak label tidak bisa diamati dari log, dan sebagian label NORMAL tidak informatif.
3. Usulan: **gerbang bukti dua kunci**. Kelas akhir harus (1) berasal dari label SR-BH baris itu sendiri, dan
   (2) buktinya terlihat di field log akses (method, URI, User-Agent, Referer). Baris yang gagal → `EXCLUDED`
   dengan kode alasan, disimpan terpisah, tidak dibuang.
4. **Urutan prioritas penulis dipertahankan** (CMD_INJECTION > SQLI > XSS > PATH_TRAVERSAL > WEB_SCANNING).
   Di bawah gerbang bukti, urutan ini hanya menentukan 962 baris dan hasilnya identik dengan alternatif yang dikaji.
5. Hasil usulan: SQLI 215.963 · PATH_TRAVERSAL 54.260 · WEB_SCANNING 11.678 · CMD_INJECTION 3.089 · **XSS 378** ·
   NORMAL 406.400 · EXCLUDED 216.047. XSS tidak cukup untuk ±83 baris uji pada split 15%, sehingga perlu keputusan K3.

## 1. Temuan yang mendasari usulan

Kolom "verifikasi": **CSV** = saya hitung ulang langsung dari CSV mentah dengan kode sendiri; **peninjau** = dikonfirmasi
oleh peninjau adversarial (lensa data) dalam analisis bukti, belum saya hitung ulang sendiri.

| # | Temuan | Angka kunci | Verifikasi |
|---|---|---|---|
| 1 | Permintaan dengan `%2F` di path semuanya dijawab 404 dan dilabeli tidak konsisten, sehingga label NORMAL-nya tidak andal. ~~Ditolak Apache sebelum diperiksa WAF~~ (dicabut: 56.729 baris ber-`%2F` justru berlabel serangan) | 125.868 baris ber-`%2F`, 100% status 404 (125.707 berukuran 276 byte); 69.139 berlabel NORMAL. `<script>` di path tanpa `%2F`: 124/124 berlabel serangan; dengan `%2F`: 2.335/2.385 berlabel NORMAL | CSV |
| 2 | Label 242 (Code Injection) hampir seluruhnya **bukan** XSS | 15.827 baris: PHP `print(chr(..))` bertanda `zap_token` 79,6%, EL `${a+b}` 10,0%, PHP-CGI 3,4%, SSI 2,5%, **XSS 3,2%** (507; 378 terlihat di log) | CSV (XSS 378, EL 1.586); sisanya peninjau |
| 3 | Label mengikuti aturan CRS mana yang menyala, bukan jenis serangannya | Probe perintah OS ZAP berlabel 66 pada 22.117 baris (tanpa sintaks SQL); `cat /etc/passwd` di path ada di 26.121 baris: 22.564 NORMAL, 0 berlabel 126/88 | CSV (path); peninjau (66) |
| 4 | Banyak label serangan tanpa bukti di baris log | 88: 50,7% payload hanya di body/header; 153: menandai header Content-Type tak valid (2.222 berisi payload pemindai, 50 kosong), tidak tercatat di log; 16: kredensial di body | CSV (153); peninjau |
| 5 | Label 194 "Fake the Source of Data" ternyata probe RFI OWASP ZAP | 55.033/56.145 (98,0%) baris memuat templat `www.google.com`; 37.830 dengan skema `http(s)://` di path/query | CSV |
| 6 | Label 274 identik dengan aturan metode | Metode bukan GET/POST/HEAD/OPTIONS/TRACE ⇔ label 274, cocok di 907.815/907.815 baris | CSV |
| 7 | Label 272 menandai keluarga aturan CRS-920, bukan satu jenis serangan | 39,7% baris 272 tanpa pemicu apa pun di 24 field | peninjau |
| 8 | Label 34/33: injeksi CRLF dan efek samping CRS-921; tidak ada request smuggling | 34 identik dengan aturan "CR/LF di lokasi tertentu" (19.738/19.738) | peninjau |
| 9 | Komposisi NORMAL: ~70% generator lalu lintas sintetis; ~30% lalu lintas alat serang di jendela pemindaian 17–19 Juli | Semua 279.856 baris bertanggal 29 Juli (53% NORMAL) adalah `GET /` berlabel NORMAL | CSV (29 Juli); peninjau |

## 2. Tabel pemetaan usulan

Kolom "hasil" menunjukkan ke mana baris-baris berlabel itu berakhir pada Varian B (satu baris multi-label muncul di
beberapa label).

| Label | Baris | Usulan | Hasil (Varian B) |
|---|---:|---|---|
| 000 Normal | 525.195 | NORMAL, kecuali baris yang labelnya tak informatif (K2) | NORMAL 406.400 · EXCLUDED 118.795 (LABELER_BLIND 71.431, SCANNER_PROBE 29.984, INSPECTED_VISIBLE_PAYLOAD 17.378, EMPTY_ROW 2) |
| 66 SQL Injection | 250.311 | SQLI bila sintaks SQL terlihat | SQLI 215.963 (28.625 bertanda bukti lemah) · XSS 203 · CMD 170 · WS 5 · PT 1 · EXCLUDED 33.969 |
| 242 Code Injection | 15.827 | XSS hanya bila payload XSS terlihat (K3) | XSS 378 · CMD 683 (lewat 88) · WS 1 · EXCLUDED 14.765 |
| 88 OS Command Injection | 7.482 | CMD bila perintah shell terlihat | CMD 3.089 · PT 344 (lewat 126) · WS 1 · EXCLUDED 4.048 |
| 248 Command Injection | 1 | UNMAPPED (kategori induk) | WS 1 (lewat 310) |
| 126 Path Traversal | 20.992 | PT; probe berkas VCS/backup tanpa traversal → WS (D7) | PT 16.430 · CMD 935 · WS 1.356 · EXCLUDED 2.271 |
| 310 Scanning for Vulnerable Software | 2.718 | WS | WS 2.691 · PT 23 · SQLI 2 · XSS 2 |
| 194 Fake the Source of Data | 56.145 | PT (File Inclusion) bila templat RFI ber-skema `http(s)://` (D6) | PT 37.830 · EXCLUDED 18.315 |
| 34 HTTP Response Splitting | 19.738 | UNMAPPED (CRLF di luar 6 kelas) | EXCLUDED 19.738 |
| 33 HTTP Request Smuggling | 1.059 | UNMAPPED (efek samping CRS-921) | CMD 513 (lewat 88) · EXCLUDED 546 |
| 272 Protocol Manipulation | 9.153 | WS hanya bila probe penemuan terlihat (D7) | WS 4.106 · SQLI 124 · CMD 26 · PT 23 · EXCLUDED 4.874 |
| 274 HTTP Verb Tampering | 5.437 | WS (enumerasi metode) (D7) | WS 5.437 |
| 16 Dictionary-based Password Attack | 1.847 | UNMAPPED (formulir login; kredensial di body) | SQLI 144 · PT 10 · WS 9 · CMD 4 · XSS 2 · EXCLUDED 1.678 |
| 153 Input Data Manipulation | 2.272 | UNMAPPED (payload di header Content-Type) | WS 1 (lewat 310) · EXCLUDED 2.271 |

**Label yang tidak masuk 6 kelas** (dicatat eksplisit, bukan dibuang diam-diam): 248, 34, 33, 16, 153. Label ini tidak pernah
menentukan kelas; baris yang hanya membawa label-label ini menjadi `EXCLUDED` dengan kode alasan dan dihitung di laporan.

**Aturan multi-label:** prioritas `CMD_INJECTION > SQLI > XSS > PATH_TRAVERSAL > WEB_SCANNING` diterapkan **setelah**
gerbang bukti. Hanya 962 baris yang punya >1 kandidat kelas: 935 `<pemisah>cat /etc/passwd` (CMD vs PT → CMD), 23
traversal dari Nmap (PT vs WS → PT), 2 SQLI vs WS, 2 XSS vs WS. Tidak ada baris dengan kandidat XSS dan SQLI sekaligus.

## 3. Distribusi kelas

Baris log unik = setelah membuang duplikat persis (stempel waktu + request line + status + byte + referer + UA).
"±uji" = perkiraan baris log pada split uji 15%.

| Kelas | A: pemetaan langsung per nama CAPEC | B: usulan (gerbang bukti) | B + opsi XSS (K3a) |
|---|---|---|---|
| SQLI | 249.919 (244.944 unik) | 215.963 (214.270 unik) · ±uji 32.140 | sama dengan B |
| XSS | 13.838 (13.803 unik) | **378 (377 unik) · ±uji 57** | 2.849 (2.807 unik) · ±uji 421 |
| PATH_TRAVERSAL | 18.047 (17.670 unik) | 54.260 (54.206 unik) · ±uji 8.131 | sama dengan B |
| CMD_INJECTION | 7.483 (5.230 unik) | 3.089 (3.048 unik) · ±uji 457 | sama dengan B |
| WEB_SCANNING | 2.667 (2.661 unik) | 11.678 (11.433 unik) · ±uji 1.715 | sama dengan B |
| NORMAL | 525.195 (510.869 unik) | 406.400 (394.177 unik) · ±uji 59.127 | sama dengan B |
| EXCLUDED | 90.666 | 216.047 | 213.576 |
| Baris log identik berlabel >1 kelas | 318 | 0 | 0 |

Varian A = 66→SQLI, 242→XSS, 88/248→CMD, 126→PT, 310→WS, label lain UNMAPPED, prioritas penulis, tanpa gerbang.
Berapa persen baris tiap kelas Varian A yang lolos gerbang bukti dengan kelas yang sama:

| Kelas Varian A | Lolos gerbang, kelas sama | Dikeluarkan | Pindah kelas |
|---|---:|---:|---:|
| SQLI | 86,4% | 13,5% | 0,1% |
| XSS | **1,3%** | 98,7% | 0,0% |
| PATH_TRAVERSAL | 89,1% | 3,4% | 7,5% |
| CMD_INJECTION | **41,3%** | 54,1% | 4,6% |
| WEB_SCANNING | 100,0% | 0,0% | 0,0% |
| NORMAL | 77,4% | **22,6%** | – |

## 4. Keputusan yang perlu disetujui

### Keputusan utama

**K1 — Aturan kebenaran dasar.**
(a) *Gerbang bukti dua kunci* — **rekomendasi**: sesuai Batasan 1.5 draf ("serangan yang tidak tampak pada baris log
tidak dicakup") dan tidak membuat label baru.
(b) Label saja (Varian A): sederhana, tetapi ~54% baris CMD dan hampir semua "XSS" tidak bisa dilihat atau salah kelas.
(c) Label ulang seluruhnya berdasarkan isi payload: kebenaran dasar menjadi buatan regex, sehingga sirkular dengan baseline regex.

**K2 — Baris NORMAL yang bermasalah (118.793).**
(a) Keluarkan dengan kode alasan dan laporkan terpisah — **rekomendasi**.
(b) Keluarkan hanya LABELER_BLIND (`%2F`/TRACE, 71.431; aturan tanpa melihat isi). Masih tersisa ~47 ribu baris
payload/probe pemindai di NORMAL (~10%).
(c) Biarkan sebagai NORMAL. ~22,6% baris NORMAL uji akan berisi serangan, dan detektor yang benar dihukum sebagai false positive.

**K3 — Sumber kelas XSS.** Label XSS terbukti hanya 378 baris (377 unik, ±57 di split uji 15%), di bawah target ±83.
(a) *Override templat*: tambah 2.471 baris ber-`%2F` (berlabel NORMAL/66, yang labelnya tidak andal; lihat temuan #1)
yang cocok dengan 10 templat XSS yang diverifikasi manual. XSS menjadi 2.849 baris, dan semuanya ditandai
`label_source=override`. Kelemahan: 87% kelas XSS lahir dari pencocokan templat (sirkular dengan baseline regex),
dan kebijakannya asimetris (kelas lain tidak di-override).
(b) XSS hanya dari label (378) dan kuota XSS di sampel 500 diturunkan menjadi seluruh XSS uji (±57); kelas lain
mengisi sisanya. Paling bersih, tetapi menyimpang dari "±83 per kelas".
(c) XSS hanya dari label (378), tetapi porsi split khusus XSS digeser (misalnya 55/15/30) agar sampel uji tetap bisa
83 — **rekomendasi**. Label tetap murni. Porsi latih XSS hanya dipakai untuk contoh few-shot dan penyetelan regex,
jadi tidak perlu 70%. Penyimpangan dari 70/15/15 berlaku khusus untuk kelas XSS dan dicatat di laporan.
(d) Tambah data XSS dari dataset lain: keluar dari SR-BH, sehingga perlu justifikasi tambahan.

### Keputusan turunan (default usulan dipakai kecuali Anda keberatan)

| Kode | Pertanyaan | Default usulan |
|---|---|---|
| D4 | Payload terlihat yang bertentangan dengan label (mis. 22.117 baris 66 berisi probe perintah OS, 4.624 baris 34 berisi perintah ber-newline) | Keluarkan sebagai LABEL_MISMATCH. Bila dilabel ulang, 89,6% kelas CMD akan lahir dari 2 templat ZAP |
| D5 | PHP-CGI CVE-2012-1823 (`?-d allow_url_include=1 -d auto_prepend_file=php://input`) | CMD_INJECTION untuk 513 baris berlabel 88; 25 baris tanpa 88 dikeluarkan |
| D6 | Label 194 (probe RFI ZAP) | PATH_TRAVERSAL untuk templat ber-skema `http(s)://` (37.830); tambahkan "URL eksternal di path/parameter" ke Tabel 2.1; batasi porsinya di sampel PT |
| D7 | Probe penemuan tanpa payload (274 sapuan metode, probe 272, berkas VCS/backup dari 126) | WEB_SCANNING. Tanpa ini, WEB_SCANNING hanya berisi satu sesi Nmap 30 menit |
| D8 | Probe di luar taksonomi (injeksi kode PHP/EL, CRLF, open redirect, XPath) | Dikeluarkan (OUT_OF_SCOPE); WEB_SCANNING tidak dijadikan kelas tampungan |
| D9 | 28.625 baris 66 yang buktinya hanya satu metakarakter (`'`, `"`, `(`, `)`, `;`, `NULL`) | Tetap SQLI dengan tanda `weak_evidence`; porsinya di sampel uji diputuskan di Langkah 9 |

## 5. Dampak untuk Langkah 4–9 (dicatat sekarang, diputuskan di titik berhenti berikutnya)

- **Satu IP untuk semua baris** (`172.26.0.1`, gateway Docker): fitur sesi per IP (Langkah 7) dan split per IP (Langkah 8)
  tidak dapat dilakukan seperti rencana. Alternatif yang akan saya usulkan: pengelompokan berdasarkan templat payload atau
  titik injeksi untuk serangan, dan berdasarkan baris log tanpa stempel waktu untuk NORMAL.
- **Stempel waktu membocorkan kelas.** Semua baris serangan (kecuali 1) berada pada 17–19 Juli dengan offset `+0200`,
  sedangkan 92,6% baris NORMAL unik ber-offset `+0100`. Offset perlu dinormalisasi saat rekonstruksi log, dan sampel
  NORMAL perlu distratifikasi per tanggal/sumber. Fitur jumlah permintaan per 60 detik juga akan membedakan kelas
  semata-mata karena jendela pemindaian.
- **Fitur jalan pintas di luar payload:** status 404 (1% NORMAL vs 92–95% SQLI/PT), halaman 404 276 byte, UA Firefox/70
  (6,5% NORMAL vs 93–97% serangan), `GET /` (75,6% NORMAL).
- **Konsentrasi templat:** PT 70% dari satu keluarga RFI (194); CMD 64% dari templat ZAP `cat`/`sleep`; WEB_SCANNING 46%
  dari satu sapuan metode. Sampel uji perlu batas per templat.
- **Rekonstruksi Combined Log Format:** pakai request line mentah (masih ter-encode, agar CR/LF tidak memecah baris);
  escape kutip dan backslash seperti Apache (±1.747 UA, 842 Referer, 178 UA dengan backslash); `-` untuk UA/Referer kosong
  dan byte nol; 2 baris kosong dibuang.
- **Byte NUL setelah decoding:** hasil URL-decode dapat memuat `\x00`. Operasi hash pandas (`unique`, `groupby`) salah
  menangani string ber-NUL. Normalisasi (Langkah 6) akan mengganti NUL dengan token terlihat; dedup memakai baris
  mentah (yang bebas NUL).
- **Sirkularitas:** label SR-BH berasal dari CRS, dan baseline regex diturunkan dari CRS, sehingga baseline diuntungkan
  sejak awal. NORMAL hasil gerbang hampir bebas pola regex (25 dari 406.400 baris memicu pola kuat, semuanya false
  positive `&dir=ltr`). Hal ini perlu dibahas di BAB IV.

## 6. Cara analisis dilakukan

- 12 analis paralel (satu per kelompok label, audit label Normal, pencarian sumber XSS, aturan multi-label), masing-masing
  diuji 2 peninjau adversarial (lensa data dan lensa metodologi), lalu 1 kritikus yang menyelesaikan 17 konflik antar-analis.
  Total 37 agen.
- Verifikasi independen dari CSV mentah dengan decoder sendiri: jumlah baris `%2F` dan statusnya, distribusi label di
  baris `%2F`, XSS terlihat per label, komposisi 242, templat RFI 194, serta offset/tanggal baris serangan. Semua cocok.
- Invarian: setiap kelas akhir berasal dari label baris itu sendiri (0 pelanggaran dari 907.815 baris). Urutan prioritas
  penulis memberi hasil identik dengan urutan alternatif (0 perbedaan).
- **Koreksi angka awal:** berkas indikator heuristik tahap awal mengandung bug (string ber-NUL membuat 2.082 baris
  "cocok semua pola"). Angka awal "4.931 baris mirip XSS, 4.151 berlabel NORMAL" salah; angka yang benar 2.849 dan 2.335.
- Setelah disetujui, aturan-aturan di YAML diimplementasikan di `src/data/` dengan unit test per aturan dan uji paritas
  terhadap angka `rows_expected`.
