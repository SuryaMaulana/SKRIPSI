# Ringkasan sidang

**Deteksi dan Klasifikasi Serangan Aplikasi Web pada Log Akses Web Server Menggunakan Deep Agent LLM**
Muhammad Surya Maulana — S1 Sains Data, Universitas Negeri Surabaya

Sumber setiap angka: **[E]** `reports/evaluasi.md` (rerata 3 run untuk LLM tunggal dan deep agent; regex 1 run),
**[P]** `reports/evaluasi_per_run.json`, **[D]** `reports/data_report.md`, **[R]** `reports/catatan_rekayasa.md`. Angka
turunan ditulis bersama perhitungannya.

## Angka kunci

Sampel uji 500 baris: SQLI 89, XSS 56, PATH_TRAVERSAL 89, CMD_INJECTION 89, WEB_SCANNING 89, NORMAL 88 [D §6].

| metode | akurasi biner | FPR | akurasi 6 kelas | macro-F1 [IK 95%] | evidence literal | biaya / 1.000 baris | latensi median |
|---|---|---|---|---|---|---|---|
| regex (CRS PL1) | 0,704 | 0,000 | 0,698 | 0,717 [0,622; 0,779] | — | — | — |
| regex_full (post hoc) | 0,836 | 0,000 | 0,828 | 0,820 [0,752; 0,859] | — | — | — |
| LLM tunggal | 0,902 | 0,030 | 0,831 | 0,830 [0,752; 0,878] | 0,762 | $0,1314 | 1,27 s |
| deep agent | 0,837 | 0,042 | 0,747 | 0,750 [0,644; 0,814] | 0,897 | $1,6304 | 18,39 s |

Sumber: [E] Tabel 4.2, 4.3, 4.4, 4.5.

## Tiga klaim utama

1. **Regex: nol positif palsu, tetapi 36% serangan lolos.** FPR 0,000 dan precision 1,000, tetapi recall 0,641 [E Tabel
   4.2]: 148 dari 412 baris serangan diprediksi NORMAL (TP 264, FN 148 [P]; 148/412 = 35,9%). Paling lemah pada SQLI:
   F1 0,367, dengan 67 dari 89 baris SQLI diprediksi NORMAL [E F1 per kelas, confusion matrix regex].
2. **LLM tunggal: akurasi tertinggi.** Akurasi biner 0,902, akurasi 6 kelas 0,831, dan macro-F1 0,830, tertinggi di antara
   keempat metode; pesaing terdekat regex_full (post hoc) 0,836 / 0,828 / 0,820 [E Tabel 4.2, 4.3]. Biaya $0,1314 per
   1.000 baris, latensi median 1,27 s [E Tabel 4.4].
3. **Deep agent: bukti paling sahih, tetapi akurasi lebih rendah dan biaya 12×.** Evidence literal 0,897 vs 0,762 [E Tabel
   4.5]; akurasi 6 kelas 0,747 vs 0,831 dan macro-F1 0,750 vs 0,830 [E Tabel 4.3]; biaya $1,6304 vs $0,1314 per 1.000
   baris (1,6304/0,1314 = 12,4×), dengan 11,8 panggilan LLM dan 20.807 token masukan per baris [E Tabel 4.4].

## Sepuluh pertanyaan penguji yang paling mungkin

1. **Mengapa deep agent lebih rendah daripada LLM tunggal?** Selisih terbesar di WEB_SCANNING (F1 0,382 vs 0,590),
   PATH_TRAVERSAL (0,699 vs 0,850), dan CMD_INJECTION (0,772 vs 0,844) [E F1 per kelas]. Deep agent memprediksi NORMAL
   untuk 54,0 dari 89 baris WEB_SCANNING (LLM tunggal 39,3) dan 17,7 dari 89 baris PATH_TRAVERSAL (4,7), serta
   PATH_TRAVERSAL untuk 30,3 baris CMD_INJECTION (13,7) [E confusion matrix rerata]. Ditambah 5,7 PARSE_ERROR per run,
   seluruhnya pada baris yang keluarannya terpotong [E tabel keluaran degeneratif].
2. **Apakah selisih LLM tunggal vs deep agent bermakna?** IK 95% macro-F1 tumpang-tindih ([0,752; 0,878] vs
   [0,644; 0,814]) karena ketidakpastian tingkat templat besar (XSS hanya 6 templat, n efektif 2,8 [D §6]); rentang tiga
   run tidak bersinggungan (0,828–0,832 vs 0,745–0,753) [E Tabel 4.3]. Uji signifikansi formal tidak dilakukan.
3. **Mengapa regex tidak pernah salah alarm tetapi banyak serangan lolos?** FPR 0,000 [E Tabel 4.2], sedangkan SQLI hanya
   F1 0,367 [E F1 per kelas]. Varian regex_full (semua kategori CRS PL1, post hoc) menaikkan macro-F1 menjadi 0,820 lewat
   WEB_SCANNING (F1 0,994) dan CMD_INJECTION (0,983), tanpa memperbaiki SQLI (0,367) [E].
4. **Apakah ada kebocoran data antara train dan uji?** Deduplikasi isi dilakukan sebelum split: 0 dari 500 baris sampel
   punya kembaran di train [D §5]. Waktu dikonstankan karena menebak label mayoritas per menit saja mencapai akurasi 92,6%
   (macro-F1 0,92) [D §6].
5. **Mengapa hanya 500 baris, dan apakah mewakili?** Kuota per kelas 89/56/89/89/89/88; XSS diambil seluruhnya karena split
   uji hanya memuat 56 baris XSS [D §6]. Baris satu kelas banyak berasal dari templat yang sama (48% baris XSS dari satu
   templat [D §6]), sehingga IK dihitung dengan bootstrap klaster 1.000× yang meresampel templat [D §6; E Tabel 4.3].
6. **Seberapa stabil hasil LLM pada temperature 0?** Label berubah antar run pada 16 dari 500 baris (LLM tunggal) dan
   26 dari 500 baris (deep agent); rentang macro-F1 0,828–0,832 dan 0,745–0,753 [E]. Karena itu tabel utama memakai rerata
   3 run.
7. **Apa arti "evidence literal", dan mengapa deep agent unggul?** Proporsi item evidence yang ada harfiah di baris log
   (mentah atau terdekode): 0,897 vs 0,762 [E Tabel 4.5]. Verifikasi deterministik menolak evidence yang tidak literal dan
   mengembalikan baris ke Klasifikasi; 68,7 baris per run tetap berstatus verification_failed [E].
8. **Berapa biaya dan waktu deep agent?** Per baris: 11,8 panggilan LLM, 15,4 pemanggilan alat, 20.807 token masukan dan
   1.322 token keluaran; latensi median 18,39 s (p95 41,34 s); $1,6304 per 1.000 baris [E Tabel 4.4].
9. **Apa itu keluaran degeneratif, dan bagaimana ditangani?** Panggilan yang terpotong di batas max_tokens 4.096: rata-rata
   24,0 kejadian di 18,0 baris per run deep agent dan 0 pada LLM tunggal; outcome baris terdampak ok 10,7,
   verification_failed 1,7, PARSE_ERROR 5,7 [E tabel keluaran degeneratif]. Batas dipasang setelah run tanpa batas
   memperlihatkan keluaran sampai batas model 32.768 token [R §5].
10. **Apakah orkestrator selalu mengikuti prosedur empat sub-agen?** Tidak selalu: delegasi ke keempat sub-agen terjadi pada
    468,7 dari 500 baris per run (rentang 465–475) [E].
