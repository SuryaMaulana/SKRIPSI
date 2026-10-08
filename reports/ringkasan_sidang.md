# Ringkasan sidang

**Deteksi dan Klasifikasi Serangan Aplikasi Web pada Log Akses Web Server Menggunakan Deep Agent LLM**
Muhammad Surya Maulana — S1 Sains Data, Universitas Negeri Surabaya

Sumber angka: **[E]** `reports/evaluasi.md` (LLM tunggal dan deep agent: rerata 3 run), **[J]**
`reports/evaluasi.json`, **[P]** `reports/evaluasi_per_run.json`, **[D]** `reports/data_report.md`, **[L]**
`reports/label_mapping_proposal.md`, **[R]** `reports/catatan_rekayasa.md`.

## Angka kunci

Sampel uji 500 baris: SQLI 89, XSS 56, PATH_TRAVERSAL 89, CMD_INJECTION 89, WEB_SCANNING 89, NORMAL 88 [D §6].

| metode | akurasi biner | FPR | akurasi 6 kelas | macro-F1 [IK 95%] | evidence literal | biaya / 1.000 baris | latensi median per baris |
|---|---|---|---|---|---|---|---|
| regex (utama) | 0,704 | 0,000 | 0,698 | 0,717 [0,622; 0,779] | — | — | — |
| regex_full (post hoc) | 0,836 | 0,000 | 0,828 | 0,820 [0,752; 0,859] | — | — | — |
| LLM tunggal | 0,902 | 0,030 | 0,831 | 0,830 [0,752; 0,878] | 0,762 | $0,1314 | 1,27 s |
| deep agent | 0,837 | 0,042 | 0,747 | 0,750 [0,644; 0,814] | 0,897 | $1,6304 | 18,39 s |

Sumber: [E] Tabel 4.2–4.5.

## Tiga klaim utama

1. **Regex: nol positif palsu, tetapi 36% serangan lolos.** FPR 0,000, recall 0,641 [E Tabel 4.2]: 148 dari 412 baris
   serangan diprediksi NORMAL, yaitu 35,9% (412 = 500 − 88 NORMAL [D §6] = TP 264 + FN 148 [P]). Terlemah di SQLI,
   F1 0,367 [E].
2. **LLM tunggal: akurasi tertinggi** pada akurasi biner (0,902; berikutnya deep agent 0,837), akurasi 6 kelas (0,831;
   regex_full 0,828), dan macro-F1 (0,830; regex_full 0,820) [E Tabel 4.2, 4.3].
3. **Deep agent: bukti paling sahih, tetapi akurasi lebih rendah dan biaya 12×.** Evidence literal 0,897 vs 0,762,
   macro-F1 0,750 vs 0,830, biaya per 1.000 baris 1,6304/0,1314 = 12,4× [E Tabel 4.3–4.5].

## Pertanyaan penguji

1. **Mengapa deep agent lebih rendah?** Selisih F1 terbesar di WEB_SCANNING (0,382 vs 0,590) dan PATH_TRAVERSAL (0,699
   vs 0,850). Deep agent memberi NORMAL pada 54,0 dari 89 baris WEB_SCANNING (LLM tunggal 39,3) dan 17,7 baris
   PATH_TRAVERSAL (4,7), serta PATH_TRAVERSAL pada 30,3 baris CMD_INJECTION (13,7); ditambah 5,7 prediksi tidak valid
   per run [E].
2. **Apakah selisihnya bermakna?** Rentang tiga run tidak bersinggungan (macro-F1 0,828–0,832 vs 0,745–0,753), tetapi
   IK 95% tumpang-tindih karena ketidakpastian tingkat templat besar (XSS: 6 templat, n efektif 2,8) [E Tabel 4.3;
   D §6]. Uji signifikansi formal tidak dilakukan.
3. **Mengapa regex tanpa salah alarm?** Label SR-BH adalah keluaran CRS dan gerbang data membersihkan NORMAL dari pola
   payload/probe, sehingga pembanding turunan CRS diuntungkan [D §3]. regex_full menaikkan macro-F1 ke 0,820 lewat
   WEB_SCANNING dan CMD_INJECTION, tetapi SQLI tetap 0,367 [E].
4. **Ada kebocoran train–uji?** Dedup isi sebelum split; 0 dari 500 baris sampel punya kembaran di train
   [D §5]. Waktu dikonstankan karena tebakan label mayoritas per menit saja mencapai akurasi 92,6% [D §6].
5. **Apakah 500 baris mewakili?** XSS diambil seluruhnya (split uji hanya memuat 56). Baris sekelas sering berasal dari
   templat yang sama (48% baris XSS dari satu templat), sehingga IK memakai bootstrap klaster 1.000× atas templat [D §6].
6. **Stabil pada temperature 0?** Label berubah antar run pada 16/500 baris (LLM tunggal) dan 26/500 (deep agent) [E].
   Dua run C pada 30 baris yang sama sudah berbeda label di 1/30 baris [R §2]; karena itu dipakai 3 run dan reratanya.
7. **Apa itu evidence literal?** Proporsi item evidence yang ada harfiah di `raw_log_masked`, mentah atau hasil decode
   (`reports/evaluasi_per_run.md`). Deep agent unggul karena Verifikasi deterministik menolak evidence non-literal
   (68,7 baris per run tetap verification_failed [E]) dan prompt Klasifikasinya meminta evidence ditulis persis seperti
   di log (K3) [R §3].
8. **Biaya dan waktu deep agent?** Per baris 11,8 panggilan LLM, 20.807 token masukan, dan latensi median 18,39 s
   (p95 41,34 s) [E Tabel 4.4]; 15,4 pemanggilan alat [E, baris ringkasan agent].
9. **Apa itu keluaran degeneratif?** Panggilan yang terpotong di `max_tokens` 4.096. Batas ini dipasang setelah run tanpa
   batas menghasilkan keluaran sampai batas model 32.768 token [R §5]. Deep agent mengalami 24,0 kejadian per run di
   18,0 baris; dari baris itu, 10,7 tetap ok dan 5,7 berakhir PARSE_ERROR. LLM tunggal: 0 [E].
10. **Apakah orkestrator selalu mengikuti prosedur?** Tidak: delegasi ke keempat sub-agen terjadi pada 468,7 dari 500
    baris per run (465–475) [E].
11. **Mengapa gpt-4.1-nano, dan apakah berlaku untuk model besar?** Model ditetapkan penulis dan dipakai identik oleh LLM
    tunggal dan deep agent: `openai/gpt-4.1-nano` (versi 2025-04-14), temperature 0, seed 42 [J], pada 500 baris yang
    sama. Karena itu selisih antarmetode sahih untuk model ini. Apakah kesimpulannya berlaku untuk model yang lebih besar
    belum diuji; itu saran penelitian lanjutan.
12. **Apa bedanya deep agent dengan pipeline biasa?** Pada pipeline, urutan Parser → Analisis Payload → Klasifikasi →
    Verifikasi tetap di kode. Pada deep agent, orkestrator LLM sendiri yang memutuskan sub-agen mana yang dipanggil dan
    kapan, sehingga prosedurnya tidak selalu lengkap: delegasi ke keempat sub-agen terjadi pada 468,7 dari 500 baris per
    run, dan 31,3 baris (500 − 468,7) tidak [E].
13. **Mengapa label CAPEC tidak dipetakan langsung, dan berapa yang dikeluarkan?** Pada pemetaan langsung per nama CAPEC,
    hanya 1,3% baris "XSS" dan 41,3% baris CMD_INJECTION yang lolos gerbang bukti dengan kelas yang sama [L §3]. Karena
    itu kelas akhir harus berasal dari label baris itu sendiri dan buktinya terlihat di field log [D §3]. Dikeluarkan
    216.047 dari 907.815 baris [D §2], masing-masing dengan kode alasan: LABELER_BLIND 71.431, OUT_OF_SCOPE 38.022,
    SCANNER_PROBE 29.984, LABEL_MISMATCH 27.097, INSPECTED_VISIBLE_PAYLOAD 17.378, HIDDEN_EVIDENCE 15.099,
    RFI_SCHEMELESS 12.262, NO_EVIDENCE 4.772, EMPTY_ROW 2 [D §3].
14. **Mengapa tidak ada XSS di label asli, dan dari mana 56 baris XSS?** SR-BH 2020 punya 1 label Normal dan 13 label
    CAPEC, tanpa label XSS (CAPEC-63) [L, Ringkasan]. Payload XSS ada di bawah label 242 (Code Injection): dari 15.827
    baris berlabel 242, 378 memuat payload XSS yang terlihat di log (aturan gerbang K1), sedangkan sebagian besar
    sisanya injeksi kode di luar taksonomi (OUT_OF_SCOPE 13.742) [D §3]. Setelah dedup dan split, split uji memuat 56
    baris XSS [D §5], dan sampel mengambil seluruhnya [D §6].
15. **Bagaimana prompt injection lewat baris log ditangani?** Baris log dikirim di dalam `<log>...</log>` dengan aturan
    bahwa isinya data, bukan instruksi, dan Verifikasi E hanya menerima evidence yang ada harfiah di log. Di log
    panggilan run resmi tidak ada kejadian: 0 dari 500 baris sampel memuat teks berpola instruksi, dan 0 dari 1.500
    respons C serta 17.739 respons E memuat penolakan atau frasa meta [R §8]. Sampel tidak memuat percobaan prompt
    injection, jadi ketahanannya belum teruji (keterbatasan).
16. **Mengapa validasi di log Indonesia tidak dilakukan?** Label YAML dataset log Indonesia belum diaudit, sehingga hasil
    di sana belum dapat dinilai sahih. Validasi eksternal ini dicatat sebagai keterbatasan dan saran penelitian lanjutan.
17. **Apa kontribusi penelitian ini?** (1) Gerbang bukti dan dataset 6 kelas yang dapat direproduksi: 907.815 baris
    SR-BH 2020 menjadi 272.107 baris dalam split (190.474 / 40.816 / 40.817) dan sampel uji 500 baris, dengan setiap
    eksklusi berkode alasan [D §2, §3]. (2) Perbandingan terkendali regex, LLM tunggal, dan deep agent pada model dan
    baris yang sama [E; J]. (3) Metrik evidence literal untuk kesahihan bukti: 0,897 vs 0,762 [E Tabel 4.5]. (4) Temuan
    bahwa arsitektur agen tidak menaikkan akurasi pada klasifikasi per baris: macro-F1 0,750 vs 0,830 [E Tabel 4.3].
