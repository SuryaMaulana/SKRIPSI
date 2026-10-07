# Temuan pilot deep agent (30 baris) — terverifikasi

Run `agent-20261007T164716Z-725069c` (commit 725069c, bersih). Angka per baris: `reports/pilot_agent.md`. Setiap temuan
di bawah diperiksa ulang secara adversarial oleh agen independen langsung pada `results/agent_calls.jsonl` dan
`results/pilot/agent.jsonl` (rincian lengkap: `reports/pilot_agent_verifikasi.json`). Baris pilot adalah bagian dari
sampel uji: temuan ini dicatat untuk keputusan penulis, bukan untuk menyetel agen pada data uji.

## Hasil utama

- Benar: C 23/30, E 19/30 (macro-F1 pada 30 baris 0,747 vs 0,624). E tidak pernah benar di baris yang salah menurut C;
  E salah di 4 baris yang benar menurut C (3 PARSE_ERROR + `srbh-fae0e1ba315fa2c1` MKCOL -> NORMAL).
- Biaya/latensi: E rata-rata 18,8 panggilan LLM dan 55.618 token masukan per baris (C: 1 panggilan, 948 token);
  latensi median 28,2 s vs 1,7 s; biaya 30 baris $0,0834 vs $0,0039 (±21x).

## 1. Orkestrator menyimpang ke alat berkas virtual deepagents (penyebab semua PARSE_ERROR) — terkonfirmasi

- Ketiga PARSE_ERROR (`srbh-01b00fcbf8064bef`, `srbh-8002b48db2cdb197`, `srbh-a7c36c09bcd7bf3b`) tidak pernah memanggil
  sub-agen apa pun (0 panggilan task). Orkestrator memakai ls/read_file/write_file/edit_file/glob/grep:
  - 01b00f: menyalin log ke /tmp/log.txt lalu grep 16x berputar pada 3 pola sampai batas rekursi 80 langkah;
  - 8002b4 dan a7c36c: mencari "berkas log" di sistem berkas, lalu berhenti dan meminta pengguna menempelkan log;
    4 pengingat prosedur disisipkan dan diabaikan semuanya.
- Alat berkas dipakai orkestrator di 9/30 baris (70 panggilan); sub-agen tidak pernah memakainya. Baris yang memakai
  alat berkas lebih sering gagal (status bukan ok 8/9 vs 8/21), terutama karena 3 baris PARSE_ERROR.
- Ketiga baris PARSE_ERROR adalah satu-satunya baris pilot dengan payload injeksi di User-Agent (XSS 2x, Shellshock 1x);
  C dengan model yang sama mengklasifikasi ketiganya benar. Pemicu pastinya belum terbukti (n=3).

## 2. Penilaian LLM verifikator tidak andal ke dua arah — terkonfirmasi

- 4 penolakan murni oleh penilaian LLM (skema valid, semua evidence literal): keempatnya salah tolak (label = label benar),
  mis. `srbh-08bedb024d7ae9ea` XSS ter-encode ganda ditolak dua kali karena "masih ter-encode", ditambah alasan karangan
  bahwa schema_check gagal (semua 64 panggilan schema_check menjawab valid).
- Sebaliknya 14 putusan di 9 baris: LLM meloloskan evidence non-literal, 13 di antaranya setelah evidence_exists miliknya
  sendiri menjawab ada:false; 4 di antaranya menyetujui label salah (NORMAL untuk MKCOL/TRACK/UNLOCK). Yang menolak hanya
  pemeriksaan deterministik.
- Lain-lain: 1x verifikator berputar memanggil alat sampai batas 15 panggilan tanpa putusan (`srbh-b90bd4ea89d4b716`);
  2x keluaran Verdict ganda; 4x argumen evidence_exists bukan item evidence.

## 3. Evidence non-literal berasal dari format masukan berbasis alat — terkonfirmasi

- 39 dari 78 item evidence E non-literal: awalan nama kolom ("path: /blog/...") 18, salinan keluaran alat (pesan aturan
  CRS seperti "Method is not allowed by policy", kunci scanner_indicators, nilai `cocok` CRS yang sudah di-lowercase) 15,
  kalimat deskriptif 5, lain-lain 1; 28 dari 39 pada prediksi NORMAL.
- Semua 25 penolakan deterministik karena evidence tidak ditemukan (0 karena skema). C pada 30 baris yang sama tidak
  pernah menghasilkan jenis awalan kolom atau salinan keluaran alat (masukan C hanya baris log).
- Umpan balik verifikasi jarang memperbaiki evidence: 9 dari 14 baris mengulang item yang sudah ditandai hilang; 4 baris
  justru membuang item literal (mis. 'MKCOL', 'UNLOCK').

## 4. Putaran verifikasi ke-2 hampir tidak mengubah label — terkonfirmasi

- 16 baris menjalani 2 putaran; label berubah di 1 baris (`srbh-e96613aeb264209a` NORMAL -> PATH_TRAVERSAL, salah ke
  salah). Tanpa putaran 2: akurasi tetap 19/30, macro-F1 0,625 vs 0,624.
- Putaran 2 memakan 95 panggilan LLM, 266.905 token, $0,0135 (16,1% biaya) dan 17% waktu. 9 dari 16 penolakan putaran 1
  memang tidak mempersoalkan label (hanya evidence).

## 5. Pola lain (klaim "tidak ada mode lain" terbantah)

- Kebingungan label sistematis menjelaskan 6 dari 11 kesalahan E: CMD_INJECTION -> PATH_TRAVERSAL 3x (payload
  `|cat /etc/passwd`, `&cat /etc/passwd&`; pattern_match juga melaporkan 932160 attack-rce) dan WEB_SCANNING -> NORMAL 3x
  (MKCOL, TRACK, UNLOCK; metode non-standar terlapor alat). Pola yang sama ada di C (CMD->PATH_TRAVERSAL 13,
  WEB_SCANNING->NORMAL 37 pada 500 baris).
- Status verifikasi tidak menandakan kebenaran: akurasi baris ok 9/14, baris verification_failed 10/13.
- Orkestrator mencoba berhenti dini 10x di 8 baris (semua patuh setelah pengingat), 3x mengklasifikasi sendiri (diabaikan
  karena label diambil dari sub-agen Klasifikasi); 9 pemanggilan sub-agen di luar urutan ditahan guard; pesan akhir
  orkestrator bukan salinan JSON di 20/27 baris (2 bertentangan dengan hasil; tidak memengaruhi metrik).
- Kepatuhan sub-agen: Parser menulis prosa (22/26) dan 3x menilai serangan; analisis_payload melewatkan scanner_indicators
  di 4/27 baris; 18/53 deskripsi tugas tidak menyertakan baris log (alat tetap membaca log asli dari konteks).
- write_todos hanya dipakai di 1/30 baris: prompt sistem orkestrator yang terkirim memuat blok bawaan deepagents yang
  menyarankan tidak memakai write_todos untuk tugas sederhana (bertentangan dengan langkah 1). agent.run.json mencatat
  prompt tulisan penulis; prompt yang benar-benar terkirim tercatat di agent_calls.jsonl (jenis "prompt_sistem").
- Tidak ditemukan: galat API, galat alat, keluaran degeneratif (finish_reason length), explanation non-Indonesia, salah
  atribusi sub-agen.
