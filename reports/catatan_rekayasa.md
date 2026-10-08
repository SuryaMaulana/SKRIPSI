# Catatan rekayasa — run yang tidak masuk tabel utama

Semua run di bawah dipindah ke `results/archive/` atas keputusan penulis (2026-10-08) dan **tidak dipakai di tabel
evaluasi utama** (`reports/evaluasi.md`, 3 run per metode dengan konfigurasi final ber-batas `max_tokens` 4.096). Catatan
ini mendokumentasikan riwayat rekayasa agar setiap keputusan dapat ditelusuri. Laporan lama yang dirujuk ada di
`reports/archive/`.

## 1. Daftar run arsip

| run_id | metode / konfigurasi | baris | tujuan | status | alasan tidak dipakai |
|---|---|---|---|---|---|
| `llm_single-20261007T153351Z-47b7a8d` | C pilot v1 (prompt awal) | 30 uji | cek format | selesai | prompt diperbarui (Tabel 2.1 final, aturan bahasa Indonesia) |
| `llm_single-20261007T161103Z-d03363c` | C pilot v2 | 30 uji | cek format | selesai | pilot |
| `llm_single-20261007T161203Z-6ce9f30` | C 500, tanpa batas token | 500 uji | run C pertama | selesai | konfigurasi final menambah `max_tokens` 4.096 |
| `agent-20261007T164625Z-2efbd87` | E v1 | 0 (1 baris berjalan) | pilot | dihentikan | tercatat dirty karena `make eval` paralel menulis laporan |
| `agent-20261007T164716Z-725069c` | E v1 (alat berkas deepagents, verifikator LLM) | 30 uji | pilot E | selesai | desain diubah (K1–K3) |
| `agent-20261007T174549Z-9ad710b` | E v2 sebelum perbaikan review | 15 val | validasi | dihentikan | race guard putaran, resume (review adversarial) |
| `agent-20261007T182502Z-38b109b` | E v2 | 16 val | validasi | dihentikan | masukan Klasifikasi memalsukan alat yang tidak dijalankan |
| `agent-20261007T185745Z-3988205` | E v2 final, tanpa batas token | 30 val | validasi K4 | selesai | konfigurasi final menambah `max_tokens` |
| `llm_single-20261007T201505Z-3988205` | C, tanpa batas token | 30 val | pembanding validasi | selesai | validasi |
| `agent-20261007T201758Z-e0daa05` | E v2, tanpa batas token | 82 uji | E 500 pertama | dihentikan (keputusan penulis) | konfigurasi final menambah `max_tokens`; disimpan untuk analisis keluaran degeneratif (`results/archive/agent_uncapped_partial.jsonl`) |
| `llm_single-20261007T214045Z-dc055cd` (3 run) | C ber-batas | 30 / 30 / 27 uji (r1/r2/r3) | run resmi | dihentikan | ketiga run paralel mendapat run_id sama; run_id kini memuat nama run (koreksi: pesan commit 9890bd0 menyebut ±15 baris) |
| `llm_single_r{1,2,3}-20261007T214206Z-9890bd0` | C ber-batas | 500 uji tiap run | run resmi | selesai, diganti | deteksi TRUNCATED diperluas (aturan bersama C/E: finish_reason length, alasan asli penyedia, atau token keluaran ≥ max_tokens); pada ketiga run ini aturan baru memberi hasil identik (4 panggilan TRUNCATED, semuanya finish_reason length), tetapi run diulang agar keenam run resmi memakai kode yang identik: C di `ed0941b`, E di `53ec4d2` (anak langsung `ed0941b` yang hanya menambah berkas hasil C) (`results/archive/c_9890bd0/`) |
| `agent_r{1,2,3}-20261007T215441Z-bcb3445` | E ber-batas | 52 / 55 / 52 uji | run resmi | dihentikan | review: Klasifikasi memakai chat.completions.parse() yang melempar LengthFinishReasonError pada keluaran terpotong (run akan crash), dan pemanggilan alat orkestrator yang terpotong dilaporkan OpenRouter sebagai finish_reason tool_calls sehingga TRUNCATED tidak terdeteksi (6 kejadian di ±160 baris) (`results/archive/dihentikan_e_bcb3445/`) |

## 2. C 500 baris tanpa batas token (`llm_single-20261007T161203Z-6ce9f30`)

Laporan lengkap: `reports/archive/evaluasi_c_tanpa_batas.md`.

| biner acc / P / R / F1 / FPR | 6 kelas acc | macro-F1 (IK 95%) | evidence literal | biaya | latensi median / p95 |
|---|---|---|---|---|---|
| 0,906 / 0,992 / 0,893 / 0,940 / 0,034 | 0,830 | 0,829 [0,751; 0,878] | 0,749 | $0,0917 | 1,69 / 3,00 s |

- 1 PARSE_ERROR (srbh-cf88bef37916a979): dua keluaran degeneratif (spasi sampai 32.768 token, finish_reason length),
  506 s, $0,0264 = 28,8% biaya run.
- Nondeterminisme: C pilot v2 vs C 500 pada 30 baris yang sama (prompt, temperature 0, dan seed sama) berbeda label di
  1/30 baris dan berbeda evidence di 9/30 baris. Temuan ini menjadi alasan replikasi 3 run per metode.

## 3. Pilot E v1 (`agent-20261007T164716Z-725069c`, 30 baris uji)

Laporan: `reports/archive/pilot_agent.md`, temuan terverifikasi: `reports/archive/pilot_agent_temuan.md` dan
`reports/archive/pilot_agent_verifikasi.json` (verifikasi adversarial independen).

- Benar 19/30 (C 23/30); macro-F1 30 baris 0,624 (C 0,747); evidence literal 0,636 (C 0,761); 18,8 panggilan LLM dan
  55.618 token masukan per baris; latensi median 28,2 s; ok 14 / verification_failed 13 / PARSE_ERROR 3.
- Penyebab yang terverifikasi dan keputusan penulis yang mengikutinya:
  - ketiga PARSE_ERROR: orkestrator memakai alat berkas virtual deepagents dan tidak pernah mendelegasikan -> **K1**
    (alat berkas dan execute dimatikan; orkestrator hanya task + write_todos);
  - penilaian LLM verifikator salah ke dua arah (4/4 penolakan murni-LLM salah; 14 kali meloloskan evidence yang
    menurut alatnya sendiri tidak ada) -> **K2** (Verifikasi deterministik tanpa LLM);
  - 33 dari 39 item evidence non-literal berupa awalan nama kolom atau salinan keluaran alat -> **K3** (prompt
    Klasifikasi E = prompt C + bagian MASUKAN, dengan kalimat penulis tentang menulis evidence persis seperti di log);
  - perubahan divalidasi di srbh_val, bukan di baris uji -> **K4**.

## 4. Validasi v2 di srbh_val (30 baris, 5 per kelas, tanpa 4 baris uji asap)

Laporan: `reports/archive/validasi_agent_val.md`. Dua run validasi dihentikan sebelum selesai karena review adversarial
kode menemukan masalah yang mengubah perilaku agen:
- `9ad710b`: guard putaran tidak atomik bila klasifikasi dan verifikasi dipanggil dalam satu pesan; `--resume` tidak
  memeriksa split/ids/log -> diperbaiki (pemanggilan klasifikasi/verifikasi berurutan, resume diperiksa);
- `38b109b`: Klasifikasi menerima `<pattern_hits>[]` ("CRS dijalankan, tidak cocok") ketika alatnya tidak pernah
  dijalankan (2/15 baris) -> masukan kini menulis "(alat tidak dijalankan)" dan klasifikasi yang dipanggil bersama
  parser/analisis_payload ditunda ke pesan berikutnya.

Hasil run validasi final (`agent-20261007T185745Z-3988205` vs `llm_single-20261007T201505Z-3988205`):

| | C | E v2 |
|---|---|---|
| benar | 21/30 | 21/30 |
| macro-F1 | 0,675 | 0,702 |
| evidence literal | 0,830 | 0,978 |
| panggilan LLM / baris | 1,0 | 11,5 |
| latensi median / p95 | 1,46 / 1,91 s | 20,9 / 552,6 s |
| PE / VF | 0 / — | 1 / 1 |
| delegasi ke 4 sub-agen | — | 26/30 |

## 5. Keluaran degeneratif pada run tanpa batas token

Definisi di sini: panggilan LLM dengan ≥32.000 token keluaran (batas keluaran model 32.768). Pada C keluarannya spasi
sampai batas (finish_reason length); pada E keluarannya pemanggilan alat orkestrator dengan argumen tidak valid
(`invalid_tool_calls`) sampai batas, ±500 s per panggilan.

| run | panggilan LLM | kejadian degeneratif | baris terdampak | porsi latensi | porsi biaya | outcome baris terdampak |
|---|---|---|---|---|---|---|
| C 500 (`6ce9f30`) | 501 | 2 | 1 dari 500 | 506 / 1.454 s | $0,0264 / $0,0917 | 1 PARSE_ERROR |
| E pilot v1 (`725069c`) | 563 | 0 | 0 dari 30 | 0 | 0 | — |
| E validasi (`9ad710b`, dihentikan) | 185 | 4 | 2 dari 16 | 1.442 / 1.828 s | $0,0579 / $0,0881 | — |
| E validasi (`38b109b`, dihentikan) | 177 | 3 | 2 dari 16 | 1.243 / 1.570 s | $0,0428 / $0,0851 | — |
| E validasi final (`3988205`) | 345 | 7 | 2 dari 30 | 3.596 / 4.301 s | $0,1111 / $0,1651 | 1 PARSE_ERROR (5 kejadian beruntun), 1 pulih |
| E 500 parsial (`e0daa05`) | 961 | 6 | 2 dari 83 | 2.781 / 4.674 s | $0,0946 / $0,2257 | lihat `results/archive/agent_uncapped_partial.jsonl` |

Pengamatan: keluaran degeneratif E muncul pada semua run v2 (setelah K1–K3) dan tidak muncul pada pilot v1 (563
panggilan), tetapi baris dan konfigurasinya berbeda sehingga penyebabnya belum dapat dipastikan. Atas dasar ini penulis
menetapkan `max_tokens` 4.096 untuk semua panggilan LLM C dan E sebagai pengaman kegagalan (bukan biaya); panggilan yang
terpotong dicatat TRUNCATED, diulang sekali, lalu PARSE_ERROR bila tetap tidak valid. Frekuensi TRUNCATED pada run resmi
dilaporkan di `reports/evaluasi.md`.

## 6. Perbaikan rekayasa lain yang tercatat di riwayat git

- Atribusi panggilan alat sub-agen terkompilasi (verifikasi) di log; alat dekode menerima nama bagian log, bukan teks
  bebas (uji asap di srbh_val menunjukkan orkestrator memparafrasekan log); `ProcedureGuard` menegakkan aturan "jika
  verifikasi gagal kembali ke Klasifikasi".
- Delegasi dihitung hanya dari pemanggilan sub-agen yang benar-benar berjalan; `invalid_tool_calls` ikut dicatat;
  laporan di `reports/` tidak membuat run tercatat dirty; run_id memuat nama run.
- Review adversarial kode dijalankan sebelum setiap run panjang (pilot, validasi, run resmi); hasilnya ada di riwayat
  commit dan di `reports/archive/`.
- Komentar (bukan nilai) di `configs/regex_baseline.yaml` dan `configs/regex_full.yaml` disunting setelah run regex
  resmi; isi konfigurasi yang dibaca program identik. `config_sha256` di `results/regex.run.json`,
  `results/regex_full.run.json`, dan `results/tuning/regex_full_val.run.json` cocok dengan berkas pada commit run
  masing-masing (`497dc3d`, `d7fd371`).
