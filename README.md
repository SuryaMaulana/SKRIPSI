# Deteksi dan Klasifikasi Serangan Aplikasi Web pada Log Akses Web Server Menggunakan Deep Agent LLM

**Muhammad Surya Maulana** — Skripsi S1 Sains Data, Universitas Negeri Surabaya

## Ringkasan

Penelitian ini mengklasifikasikan setiap baris log akses web server (Combined Log Format) dari dataset SR-BH 2020 ke enam
kelas (SQLI, XSS, PATH_TRAVERSAL, CMD_INJECTION, WEB_SCANNING, NORMAL) dan membandingkan tiga pendekatan: pembanding
berbasis aturan (emulasi OWASP CRS 4.30.0 PL1 dan aturan Baş Seyyar dkk.), satu LLM zero-shot, dan deep agent (orkestrator
LangGraph/deepagents yang mendelegasikan ke sub-agen Parser, Analisis Payload, Klasifikasi, dan Verifikasi deterministik).
Pada sampel uji 500 baris, LLM tunggal mencapai akurasi tertinggi (macro-F1 0,830, rerata 3 run), deep agent menghasilkan
bukti yang paling sahih (evidence literal 0,897 vs 0,762) tetapi dengan akurasi lebih rendah (macro-F1 0,750) dan biaya
sekitar 12 kali, sedangkan regex tidak menghasilkan positif palsu (FPR 0,000) namun melewatkan 35,9% baris serangan.
Rincian angka dan sumbernya ada di `reports/evaluasi.md` dan `reports/ringkasan_sidang.md`.

## Reproduksi dari nol

Prasyarat: Python 3.11, `uv` (atau `pip`), `make`, dan `OPENROUTER_API_KEY` di berkas `.env` (dibaca hanya di dalam kode,
tidak pernah dicatat).

```bash
make setup        # .venv Python 3.11 + dependensi terkunci (requirements.txt)
make data         # unduh SR-BH 2020, verifikasi MD5, pipeline Langkah 1-10 -> data/processed/, reports/data_report.md,
                  #   reports/srbh_inspection.md
make regex        # pembanding regex utama -> results/regex.jsonl
make regex-full   # varian sekunder regex_full (CRS PL1 semua kategori, post hoc) -> results/regex_full.jsonl
make llm_single   # LLM tunggal, 3 run pada 500 baris yang sama -> results/llm_single_r{1,2,3}.jsonl
make agent        # deep agent, 3 run pada 500 baris yang sama -> results/agent_r{1,2,3}.jsonl
make llm_single_verified  # ablasi revisi jurnal: LLM tunggal + loop verifikasi, 3 run
                  #   -> results/llm_single_verified_r{1,2,3}.jsonl
make eval         # reports/evaluasi.md (rerata dan rentang min-maks), reports/evaluasi_per_run.md,
                  #   reports/revisi_ablasi.md (Tabel 4-11 manuskrip revisi, uji berpasangan), dan
                  #   reports/revisi_tambahan.md (angka di teks naskah; kontrafaktual dedup membaca data/raw)
make test         # unit test
```

- Ketiga run tiap metode boleh dijalankan paralel: `make run-c R=1|2|3` dan `make run-e R=1|2|3`. Run yang terhenti karena
  galat API dilanjutkan dengan perintah yang sama ditambah `--resume`
  (mis. `python -m src.agent.run --name agent_r1 --calls results/agent_r1_calls.jsonl --resume`).
- Hasil LLM tidak identik bit demi bit antar run walaupun temperature 0 dan seed sama; karena itu tabel utama memakai
  rerata 3 run.
- **Model:** `openai/gpt-4.1-nano` (versi model `openai/gpt-4.1-nano-2025-04-14`) lewat OpenRouter, penyedia `openai`
  tanpa fallback (`require_parameters: true`), temperature 0, seed 42, `max_tokens` 4.096 untuk semua panggilan
  (pengaman kegagalan; panggilan terpotong dicatat TRUNCATED, diulang sekali, lalu PARSE_ERROR bila tetap tidak valid).
- **Tarif** (OpenRouter, diambil 2026-10-07, `configs/llm.yaml`): $0,10 per 1 juta token masukan, $0,40 per 1 juta token
  keluaran, $0,025 per 1 juta token masukan dari cache (cache read).
- **Versi:** Python 3.11.13; deepagents 0.7.22; langchain 1.4.3; langchain-core 1.6.7; langchain-openai 1.6.7;
  langgraph 1.2.14; openai 3.26.0; httpx 0.28.1; pydantic 2.13.5; pandas 2.3.3; numpy 2.4.6; pyarrow 25.0.1;
  scikit-learn 1.9.1; pyyaml 6.0.3; python-dotenv 1.2.4; pytest 9.1.1. Daftar lengkap terkunci di `requirements.txt`.
  OWASP CRS 4.30.0 diunduh dari arsip terpatok dan diverifikasi SHA-256; emulasi mengikuti ModSecurity 2.9.15.
- **Log panggilan** (`results/*_calls.jsonl`: setiap panggilan LLM dan alat) tidak disertakan di repositori karena
  ukurannya. Tanpa log itu, `make eval` tetap menghasilkan semua tabel, kecuali dua kolom latensi per panggilan di
  Tabel 4.4, catatan panggilan agent yang dibatalkan galat API, dan cek silang TRUNCATED; karena itu `reports/evaluasi.md`
  dari klon bersih berbeda dari versi di repositori pada bagian tersebut.

## Hasil akhir (ringkas)

Disalin dari `reports/evaluasi.md`; nilai LLM tunggal dan deep agent adalah rerata 3 run (min–maks). IK 95% macro-F1
dihitung dengan bootstrap klaster per templat (1.000×) atas macro-F1 rerata run.

**Tabel 4.2 — deteksi biner (serangan vs NORMAL)**

| metode | accuracy | precision | recall | F1 | FPR |
|---|---|---|---|---|---|
| regex | 0,704 | 1,000 | 0,641 | 0,781 | 0,000 |
| regex_full (post hoc) | 0,836 | 1,000 | 0,801 | 0,889 | 0,000 |
| llm_single | 0,902 (0,898–0,906) | 0,993 (0,992–0,995) | 0,888 (0,883–0,891) | 0,937 (0,935–0,940) | 0,030 (0,023–0,034) |
| agent | 0,837 (0,836–0,838) | 0,989 (0,985–0,991) | 0,811 (0,808–0,813) | 0,891 (0,890–0,892) | 0,042 (0,034–0,057) |

**Tabel 4.3 — klasifikasi 6 kelas**

| metode | accuracy | macro-P | macro-R | macro-F1 | IK 95% macro-F1 (rerata run) |
|---|---|---|---|---|---|
| regex | 0,698 | 0,889 | 0,717 | 0,717 | [0,622; 0,779] |
| regex_full (post hoc) | 0,828 | 0,912 | 0,839 | 0,820 | [0,752; 0,859] |
| llm_single | 0,831 (0,828–0,832) | 0,860 (0,859–0,862) | 0,841 (0,839–0,843) | 0,830 (0,828–0,832) | [0,752; 0,878] |
| agent | 0,747 (0,740–0,752) | 0,853 (0,850–0,857) | 0,763 (0,756–0,768) | 0,750 (0,745–0,753) | [0,644; 0,814] |

**Tabel 4.5 — evidence literal**

| metode | proporsi literal |
|---|---|
| llm_single | 0,762 (0,750–0,768) |
| agent | 0,897 (0,890–0,901) |

## Berkas hasil dan laporan

| berkas | isi |
|---|---|
| `results/regex.jsonl` (+ `.run.json`) | prediksi pembanding regex utama per baris dan metadata run |
| `results/regex_full.jsonl` (+ `.run.json`) | prediksi varian sekunder regex_full (post hoc) |
| `results/llm_single_r{1,2,3}.jsonl` (+ `.run.json`) | LLM tunggal, 3 run resmi: label, confidence, evidence, explanation, token, biaya, latensi |
| `results/agent_r{1,2,3}.jsonl` (+ `.run.json`) | deep agent, 3 run resmi: label akhir, status verifikasi, delegasi, token, biaya, latensi |
| `results/tuning/` | run regex_full di srbh_val untuk penyesuaian pemetaan |
| `results/crs_regression.json`, `results/crs_regression_regex_full.json` | verifikasi emulasi CRS terhadap uji regresi resmi CRS |
| `results/llm_single_verified_r{1,2,3}.jsonl` (+ `.run.json`) | ablasi revisi jurnal (LLM tunggal + loop verifikasi), 3 run: label, status dan putusan verifikasi per putaran, riwayat klasifikasi, token, biaya, latensi |
| `results/check_openrouter.json` | hasil cek API dan konfigurasi model |
| `results/pemetaan_commit.json` | pemetaan commit lama (tercatat di `*.run.json` dan `run_id`) ke riwayat git sekarang |
| `results/archive/` | run yang tidak masuk tabel (lihat Catatan rekayasa) |
| `reports/evaluasi.md` (+ `.json`) | laporan evaluasi utama: Tabel 4.2–4.5, F1 per kelas, confusion matrix rerata, keluaran degeneratif |
| `reports/evaluasi_per_run.md` (+ `.json`) | rincian evaluasi per run dan aturan pendorong salah kelas regex |
| `reports/revisi_ablasi.md` (+ `.json`) | revisi jurnal: angka Tabel 4-11 manuskrip untuk kelima metode termasuk ablasi, uji berpasangan, dekomposisi loop vs orkestrasi |
| `reports/revisi_tambahan.md` (+ `.json`) | revisi jurnal: angka di teks naskah di luar Tabel 4-11 (470 baris tanpa pilot, kaskade regex → LLM tunggal, recall sub-tipe WEB_SCANNING, label berubah antar run per kelas, letak payload SQLI yang terlewat regex, kontrafaktual dedup persis) |
| `sampel/test_sample_500_masukan.jsonl` | sampel uji 500 baris: id opak + kolom masukan metode saja, tanpa label gerbang dan `template_key` (lihat Data) |
| `reports/ringkasan_sidang.md` | ringkasan sidang: angka kunci, tiga klaim utama, 17 pertanyaan penguji dengan jawaban berbasis angka |
| `reports/catatan_rekayasa.md` | riwayat run yang tidak masuk tabel beserta alasannya, pemetaan hash commit, pemeriksaan prompt injection |
| `reports/data_report.md` | statistik dataset per tahap, sampel uji, dan daftar keputusan praproses |
| `reports/srbh_inspection.md` | inspeksi awal SR-BH 2020 |
| `reports/label_mapping_proposal.md` | usulan dan bukti pemetaan label CAPEC ke 6 kelas |
| `reports/catatan_pembanding_regex.md` | catatan pembanding regex dan regex_full |
| `reports/archive/` | laporan run lama (pilot, validasi, evaluasi tanpa batas token, evaluasi regex awal) |

## Revisi jurnal (cabang `revisi-jurnal`)

- **Ablasi** `src/baselines/llm_single_verified.py`: panggilan pertama identik dengan LLM tunggal; bila evidence tidak
  literal atau skema salah, model dipanggil sekali lagi dengan alasan penolakan memakai bagian MASUKAN prompt
  Klasifikasi tanpa keluaran alat (paling banyak 2 putaran verifikasi, sama dengan deep agent). Verifikasi memakai
  fungsi deep agent apa adanya.
- **Laporan** `src/eval/revisi.py` (bagian dari `make eval`): definisi setiap kolom ada di docstring-nya; leksikon
  class-consistent di `configs/leksikon_kelas.yaml`.
- **Analisis tambahan** `src/eval/revisi_tambahan.py` (bagian dari `make eval`) -> `reports/revisi_tambahan.md`: sumber
  angka di teks naskah yang tidak ada di Tabel 4-11; definisi di docstring-nya. Kontrafaktual dedup persis membangun ulang
  bingkai 6 kelas dari `data/raw/` (hanya dibaca, MD5 diverifikasi) dan memeriksa paritasnya dengan split uji resmi.
- **Sampel publik** `sampel/test_sample_500_masukan.jsonl` (`make sampel-publik`): lihat Data.
- **Audit manusia** `src/eval/anotasi.py`: `python -m src.eval.anotasi siapkan` membuat `audit/anotasi_A_anotator{1,2}.xlsx`
  (label kelas) dan `audit/anotasi_B_anotator{1,2}.xlsx` (relevansi bukti, metode disamarkan); daftar id dan kunci
  disimpan di `data/processed/` dan tidak dibagikan. Setelah diisi: `python -m src.eval.anotasi hitung --a1 ... --a2 ...
  --b1 ... --b2 ...` -> `reports/revisi_anotasi.md`.

## Data

| dataset | lokasi | keterangan |
|---|---|---|
| SR-BH 2020 | `data/raw/srbh2020/data_capec_multilabel.csv` | Harvard Dataverse doi:10.7910/DVN/OGOIXX, v1.2, CC0 1.0, MD5 `173ec515308bdce5aec19cfd5b792596` |

Berkas di `data/raw/` tidak pernah diubah; pipeline memverifikasi MD5 sebelum membaca. Folder `data/` tidak di-commit dan
dibangun ulang dengan `make data`.

**Sampel uji 500 baris** ada di repositori: [`sampel/test_sample_500_masukan.jsonl`](sampel/test_sample_500_masukan.jsonl)
(433 KB, CC0 1.0 seperti SR-BH 2020). Isinya baris `data/processed/test_sample_500.jsonl` dalam urutan yang sama, hanya
dengan `id` dan kolom masukan metode (`raw_log_masked`, hasil parsing tanpa waktu dan protokol, serta `path_norm`,
`query_norm`, `ua_norm`), yaitu persis yang dibaca semua metode. Label gerbang dan `template_key` tidak disertakan;
keduanya dibangun ulang dengan `make data`. `id` adalah id opak `srbh-` + 16 digit heksadesimal pertama
SHA-256(`srbh2020:<row_id>`), dengan `row_id` = indeks baris data berbasis 0 di CSV SR-BH (tanpa header;
`opaque_id` di `src/data/prepare.py`), sehingga id tidak memuat nomor baris; id yang sama dipakai di `results/*.jsonl`.
Urutan baris berkas adalah acakan berbenih tetap (random_state 42) dari sampel, sama dengan urutan `results/*.jsonl`.
Berkas ini dibuat ulang dari sampel olahan dengan `make sampel-publik`. Semua metode hanya membaca kolom masukan `test_sample_500.jsonl` lewat
`src/common/inputs.py` (tanpa `label`/`template_key`); setiap run mencatat tanggal, commit git, dan nama model di
`results/*.run.json`. Riwayat git ditulis ulang setelah semua run selesai, sehingga commit di `*.run.json` dan di
`run_id` adalah hash lama; pemetaannya ke riwayat sekarang ada di `results/pemetaan_commit.json` dan
`reports/catatan_rekayasa.md` §7.

## Struktur

```
configs/      pemetaan label, model LLM dan tarif, konfigurasi regex/regex_full, basis pengetahuan OWASP untuk agen
src/data/     pipeline dataset (unduh, label, rekonstruksi, parsing, normalisasi, split, sampel, laporan)
src/baselines/ pembanding regex (emulasi CRS/ModSecurity, Baş Seyyar dkk.) dan LLM tunggal
src/llm/      klien OpenRouter dan klasifikasi terstruktur (dipakai LLM tunggal dan deep agent)
src/agent/    deep agent: orkestrator deepagents, sub-agen, alat, prompt, runner
src/eval/     evaluasi per run, agregasi rerata 3 run, laporan revisi dan analisis tambahan, audit manusia, pemilihan pilot
src/common/   masukan metode, metadata run, pemeriksa evidence literal
scripts/      cek API OpenRouter (make check-api) dan pembuat golden ModSecurity (make golden-check)
tools/        harness C ModSecurity 2.9.15 untuk verifikasi emulasi
audit/        berkas anotasi audit manusia (revisi jurnal)
sampel/       sampel uji 500 baris publik (id opak + kolom masukan metode, tanpa label)
tests/        unit test (pytest)
```

## Catatan rekayasa

Run yang tidak masuk tabel utama, misalnya run sebelum batas `max_tokens`, pilot, validasi, dan run yang dihentikan,
disimpan di `results/archive/`. Riwayat dan alasan setiap keputusannya dicatat di
[`reports/catatan_rekayasa.md`](reports/catatan_rekayasa.md), bersama pemetaan hash commit (§7) dan pemeriksaan prompt
injection pada run resmi (§8).
