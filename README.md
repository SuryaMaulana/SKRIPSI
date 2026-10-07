# Skripsi — Deteksi dan Klasifikasi Serangan Aplikasi Web pada Log Akses (Deep Agent LLM)

Tahap persiapan dataset selesai (langkah 1–10). Tahap sistem: A cek API, B pembanding regex (utama + varian sekunder `regex_full`, post hoc), C LLM tunggal zero-shot, D evaluasi, E deep agent (pilot 30 baris; 500 baris menunggu persetujuan penulis).

## Menjalankan

```bash
make setup   # sekali: .venv Python 3.11 + dependensi terkunci (requirements.txt)
make data    # dari awal: unduh SR-BH 2020 bila belum ada, lalu seluruh pipeline (Langkah 1–10)
make test       # unit test (cepat)
make test-slow  # uji paritas gerbang bukti (data penuh) + uji regresi resmi CRS
make check-api  # A: satu prompt pendek ke model di configs/llm.yaml (OPENROUTER_API_KEY dari .env)
make regex      # B: pembanding regex pada test_sample_500 -> results/regex.jsonl
make verify-crs # B: cocokkan emulasi CRS dengan uji regresi resmi CRS -> results/crs_regression.json
make golden-check   # B: bandingkan port ModSecurity dengan vektor emas harness C (tools/modsec_harness/)
make regex-full-val # B: varian sekunder regex_full (CRS PL1 semua kategori) pada srbh_val -> results/tuning/
make regex-full     # B: regex_full sekali pada test_sample_500 -> results/regex_full.jsonl (post_hoc=true)
make llm-single-pilot # C: LLM tunggal pada 30 baris pilot (5 per kelas) -> results/pilot/
make run-c R=1        # C: run resmi ke-1 (1-3) pada 500 baris -> results/llm_single_r1.jsonl (+ _calls.jsonl)
make agent-pilot      # E: deep agent pada 30 baris pilot yang sama -> results/pilot/agent.jsonl
make agent-val        # E: validasi deep agent v2 (K1-K3) + LLM tunggal pada 30 baris srbh_val -> results/validasi/
make run-e R=1        # E: run resmi ke-1 (1-3) pada 500 baris -> results/agent_r1.jsonl (+ _calls.jsonl)
make runs-c / runs-e  # ketiga run resmi C / E berurutan (boleh dijalankan paralel antar run)
make eval             # D: laporan utama reports/evaluasi.md = rerata (min-maks) atas 3 run C dan 3 run E untuk
                      #    Tabel 4.2-4.5, F1 per kelas, confusion matrix rerata, frekuensi keluaran degeneratif;
                      #    rincian per run di reports/evaluasi_per_run.md
```

Run LLM (C dan E) yang terhenti karena galat API dilanjutkan dengan menjalankan ulang perintah yang sama persis ditambah
`--resume` (mis. `python -m src.agent.run --split val --ids results/validasi/val_ids.json --out-dir results/validasi
--resume`); runner menolak bila masukan, daftar baris, log panggilan, atau nama keluaran berbeda dari run awal. Baris yang
terkena galat API tidak dinilai salah. Kunci `OPENROUTER_API_KEY` hanya dibaca dari `.env` di dalam kode dan tidak pernah dicatat; tracing
LangSmith dimatikan, semua catatan panggilan tetap lokal.

Protokol akhir (keputusan penulis 2026-10-08): semua panggilan LLM C dan E memakai max_tokens 4.096 (configs/llm.yaml;
pengaman kegagalan, bukan biaya). Panggilan yang terpotong dicatat TRUNCATED, diulang sekali, lalu PARSE_ERROR bila tetap
tidak valid. C dan E masing-masing dijalankan 3 kali pada 500 baris yang sama (seed sama); tabel utama memakai rerata.
Run lama (C 500 tanpa batas, pilot E v1, validasi v2, E 500 tanpa batas parsial) ada di results/archive/ dan dibahas di
reports/catatan_rekayasa.md; tidak masuk tabel.

Aturan umum tahap sistem: semua metode membaca kolom masukan yang sama dari `test_sample_500.jsonl` lewat
`src/common/inputs.py` (tanpa `label`/`template_key`); setiap run mencatat tanggal, commit git, dan nama model
(`results/*.run.json`).

Tanpa `make`: `python -m src.data.download && python -m src.data.prepare`.

## Data

| Dataset | Lokasi | Keterangan |
|---|---|---|
| SR-BH 2020 | `data/raw/srbh2020/data_capec_multilabel.csv` | Harvard Dataverse doi:10.7910/DVN/OGOIXX, v1.2, CC0 1.0, MD5 `173ec515308bdce5aec19cfd5b792596` |
| Zenodo Org. X | `data/raw/zenodo_orgx/` | belum diproses (validasi eksternal opsional) |

Berkas di `data/raw/` tidak pernah diubah; pipeline memverifikasi MD5 sebelum membaca. Folder `data/` tidak di-commit.

## Keluaran

| Berkas | Isi |
|---|---|
| `data/processed/srbh_{train,val,test}.parquet` | split stratified 70/15/15 (random_state=42) |
| `data/processed/test_sample_500.jsonl` | sampel uji untuk eksperimen LLM |
| `data/processed/srbh_excluded.parquet` | baris yang dikeluarkan beserta kode alasannya |
| `data/processed/label_mapping.yaml` | pemetaan CAPEC → 6 kelas yang dipakai + hitungan |
| `reports/data_report.md` | statistik per tahap dan daftar keputusan praproses |
| `configs/llm.yaml` | model (openai/gpt-4.1-nano-2025-04-14), tarif per 1M token, hasil cek API |
| `results/regex.jsonl`, `results/regex.run.json` | prediksi pembanding regex per baris + metadata run |
| `results/regex_full.jsonl`, `results/regex_full.run.json` | varian sekunder regex_full (post hoc) |
| `results/llm_single_r{1,2,3}.jsonl` + `.run.json` | LLM tunggal, 3 run resmi: label, confidence, evidence, explanation, token, biaya, latensi |
| `results/llm_single_r{1,2,3}_calls.jsonl` | setiap panggilan API LLM tunggal per run: prompt, respons mentah, token, biaya, TRUNCATED |
| `results/agent_r{1,2,3}.jsonl` + `.run.json` | deep agent, 3 run resmi: label akhir, status verifikasi, delegasi, token, biaya, latensi |
| `results/agent_r{1,2,3}_calls.jsonl` | setiap panggilan LLM dan alat deep agent per run: sub-agen, token, biaya, latensi, putaran |
| `results/archive/` | run lama (catatan rekayasa): C tanpa batas, pilot v1, validasi v2, E 500 tanpa batas parsial |
| `reports/evaluasi.md/.json` | laporan evaluasi utama (rerata dan rentang atas 3 run) |
| `reports/evaluasi_per_run.md/.json` | rincian evaluasi per run dan aturan pendorong salah kelas regex |

## Struktur

```
configs/label_mapping.yaml   pemetaan CAPEC → 6 kelas (sumber kebenaran)
configs/llm.yaml             model LLM dan tarif (langkah A)
configs/regex_baseline.yaml  versi CRS, PL, poin skor, pemetaan hit -> kelas, aturan Baş Seyyar dkk. (langkah B)
configs/regex_full.yaml      varian sekunder: CRS PL1 semua kategori, pemetaan kategori -> kelas, penyesuaian tercatat
configs/owasp_kb.yaml        basis pengetahuan statis per kelas untuk alat lookup_owasp (langkah E)
src/data/                    pipeline: download, load, inspect_srbh, labels, reconstruct, clf_parser,
                             normalize, session, split, sample, report, prepare
src/data/gate/               aturan gerbang bukti per kelompok label
src/common/                  masukan metode (tanpa kolom evaluasi), metadata run, pemeriksa evidence literal
src/llm/                     klien OpenRouter; klasifikasi.py: Tabel 2.1, aturan, skema keluaran (dipakai C dan E)
src/baselines/               pembanding: crs (pemuat aturan CRS), modsec (emulasi ModSecurity 2.9.15 + Apache 2.4),
                             bas_seyyar, regex_baseline, crs_regression (verifikasi terhadap uji resmi CRS)
                             llm_prompt + llm_single (LLM tunggal zero-shot, langkah C)
src/agent/                   deep agent (langkah E): graph (orkestrator deepagents + 4 sub-agen), tools,
                             prompts, context, run; tidak mengimpor src/data/gate/. Sejak keputusan K1-K3
                             (2026-10-08): orkestrator hanya task + write_todos (alat berkas deepagents dan execute
                             dimatikan), Verifikasi deterministik tanpa LLM, prompt Klasifikasi = prompt C + MASUKAN
src/eval/                    evaluate (Tabel 4.2-4.5, bootstrap klaster), replikasi (rerata/min-maks atas run),
                             pilot (pemilihan 30 baris),
                             pilot_compare (perbandingan per baris E vs C)
scripts/check_openrouter.py  langkah A
scripts/make_modsec_golden.py vektor emas port ModSecurity dari harness C (tests/fixtures/modsec_v2915_golden.json)
data/external/crs/           arsip OWASP CRS terpatok (diunduh otomatis, diverifikasi SHA-256)
data/external/modsecurity/   unicode.mapping ModSecurity v2.9.15 terpatok (SecUnicodeMapFile 20127, diverifikasi SHA-256)
tests/                       unit test (pytest)
reports/                     laporan yang dihasilkan pipeline
data/evidence/               cuplikan analisis bukti pemetaan label (sumber target paritas; tidak dihapus `make clean`)
```

## Kelas target

SQLI, XSS, PATH_TRAVERSAL, CMD_INJECTION, WEB_SCANNING, NORMAL.
