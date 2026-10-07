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
make llm-single       # C: LLM tunggal pada 500 baris -> results/llm_single.jsonl (+ llm_single_calls.jsonl)
make agent-pilot      # E: deep agent pada 30 baris pilot yang sama -> results/pilot/agent.jsonl
make agent-val        # E: validasi deep agent v2 (K1-K3) + LLM tunggal pada 30 baris srbh_val -> results/validasi/
make agent            # E: deep agent pada 500 baris -> results/agent.jsonl (+ agent_calls.jsonl)
make replikasi        # C dan E masing-masing 3 run lagi pada 500 baris yang sama -> results/replikasi/
make eval             # D: Tabel 4.2-4.5 per run (reports/evaluasi.md) + rerata dan rentang min-maks atas
                      #    run berkonfigurasi sama (reports/evaluasi_replikasi.md; tabel utama = rerata)
```

Run LLM (C dan E) yang terhenti karena galat API dilanjutkan dengan `--resume`
(`python -m src.baselines.llm_single --resume`, `python -m src.agent.run --resume`); baris yang terkena galat API tidak
dinilai salah. Kunci `OPENROUTER_API_KEY` hanya dibaca dari `.env` di dalam kode dan tidak pernah dicatat; tracing
LangSmith dimatikan, semua catatan panggilan tetap lokal.

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
| `results/llm_single.jsonl`, `results/llm_single.run.json` | LLM tunggal: label, confidence, evidence, explanation, token, biaya, latensi |
| `results/llm_single_calls.jsonl` | setiap panggilan API LLM tunggal: prompt, respons mentah, token, biaya |
| `results/agent.jsonl`, `results/agent.run.json` | deep agent: label akhir, status verifikasi, token, biaya, latensi per baris |
| `results/agent_calls.jsonl` | setiap panggilan LLM dan alat deep agent: sub-agen, token, biaya, latensi, putaran verifikasi |
| `results/pilot/` | pilot 30 baris (5 per kelas) untuk C dan E |
| `reports/evaluasi*.md/.json` | keluaran skrip evaluasi (langkah D) |

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
