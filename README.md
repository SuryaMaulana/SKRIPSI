# Skripsi — Deteksi dan Klasifikasi Serangan Aplikasi Web pada Log Akses (Deep Agent LLM)

Tahap saat ini **hanya persiapan dataset**. Belum ada agen atau model.

## Menjalankan

```bash
make setup   # sekali: .venv Python 3.11 + dependensi terkunci (requirements.txt)
make data    # dari awal: unduh SR-BH 2020 bila belum ada, lalu seluruh pipeline (Langkah 1–10)
make test       # unit test (cepat)
make test-slow  # uji paritas gerbang bukti pada data penuh (butuh data/evidence/)
```

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

## Struktur

```
configs/label_mapping.yaml   pemetaan CAPEC → 6 kelas (sumber kebenaran)
src/data/                    pipeline: download, load, inspect_srbh, labels, reconstruct, clf_parser,
                             normalize, session, split, sample, report, prepare
src/data/gate/               aturan gerbang bukti per kelompok label
tests/                       unit test (pytest)
reports/                     laporan yang dihasilkan pipeline
data/evidence/               cuplikan analisis bukti pemetaan label (sumber target paritas; tidak dihapus `make clean`)
```

## Kelas target

SQLI, XSS, PATH_TRAVERSAL, CMD_INJECTION, WEB_SCANNING, NORMAL.
