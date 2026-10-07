"""Jalur, sumber data, dan parameter global pipeline persiapan dataset."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
INTERIM_DIR = DATA_DIR / "interim"
PROCESSED_DIR = DATA_DIR / "processed"
REPORTS_DIR = ROOT / "reports"
CONFIGS_DIR = ROOT / "configs"

# SR-BH 2020 — Harvard Dataverse, doi:10.7910/DVN/OGOIXX, versi 1.2 (rilis 2022-06-06), lisensi CC0 1.0.
# Dataset ini hanya berisi satu berkas; MD5 dan ukuran diambil dari metadata API Dataverse.
SRBH_DOI = "10.7910/DVN/OGOIXX"
SRBH_DATAFILE_ID = 6319496
SRBH_URL = f"https://dataverse.harvard.edu/api/access/datafile/{SRBH_DATAFILE_ID}"
SRBH_MD5 = "173ec515308bdce5aec19cfd5b792596"
SRBH_SIZE_BYTES = 436_437_661
SRBH_CSV = RAW_DIR / "srbh2020" / "data_capec_multilabel.csv"

# Sumber kebenaran pemetaan label ada di configs/ (ikut versi kode);
# pipeline menyalinnya ke data/processed/ agar folder keluaran berdiri sendiri.
LABEL_MAPPING_SRC = CONFIGS_DIR / "label_mapping.yaml"
LABEL_MAPPING_OUT = PROCESSED_DIR / "label_mapping.yaml"

INSPECTION_REPORT = REPORTS_DIR / "srbh_inspection.md"

RANDOM_STATE = 42

CLASSES = ["SQLI", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "WEB_SCANNING", "NORMAL"]
