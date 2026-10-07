# Pipeline persiapan data SR-BH 2020. `make help` untuk daftar target.
PY ?= .venv/bin/python
RAW := data/raw/srbh2020/data_capec_multilabel.csv

.PHONY: help setup download inspect data test test-slow clean

help:
	@echo "make setup     buat .venv (Python 3.11) dan pasang dependensi terkunci"
	@echo "make download  unduh SR-BH 2020 dari Harvard Dataverse bila belum ada (diverifikasi MD5)"
	@echo "make inspect   langkah 2 saja: inspeksi dataset -> reports/srbh_inspection.md"
	@echo "make data      seluruh pipeline dari awal -> data/interim, data/processed, reports"
	@echo "make test      unit test (cepat)"
	@echo "make test-slow uji paritas gerbang bukti pada data penuh"
	@echo "make clean     hapus data/interim dan data/processed (data/raw tidak disentuh)"

setup:
	@if command -v uv >/dev/null 2>&1; then \
		uv venv --python 3.11 .venv && uv pip install --python .venv/bin/python -r requirements.txt; \
	else \
		python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt; \
	fi

$(RAW):
	$(PY) -m src.data.download

download: $(RAW)

inspect: $(RAW)
	$(PY) -m src.data.inspect_srbh

data: $(RAW)
	$(PY) -m src.data.prepare

test:
	$(PY) -m pytest

test-slow:
	$(PY) -m pytest -m slow

clean:
	rm -rf data/interim data/processed
