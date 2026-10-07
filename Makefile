# Pipeline persiapan data SR-BH 2020. `make help` untuk daftar target.
PY ?= .venv/bin/python
RAW := data/raw/srbh2020/data_capec_multilabel.csv

.PHONY: help setup download inspect data test test-slow clean check-api regex verify-crs golden-check regex-full-val regex-full eval

help:
	@echo "make setup     buat .venv (Python 3.11) dan pasang dependensi terkunci"
	@echo "make download  unduh SR-BH 2020 dari Harvard Dataverse bila belum ada (diverifikasi MD5)"
	@echo "make inspect   langkah 2 saja: inspeksi dataset -> reports/srbh_inspection.md"
	@echo "make data      seluruh pipeline dari awal -> data/interim, data/processed, reports"
	@echo "make test      unit test (cepat)"
	@echo "make test-slow uji paritas gerbang bukti pada data penuh"
	@echo "make clean     hapus data/interim dan data/processed (data/raw tidak disentuh)"
	@echo "make check-api langkah A: satu prompt pendek ke model di configs/llm.yaml (butuh OPENROUTER_API_KEY di .env)"
	@echo "make regex     langkah B: pembanding regex (CRS + Baş Seyyar dkk.) pada test_sample_500 -> results/regex.jsonl"
	@echo "make verify-crs cocokkan emulasi CRS dengan uji regresi resmi CRS -> results/crs_regression.json"
	@echo "make golden-check bangun harness C ModSecurity 2.9.15 (butuh cc) dan audit tests/fixtures/modsec_v2915_golden.json"
	@echo "make regex-full-val varian regex_full pada srbh_val + evaluasi (penyesuaian pemetaan)"
	@echo "make regex-full varian regex_full pada test_sample_500 -> results/regex_full.jsonl (post_hoc)"
	@echo "make eval      D: Tabel 4.2/4.3, F1 per kelas, confusion matrix, IK 95% untuk semua results/*.jsonl"

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

check-api:
	$(PY) scripts/check_openrouter.py

regex:
	$(PY) -m src.baselines.regex_baseline

verify-crs:
	$(PY) -m src.baselines.crs_regression

golden-check:
	@tmp=$$(mktemp -d) && cp -R tools/modsec_harness/. $$tmp/ && \
	cc -O2 -w -I $$tmp/apr_stub -o $$tmp/tfns_map $$tmp/main_map.c && \
	cc -O2 -w -I $$tmp/apr_stub -o $$tmp/pm $$tmp/pm_main.c $$tmp/acmp.c && \
	$(PY) scripts/make_modsec_golden.py --check $$tmp; status=$$?; rm -rf $$tmp; exit $$status

regex-full-val:
	$(PY) -m src.baselines.regex_baseline --config configs/regex_full.yaml --split val
	$(PY) -m src.eval.evaluate results/tuning/regex_full_val.jsonl --truth val --rules

regex-full:
	$(PY) -m src.baselines.regex_baseline --config configs/regex_full.yaml

eval:
	$(PY) -m src.eval.evaluate --rules
