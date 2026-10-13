# Pipeline persiapan data SR-BH 2020. `make help` untuk daftar target.
PY ?= .venv/bin/python
RAW := data/raw/srbh2020/data_capec_multilabel.csv

.PHONY: help setup download inspect data test test-slow clean check-api regex verify-crs golden-check regex-full-val regex-full eval llm-single-pilot agent-pilot agent-val run-c run-e runs-c runs-e llm_single agent run-cv runs-cv llm_single_verified

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
	@echo "               + reports/revisi_ablasi.md: Tabel 4-11 manuskrip revisi (termasuk ablasi), uji berpasangan"
	@echo "make llm-single-pilot C: LLM tunggal pada 30 baris pilot (5 per kelas) -> results/pilot/"
	@echo "make run-c R=n   C: run resmi ke-n (1-3) pada 500 baris -> results/llm_single_rn.jsonl (+ _calls.jsonl)"
	@echo "make agent-pilot E: deep agent pada 30 baris pilot yang sama dengan C -> results/pilot/"
	@echo "make agent-val    E: validasi deep agent v2 + LLM tunggal pada 30 baris srbh_val -> results/validasi/"
	@echo "make run-e R=n   E: run resmi ke-n (1-3) pada 500 baris -> results/agent_rn.jsonl (+ _calls.jsonl)"
	@echo "make runs-c / runs-e  ketiga run resmi C / E berurutan"
	@echo "make llm_single / agent  alias runs-c / runs-e (urutan reproduksi di README)"
	@echo "make run-cv R=n  ablasi revisi: LLM tunggal + loop verifikasi, run ke-n (1-3) -> results/llm_single_verified_rn.jsonl"
	@echo "make llm_single_verified  ketiga run ablasi berurutan (alias runs-cv)"

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
	$(PY) -m src.eval.replikasi --out reports/evaluasi.md
	$(PY) -m src.eval.evaluate --rules --out reports/evaluasi_per_run.md
	$(PY) -m src.eval.revisi --out reports/revisi_ablasi.md

llm-single-pilot:
	$(PY) -m src.eval.pilot
	$(PY) -m src.baselines.llm_single --ids results/pilot/pilot_ids.json --out-dir results/pilot

agent-pilot:
	$(PY) -m src.agent.run --ids results/pilot/pilot_ids.json --out-dir results/pilot

agent-val:
	$(PY) -m src.eval.pilot --split val --out results/validasi/val_ids.json
	$(PY) -m src.agent.run --split val --ids results/validasi/val_ids.json --out-dir results/validasi
	$(PY) -m src.baselines.llm_single --split val --ids results/validasi/val_ids.json --out-dir results/validasi
	$(PY) -m src.eval.pilot_compare --truth val --ids results/validasi/val_ids.json --agent results/validasi/agent.jsonl \
		--single results/validasi/llm_single.jsonl --single-pilot '' \
		--title "Validasi deep agent v2 vs LLM tunggal (srbh_val)" --out reports/validasi_agent_val.md

R ?= 1

run-c:
	$(PY) -m src.baselines.llm_single --name llm_single_r$(R) --calls results/llm_single_r$(R)_calls.jsonl

run-e:
	$(PY) -m src.agent.run --name agent_r$(R) --calls results/agent_r$(R)_calls.jsonl

runs-c:
	for r in 1 2 3; do $(MAKE) run-c R=$$r || exit 1; done

runs-e:
	for r in 1 2 3; do $(MAKE) run-e R=$$r || exit 1; done

llm_single: runs-c

agent: runs-e

run-cv:
	$(PY) -m src.baselines.llm_single_verified --name llm_single_verified_r$(R) --calls results/llm_single_verified_r$(R)_calls.jsonl

runs-cv:
	for r in 1 2 3; do $(MAKE) run-cv R=$$r || exit 1; done

llm_single_verified: runs-cv
