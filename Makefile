PY=python3
VENV=.venv

.PHONY: setup run batch

setup:
	python3 -m venv $(VENV)
	. $(VENV)/bin/activate && pip install -U pip && pip install -r requirements.txt

run:
	$(PY) run.py

batch:
	bash scripts/run_batch.sh
