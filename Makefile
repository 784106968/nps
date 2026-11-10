.PHONY: install dev lint fmt test test-all probe verify run clean

PY ?= python

install:
	$(PY) -m pip install -e .

dev:
	$(PY) -m pip install -e ".[dev]"

lint:
	$(PY) -m ruff check .

fmt:
	$(PY) -m ruff format .

test:
	$(PY) -m pytest -m "not requires_npcap"

test-all:
	$(PY) -m pytest

probe:
	$(PY) scripts/probe_pcap.py

verify:
	$(PY) scripts/verify_p0.py

run:
	$(PY) -m nps --list-interfaces

clean:
	-$(PY) -c "import shutil,pathlib;[shutil.rmtree(p,ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	-$(PY) -c "import shutil;shutil.rmtree('.pytest_cache',ignore_errors=True);shutil.rmtree('.ruff_cache',ignore_errors=True)"
