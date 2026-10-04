SHELL := /bin/bash
.DEFAULT_GOAL := help

# Auto-detect modern Python binary
PYTHON := $(shell which python3.11 2>/dev/null || which python3 2>/dev/null || which python 2>/dev/null)
PIP := $(PYTHON) -m pip

.PHONY: setup check verify demo test clean help

help:
	@echo "Lumen Agent Platform Lab Automation"
	@echo "  make setup   - Auto-install dependencies cleanly"
	@echo "  make check   - Run preflight diagnostics"
	@echo "  make verify  - Run Boundary 1 (Model Armor) verification"
	@echo "  make demo    - Run Boundary 2 & 3 interactive walkthrough"
	@echo "  make test    - Run automated unit test suite"

setup:
	@echo "[+] Provisioning runtime dependencies using $(PYTHON)..."
	@$(PIP) install --quiet --upgrade pip
	@$(PIP) install --quiet -r requirements.txt pytest
	@echo "[✓] Environment dependencies installed."

check:
	@echo "[+] Running student self-grader and diagnostic checks..."
	@PYTHONPATH=. $(PYTHON) scripts/lab_check.py

verify:
	@test -f token.txt || PYTHONPATH=. $(PYTHON) scripts/generate_tokens.py
	@PYTHONPATH=. $(PYTHON) scripts/test_gateway.py

demo:
	@PYTHONPATH=. $(PYTHON) scripts/test_personas.py

test:
	@PYTHONPATH=. $(PYTHON) -m pytest tests/ -v