SHELL := /bin/bash
PROJECT_ID := project-a661dfac-6f3d-4776-a43
GATEWAY_BASE ?= https://lumen-agent-gateway-fpnv56xj2q-uc.a.run.app
GATEWAY_URL ?= $(GATEWAY_BASE)/invoke
HANDLE ?=

# Python detection: prioritize python3.12, python3.11, or default python3
PYTHON := $(shell command -v python3.12 2>/dev/null || command -v python3.11 2>/dev/null || command -v python3 2>/dev/null)

.PHONY: all setup tokens check verify multiturn demo test recover clean

all: setup check verify

tokens:
	@if [ -n "$(HANDLE)" ]; then \
		PYTHONPATH=. $(PYTHON) scripts/generate_tokens.py --handle $(HANDLE); \
	else \
		PYTHONPATH=. $(PYTHON) scripts/generate_tokens.py; \
	fi

setup:
	@echo "[+] Provisioning runtime dependencies using $(PYTHON)..."
	@gcloud config set project $(PROJECT_ID)
	@$(PYTHON) -m pip install -q -r requirements.txt pytest
	@$(MAKE) tokens

check:
	@PYTHONPATH=. $(PYTHON) scripts/lab_check.py

verify: tokens
	@GATEWAY_URL=$(GATEWAY_URL) GATEWAY_TARGET_URL=$(GATEWAY_BASE) PYTHONPATH=. $(PYTHON) scripts/test_gateway.py

multiturn: tokens
	@GATEWAY_TARGET_URL=$(GATEWAY_BASE) GATEWAY_URL=$(GATEWAY_URL) PYTHONPATH=. $(PYTHON) scripts/test_multiturn.py

demo: tokens
	@GATEWAY_TARGET_URL=$(GATEWAY_BASE) GATEWAY_URL=$(GATEWAY_URL) PYTHONPATH=. $(PYTHON) scripts/test_personas.py

test:
	@PYTHONPATH=. $(PYTHON) -m pytest tests/ -v

recover:
	@gcloud config set project $(PROJECT_ID)
	@echo "[+] Active Google Cloud project context restored to $(PROJECT_ID)."

clean:
	@rm -f token*.txt
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "[+] Cleared generated tokens and cache files."