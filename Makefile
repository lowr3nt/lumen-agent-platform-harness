.PHONY: help setup test check verify demo deploy clean

SHELL := /bin/bash
PROJECT_ID ?= $(shell gcloud config get-value project 2>/dev/null)
REGION ?= us-central1
SERVICE_NAME ?= lumen-agent-gateway

help:
	@echo "Lumen Agent Platform Harness - Student & Evaluation Interface"
	@echo "------------------------------------------------------------"
	@echo "make setup    - Install dependencies and prepare local environment"
	@echo "make check    - Run student self-grader and environment diagnostics"
	@echo "make test     - Run local unit tests (DLP regex & adapter sanitization)"
	@echo "make verify   - Run Model Armor inbound defense verification"
	@echo "make demo     - Execute live multi-persona RBAC & DLP matrix (Exam mode)"
	@echo "make deploy   - Build and deploy gateway revision to Cloud Run"
	@echo "make clean    - Remove build artifacts, pycache, and temporary tokens"

setup:
	@echo "[+] Verifying Python environment..."
	python3 -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required'"
	@echo "[+] Installing pinned dependencies..."
	pip install --upgrade pip
	pip install -r requirements.txt
	@echo "[✓] Setup complete. Active Project: $(PROJECT_ID)"

check:
	@echo "[+] Running student self-grader and diagnostic checks..."
	PYTHONPATH=. python scripts/lab_check.py

test:
	@echo "[+] Running local test suite..."
	PYTHONPATH=. pytest tests/

verify:
	@echo "[+] Verifying Model Armor policies & prompt-injection filters..."
	PYTHONPATH=. python scripts/test_model_armor.py

demo:
	@echo "[+] Executing end-to-end multi-persona RBAC & DLP live validation..."
	PYTHONPATH=. python scripts/test_personas.py

deploy:
	@echo "[+] Submitting Cloud Build for Cloud Run deployment..."
	gcloud builds submit --config=cloudbuild.yaml
	@echo "[✓] Deployment triggered to $(SERVICE_NAME) in $(REGION)."

clean:
	@echo "[+] Cleaning temporary artifacts..."
	rm -rf __pycache__ tests/__pycache__ gateway/__pycache__ gateway/adapters/__pycache__
	rm -f .coverage token*.txt validation_report.txt
	@echo "[✓] Workspace cleaned."
