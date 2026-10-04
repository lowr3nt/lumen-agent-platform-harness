# Lumen Agent Platform Harness

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/lowr3nt/lumen-agent-platform-harness)

A secure, zero-trust AI agent gateway deployed on Google Cloud Platform. Demonstrates defense-in-depth security patterns for enterprise LLM agents: Model Armor ingress filtering, dynamic LLM tool pruning, deterministic RBAC, outbound egress DLP sanitization, and automated SIEM observability.

---

## Architecture Quick Reference

* **Ingress Guardrails:** Google Cloud Model Armor (`retail-agent-defense`)
* **API Gateway:** FastAPI on Cloud Run (`lumen-agent-gateway`)
* **Cognitive Routing:** Vertex AI Gemini 1.5 Pro with dynamic tool pruning
* **State Persistence:** Google Cloud Firestore (multi-turn sessions)
* **Data Layer:** Snowflake enterprise customer and campaign adapter
* **Egress Guardrails:** Regex and pattern-based DLP engine (`gateway/dlp.py`)
* **SIEM & Alerting:** Cloud Logging structured audits + Cloud Monitoring alert policies

---

## Student Quickstart

### 1. Launch Environment
Click the **Open in Cloud Shell** button above, or clone locally and run:
```bash
make setup