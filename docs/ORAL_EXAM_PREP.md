# Lumen Agent Platform: Technical Defense & Oral Exam Guide

Use this document to prepare for technical walkthroughs, architecture defense, and live code extensions.

---

## 1. Core Architectural Pillars

* **Inbound Perimeter:** Model Armor (`retail-agent-defense`) intercepting injections and jailbreaks before model inference.
* **Gateway Ingress:** FastAPI on Cloud Run with JWT claims validation.
* **Cognitive Layer:** Vertex AI Gemini with dynamic tool pruning based on user roles.
* **Data Access Layer:** Snowflake adapter with structured customer and campaign records.
* **Outbound Perimeter:** Egress DLP engine masking credit cards, SSNs, and non-admin emails.
* **Observability:** Structured audit logs streamed to Cloud Logging and evaluated by Cloud Monitoring alert policies.

---

## 2. Five Core Oral Defense Questions

### Q1: Why is prompt-context tool pruning insufficient as a standalone security control?
Tool pruning prevents an LLM from knowing about or hallucinating unauthorized tool calls, but it offers zero protection against a direct HTTP attack targeting `/invoke`. True defense-in-depth requires both context pruning for model safety and deterministic gateway RBAC for boundary defense.

### Q2: Why implement both Model Armor and Gateway Egress DLP?
Model Armor inspects untrusted inputs entering the system to stop prompt injection. Egress DLP inspects outgoing responses leaving the system to prevent confidential customer data leakage.

### Q3: How is tenant session isolation maintained across turns?
Multi-turn conversational memory is stored in Firestore with composite keys (`session_id` + `tenant_id`). The gateway validates session ownership against the caller's JWT claims before loading past turns into the model context.

### Q4: How does the platform detect and respond to coordinated attacks?
Security events write structured JSON payloads to Cloud Logging under `lumen-agent-security-audit`. Cloud Monitoring policies watch log-based metrics and trigger alerts when injection counts exceed 0 or authorization denials spike within a 5-minute window.

### Q5: How would you add a new third-party adapter (e.g., Databricks or BigQuery)?
1. Add an adapter module under `gateway/adapters/`.
2. Register the tool in `gateway/server.py`.
3. Update the role-to-tool RBAC mapping matrix.
4. Pass adapter output through `redact_sensitive_payload()` in `gateway/dlp.py`.

---

## 3. Live Demonstration Protocol (30 Seconds)

```bash
make check    # Demonstrates environment readiness and passing DLP logic
make demo     # Executes live multi-persona RBAC and egress validation against Cloud Run

#### 3. Update `README.md`
Open the existing `README.md` in your project root and replace its contents with:

```markdown
# Lumen Agent Platform Harness

A secure, zero-trust AI agent gateway deployed on Google Cloud Platform. Demonstrates defense-in-depth security patterns for enterprise LLM agents: Model Armor ingress filtering, dynamic LLM tool pruning, deterministic RBAC, outbound egress DLP sanitization, and automated SIEM observability.

---

## Architecture Quick Reference

* **Ingress Guardrails:** Google Cloud Model Armor (`retail-agent-defense`)
* **API Gateway:** FastAPI on Cloud Run (`lumen-agent-gateway`)
* **Cognitive Routing:** Vertex AI Gemini with dynamic tool pruning
* **State Persistence:** Google Cloud Firestore (multi-turn sessions)
* **Data Layer:** Snowflake enterprise customer and campaign adapter
* **Egress Guardrails:** Regex and pattern-based DLP engine (`gateway/dlp.py`)
* **SIEM & Alerting:** Cloud Logging structured audits + Cloud Monitoring alert policies

---

## Quickstart

### 1. Verify Readiness
```bash
make check
### Run test suite
make test
### Execute multi-persona live demonstration
make demo


COMMAND REFERENCE

Command, Action
make setup, Install dependencies and verify Python version
make check, Run student diagnostics and environment validation
make test, Execute local unit tests for DLP and adapters
make verify, Validate inbound Model Armor threat interception
make demo, Run live multi-persona RBAC and egress matrix against Cloud Run
make deploy, Submit Cloud Build to package and update Cloud Run
make clean, "Purge pycache, build artifacts, and test tokens"

---

Once those files are saved, run `git status` in your terminal to review what has changed.

<FollowUp label="Want to cancel out of the prompt with Ctrl+C and check git status?" query="I hit Ctrl+C and saved the files. Here is the output from git status: "/>