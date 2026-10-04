#!/usr/bin/env python3
"""
Lumen Agent Platform Harness - Student Readiness & Lab Assessment Validator
Usage: python scripts/lab_check.py
"""

import sys
import os
import subprocess
import importlib.util

# Ensure project root is always in Python search path regardless of where script is invoked
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_header(title):
    print(f"\n{BLUE}{BOLD}=== {title} ==={RESET}")

def report_check(name, passed, details=""):
    symbol = f"{GREEN}[✓]{RESET}" if passed else f"{RED}[✗]{RESET}"
    msg = f"{symbol} {name}"
    if details:
        msg += f" ({details})"
    print(msg)
    return passed

def check_python_version():
    v = sys.version_info
    passed = v.major == 3 and v.minor >= 11
    return report_check(
        "Python Runtime >= 3.11", 
        passed, 
        f"Detected {v.major}.{v.minor}.{v.micro}"
    )

def check_dependencies():
    required = [
        ("fastapi", "FastAPI"),
        ("google.cloud.modelarmor_v1", "Model Armor SDK"),
        ("google.cloud.firestore", "Firestore SDK"),
        ("jose", "Python-JOSE (JWT)"),
        ("pytest", "Pytest Test Runner"),
        ("requests", "Requests HTTP Client")
    ]
    all_passed = True
    for mod, label in required:
        installed = importlib.util.find_spec(mod) is not None
        if not report_check(f"Dependency '{label}'", installed):
            all_passed = False
    return all_passed

def check_gcloud_auth():
    try:
        res = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True, text=True, check=True
        )
        project = res.stdout.strip()
        passed = bool(project and project != "(unset)")
        return report_check("GCP Active Project Bound", passed, project if passed else "None set")
    except Exception as e:
        return report_check("GCP CLI Tooling Accessible", False, str(e))

def check_dlp_engine():
    try:
        from gateway.dlp import redact_sensitive_payload
        sample = {
            "name": "Jordan Hayes",
            "email": "jordan.hayes@example.com",
            "credit_card": "4532-7589-2341-9021",
            "ssn": "987-65-4321"
        }
        analyst_out, _ = redact_sensitive_payload(
            sample, 
            principal="alex.analyst@lumenretail.lab", 
            groups=["Lumen-Marketing-Analysts"]
        )
        admin_out, _ = redact_sensitive_payload(
            sample, 
            principal="dana.admin@lumenretail.lab", 
            groups=["Lumen-Data-Admins"]
        )
        
        redaction_ok = (
            "[REDACTED_CREDIT_CARD]" in str(analyst_out) and
            "[REDACTED_SSN]" in str(analyst_out) and
            "[REDACTED_EMAIL]" in str(analyst_out) and
            "[REDACTED_CREDIT_CARD]" in str(admin_out) and
            "[REDACTED_SSN]" in str(admin_out) and
            "jordan.hayes@example.com" in str(admin_out)
        )
        return report_check("Egress DLP Masking Logic", redaction_ok, "Persona rules validated")
    except Exception as e:
        return report_check("Egress DLP Masking Logic", False, str(e))

def check_cloud_run_gateway():
    try:
        res = subprocess.run(
            ["gcloud", "run", "services", "describe", "lumen-agent-gateway", 
             "--region=us-central1", "--format=value(status.url)"],
            capture_output=True, text=True
        )
        url = res.stdout.strip()
        passed = bool(url and url.startswith("https://"))
        return report_check("Cloud Run Deployment", passed, url if passed else "Not deployed")
    except Exception as e:
        return report_check("Cloud Run Deployment", False, str(e))

def main():
    print(f"{BOLD}Lumen Agent Platform - Student Self-Grader & Lab Diagnostics{RESET}")
    print("Evaluating current development environment...")

    checks = []
    print_header("1. Environment & Runtimes")
    checks.append(check_python_version())
    checks.append(check_dependencies())

    print_header("2. Google Cloud Platform Identity")
    checks.append(check_gcloud_auth())
    checks.append(check_cloud_run_gateway())

    print_header("3. Core Security Modules")
    checks.append(check_dlp_engine())

    passed_count = sum(1 for c in checks if c)
    total_count = len(checks)

    print(f"\n{BOLD}Diagnostic Summary: {passed_count}/{total_count} checks passed.{RESET}")
    if passed_count == total_count:
        print(f"{GREEN}{BOLD}[✓] Lab environment is validated and ready for evaluation/demo.{RESET}\n")
        sys.exit(0)
    else:
        print(f"{YELLOW}[!] Some checks failed. Resolve highlighted issues before oral exam.{RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
