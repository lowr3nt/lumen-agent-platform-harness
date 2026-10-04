import json
from typing import Any, Dict, List, Optional
from google.cloud import logging as cloud_logging

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"

# Initialize Google Cloud Logging Client gracefully
try:
    client = cloud_logging.Client(project=PROJECT_ID)
    logger = client.logger("lumen-agent-security-audit")
except Exception as e:
    # Graceful fallback for local offline testing / CI without ADC
    client = None
    logger = None
    print(f"[*] Notice: Running without GCP Cloud Logging credentials: {e}")

def log_audit_event(
    event_type: str,
    severity: str,
    principal: str,
    groups: List[str],
    action: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
):
    """
    Emits a structured JSON audit log entry directly to Google Cloud Logging.
    """
    payload = {
        "event_type": event_type,
        "principal": principal,
        "groups": groups,
        "action": action,
        "status": status,
        "details": details or {},
    }

    # Write structured entry to GCP Cloud Logging if connected
    if logger:
        try:
            logger.log_struct(payload, severity=severity)
        except Exception as e:
            print(f"[!] Warning: Failed to send log to GCP Cloud Logging: {e}")

    # Always output to local stdout for developer and container log capture
    print(f"[{severity}] AUDIT: {json.dumps(payload)}")