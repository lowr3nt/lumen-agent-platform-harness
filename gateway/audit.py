import json
from typing import Any, Dict, List, Optional
from google.cloud import logging as cloud_logging

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"

# Initialize Google Cloud Logging Client with explicit project ID
client = cloud_logging.Client(project=PROJECT_ID)
# Connect structured logger to GCP log name
logger = client.logger("lumen-agent-security-audit")

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

    # Write structured entry to GCP Cloud Logging
    try:
        logger.log_struct(payload, severity=severity)
    except Exception as e:
        print(f"[!] Warning: Failed to send log to GCP Cloud Logging: {e}")

    # Print to local console for immediate developer visibility
    print(f"[{severity}] AUDIT: {json.dumps(payload)}")