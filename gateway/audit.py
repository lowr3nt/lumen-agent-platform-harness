"""
Centralized audit logging facility for the zero-trust AI gateway.
Each event is printed to stdout and, on Cloud Run, written to Cloud Logging
as one structured JSON entry in the lumen-agent-security-audit log.
"""
import os
import json
import logging
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway.audit")

CLOUD_LOGGING_ENABLED = False
cloud_logger = None

# Only bind to Google Cloud Logging when executing inside a Cloud Run container
if os.getenv("K_SERVICE"):
    try:
        from google.cloud import logging as gcp_logging
        client = gcp_logging.Client()
        cloud_logger = client.logger("lumen-agent-security-audit")
        CLOUD_LOGGING_ENABLED = True
    except Exception as e:
        logger.warning(f"Could not initialize Cloud Logging in container: {e}")

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
    Emits security audit telemetry.
    When running in Cloud Run, writes one structured JSON entry to Cloud Logging.
    The same event is always printed to stdout, which Cloud Run also captures.
    When running locally (tests, check scripts), prints only to the terminal.
    """
    payload = {
        "event_type": event_type,
        "principal": principal,
        "groups": groups,
        "action": action,
        "status": status,
        "details": details or {},
    }

    # Human-readable line for console inspection
    print(f"[{severity}] AUDIT: {json.dumps(payload)}")

    # Google Cloud Logging structured emission (Cloud Run only)
    if CLOUD_LOGGING_ENABLED and cloud_logger:
        try:
            cloud_logger.log_struct(payload, severity=severity)
        except Exception as e:
            logger.error(f"Failed to write to Cloud Logging: {e}")
