"""
Egress Data Loss Prevention (DLP) & Sanitization Engine.
Provides deterministic egress masking for sensitive PII/SPI fields.
"""
import re
from typing import Any, List, Optional, Tuple
from gateway.audit import log_audit_event

# ==============================================================================
# STUDENT EXERCISE: Read, then extend
# ==============================================================================
# The baseline patterns below detect standard credit cards, SSNs, emails, and phones.
# Exercise: Extend this engine to support International Bank Account Numbers (IBAN).

PATTERN_CREDIT_CARD = r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
PATTERN_SSN = r"\b\d{3}-\d{2}-\d{4}\b"
PATTERN_EMAIL = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b"
PATTERN_PHONE = r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"


def mask_text(
    val: str,
    is_admin: bool = False
) -> Tuple[str, int]:
    """
    Applies DLP regex masks to a raw string based on caller privilege:
      - Credit Cards & SSNs: Masked unconditionally for ALL callers.
      - Emails & Phones: Masked for standard analysts; retained for Lumen-Data-Admins.
    """
    total_redactions = 0

    # 1. Credit Card Redaction (Universal)
    val, cc_count = re.subn(PATTERN_CREDIT_CARD, "[REDACTED_CREDIT_CARD]", val)
    total_redactions += cc_count

    # 2. SSN Redaction (Universal)
    val, ssn_count = re.subn(PATTERN_SSN, "[REDACTED_SSN]", val)
    total_redactions += ssn_count

    # 3. Non-admin masking for Contact Info (Email / Phone)
    if not is_admin:
        val, email_count = re.subn(PATTERN_EMAIL, "[REDACTED_EMAIL]", val)
        val, phone_count = re.subn(PATTERN_PHONE, "[REDACTED_PHONE]", val)
        total_redactions += (email_count + phone_count)

    return val, total_redactions


def redact_sensitive_payload(
    data: Any,
    principal: str = "unknown_principal",
    groups: Optional[List[str]] = None,
) -> Tuple[Any, int]:
    """
    Recursively inspects strings, dictionaries, or lists, applying DLP redactions.
    Returns (sanitized_data, redaction_count) for compatibility with unit tests.
    """
    if groups is None:
        groups = []

    redaction_count = 0
    is_admin = "Lumen-Data-Admins" in groups

    def _walk(node: Any) -> Any:
        nonlocal redaction_count
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        elif isinstance(node, list):
            return [_walk(item) for item in node]
        elif isinstance(node, str):
            masked_str, count = mask_text(node, is_admin=is_admin)
            redaction_count += count
            return masked_str
        return node

    sanitized_data = _walk(data)

    if redaction_count > 0:
        log_audit_event(
            event_type="SECURITY_PII_REDACTED",
            severity="NOTICE",
            principal=principal,
            groups=groups,
            action="egress_dlp_sanitization",
            status="REDACTED",
            details={
                "total_redactions": redaction_count,
                "is_admin_override": is_admin,
            },
        )

    return sanitized_data, redaction_count