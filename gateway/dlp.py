"""
Egress Data Loss Prevention (DLP) & Sanitization Engine.
"""
import re
from typing import Any, Dict, List, Tuple
from gateway.audit import log_audit_event

def redact_sensitive_payload(
    data: Any, principal: str, groups: List[str]
) -> Tuple[Any, int]:
    """
    Recursively inspects dict/list structures or strings, applying redactions:
      - Credit Cards & SSNs: Redacted for all personas
      - Emails & Phones: Redacted unless user belongs to 'Lumen-Data-Admins'
    """
    redaction_count = 0
    is_admin = "Lumen-Data-Admins" in groups

    def _sanitize_string(val: str) -> str:
        nonlocal redaction_count
        # 1. Credit Cards (Luhn/standard formats)
        val, c_cc = re.subn(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]", val)
        # 2. SSN formats
        val, c_ssn = re.subn(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", val)
        redaction_count += (c_cc + c_ssn)

        # 3. Non-admin masking for emails and phone numbers
        if not is_admin:
            val, c_email = re.subn(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
                "[REDACTED_EMAIL]",
                val,
            )
            val, c_phone = re.subn(
                r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                "[REDACTED_PHONE]",
                val,
            )
            redaction_count += (c_email + c_phone)

        return val

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        elif isinstance(node, list):
            return [_walk(item) for item in node]
        elif isinstance(node, str):
            return _sanitize_string(node)
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