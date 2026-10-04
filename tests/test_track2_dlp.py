import pytest
from gateway.adapters.snowflake import query_customer_record
from gateway.dlp import redact_sensitive_payload

def test_snowflake_query_raw():
    record = query_customer_record("CUST-9921")
    assert record["customer_id"] == "CUST-9921"
    assert record["credit_card"] == "4532-8921-3312-9011"
    assert record["ssn"] == "000-12-3456"
    assert "_source" in record

def test_dlp_redacts_for_non_admin():
    raw = query_customer_record("CUST-9921")
    sanitized, count = redact_sensitive_payload(raw, "analyst@test.com", ["Lumen-Marketing-Analysts"])
    
    assert count >= 4
    assert sanitized["credit_card"] == "[REDACTED_CREDIT_CARD]"
    assert sanitized["ssn"] == "[REDACTED_SSN]"
    assert sanitized["email"] == "[REDACTED_EMAIL]"
    assert sanitized["phone"] == "[REDACTED_PHONE]"
    assert sanitized["customer_id"] == "CUST-9921"

def test_dlp_allows_email_for_admin_but_masks_financials():
    raw = query_customer_record("CUST-9921")
    sanitized, count = redact_sensitive_payload(raw, "admin@test.com", ["Lumen-Data-Admins"])
    
    assert sanitized["credit_card"] == "[REDACTED_CREDIT_CARD]"
    assert sanitized["ssn"] == "[REDACTED_SSN]"
    assert sanitized["email"] == "jordan.hayes@example.com"
    assert sanitized["phone"] == "+1-555-019-2834"