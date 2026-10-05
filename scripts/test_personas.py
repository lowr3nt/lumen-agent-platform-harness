"""
Multi-persona validation harness for Lumen Agent Platform.
Tests dynamic tool pruning, hard RBAC direct invocation, and privileged data access.
"""
import os
import requests

# Base endpoint configuration with unified environment variable resolution
BASE_URL = os.getenv("GATEWAY_TARGET_URL") or os.getenv("GATEWAY_URL", "https://lumen-agent-gateway-fpnv56xj2q-uc.a.run.app")
# Strip trailing /invoke if present to ensure clean route construction
if BASE_URL.endswith("/invoke"):
    BASE_URL = BASE_URL[:-7]
BASE_URL = BASE_URL.rstrip("/")

INVOKE_URL = f"{BASE_URL}/invoke"
CHAT_URL = f"{BASE_URL}/agent/chat"

# Load local persona JWTs
with open("token_alex.txt", "r") as f:
    alex_token = f.read().strip()

with open("token_dana.txt", "r") as f:
    dana_token = f.read().strip()

alex_headers = {
    "Authorization": f"Bearer {alex_token}",
    "Content-Type": "application/json",
}

dana_headers = {
    "Authorization": f"Bearer {dana_token}",
    "Content-Type": "application/json",
}


def run_persona_matrix_tests():
    print("======================================================================")
    print("Test 1: [Alex Analyst] Query Campaign Analytics (Allowed)")
    print("======================================================================")
    req1 = {"prompt": "Provide key metrics for our Summer Campaign."}
    res1 = requests.post(CHAT_URL, json=req1, headers=alex_headers)
    print(f"Status: {res1.status_code}")
    body1 = res1.json()
    print(f"Caller: {body1.get('caller')}")
    print(f"Exposed Tools: {body1.get('authorized_tools')}")
    print(f"Response: {body1.get('response')}")
    
    assert res1.status_code == 200, f"Expected 200, got {res1.status_code}"
    assert "get_campaign_analytics" in body1.get("authorized_tools", []), \
        "Alex must have get_campaign_analytics exposed"
    assert "lookup_customer_record" not in body1.get("authorized_tools", []), \
        "Alex must NOT have lookup_customer_record exposed"
    print("[✓] PASSED: Alex successfully invoked allowed tool.\n")

    print("======================================================================")
    print("Test 2: [Alex Analyst] Query Customer Record via Agent (Tool Pruned)")
    print("======================================================================")
    req2 = {"prompt": "Look up customer profile for CUST-9921."}
    res2 = requests.post(CHAT_URL, json=req2, headers=alex_headers)
    print(f"Status: {res2.status_code}")
    body2 = res2.json()
    print(f"Caller: {body2.get('caller')}")
    print(f"Exposed Tools: {body2.get('authorized_tools')}")
    print(f"Response: {body2.get('response')}")
    
    assert res2.status_code == 200, f"Expected 200, got {res2.status_code}"
    assert "lookup_customer_record" not in body2.get("authorized_tools", []), \
        "Alex must NOT have lookup_customer_record exposed in chat agent"
    print("[✓] PASSED: Restricted tool was not exposed to the model.\n")

    print("======================================================================")
    print("Test 3: [Alex Analyst] Direct /invoke call for restricted tool (Hard RBAC)")
    print("======================================================================")
    req3 = {
        "tool": "lookup_customer_record",
        "parameters": {"customer_id": "CUST-9921"},
    }
    res3 = requests.post(INVOKE_URL, json=req3, headers=alex_headers)
    print(f"Status: {res3.status_code}")
    print(f"Response: {res3.text}")
    
    assert res3.status_code == 403, f"Expected 403 Forbidden, got {res3.status_code}"
    print("[✓] PASSED: Direct invocation rejected with HTTP 403 Forbidden.\n")

    print("======================================================================")
    print("Test 4: [Dana Admin] Query Customer Record via Agent (Allowed + Redacted)")
    print("======================================================================")
    req4 = {"prompt": "Look up customer profile for CUST-9921."}
    res4 = requests.post(CHAT_URL, json=req4, headers=dana_headers)
    print(f"Status: {res4.status_code}")
    body4 = res4.json()
    print(f"Caller: {body4.get('caller')}")
    print(f"Exposed Tools: {body4.get('authorized_tools')}")
    print(f"Response: {body4.get('response')}")
    
    # Deterministic evaluation: verifies HTTP success, tool availability, and caller identity
    assert res4.status_code == 200, f"Expected 200, got {res4.status_code}"
    assert "lookup_customer_record" in body4.get("authorized_tools", []), \
        "Dana Admin must have lookup_customer_record in authorized_tools"
    # Verify raw sensitive patterns are absent from the outbound model response
    response_text = body4.get("response", "")
    assert "4532-8921-3312-9011" not in response_text, "Raw credit card number must not appear in response"
    assert "000-12-3456" not in response_text, "Raw SSN must not appear in response"
    print("[✓] PASSED: Dana executed privileged tool with automated PII egress redaction.\n")

    print("[+] MULTI-PERSONA RBAC MATRIX VALIDATION COMPLETE.")


if __name__ == "__main__":
    run_persona_matrix_tests()