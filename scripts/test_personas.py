import requests
import os

CLOUD_RUN_BASE = os.getenv(
    "GATEWAY_TARGET_URL",
    "https://lumen-agent-gateway-671703121200.us-central1.run.app",
)
AGENT_URL = f"{CLOUD_RUN_BASE}/agent/chat"
INVOKE_URL = f"{CLOUD_RUN_BASE}/invoke"

with open("token_dana.txt", "r") as f:
    token_dana = f.read().strip()

with open("token_alex.txt", "r") as f:
    token_alex = f.read().strip()

def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def log_test_header(title: str):
    print(f"\n{'='*60}")
    print(title)
    print(f"{'='*60}")

# --- Test Case 1: Alex requests permitted marketing metrics ---
log_test_header("Test 1: [Alex Analyst] Query Campaign Analytics (Allowed)")
res = requests.post(
    AGENT_URL,
    json={"prompt": "What were the results of the summer marketing campaign?"},
    headers=auth_header(token_alex),
)
print(f"Status: {res.status_code}")
data = res.json()
print(f"Caller: {data.get('caller')}")
print(f"Exposed Tools: {data.get('authorized_tools')}")
print(f"Response: {data.get('response')}")
assert res.status_code == 200
assert data.get("authorized_tools") == ["get_campaign_analytics"]
assert "452,100" in data.get("response")
print("[✓] PASSED: Alex successfully invoked allowed tool.")

# --- Test Case 2: Alex requests restricted customer records via Agent ---
log_test_header("Test 2: [Alex Analyst] Query Customer Record via Agent (Tool Pruned)")
res = requests.post(
    AGENT_URL,
    json={"prompt": "Can you look up customer profile CUST-9921 for me?"},
    headers=auth_header(token_alex),
)
print(f"Status: {res.status_code}")
data = res.json()
print(f"Caller: {data.get('caller')}")
print(f"Exposed Tools: {data.get('authorized_tools')}")
print(f"Response: {data.get('response')}")
assert res.status_code == 200
assert "lookup_customer_record" not in data.get("authorized_tools")
# Verify that Gemini indicates it does not have access or cannot perform the lookup
print("[✓] PASSED: Restricted tool was not exposed to the model.")

# --- Test Case 3: Alex attempts direct invocation of restricted tool ---
log_test_header("Test 3: [Alex Analyst] Direct /invoke call for restricted tool (Hard RBAC)")
res = requests.post(
    INVOKE_URL,
    json={"tool": "lookup_customer_record", "prompt": "Audit lookup CUST-9921"},
    headers=auth_header(token_alex),
)
print(f"Status: {res.status_code}")
print(f"Response: {res.json()}")
assert res.status_code == 403
assert "Access Denied" in res.json().get("detail", "")
print("[✓] PASSED: Direct invocation rejected with HTTP 403 Forbidden.")

# --- Test Case 4: Dana requests customer record via Agent (Allowed) ---
log_test_header("Test 4: [Dana Admin] Query Customer Record via Agent (Allowed + Redacted)")
res = requests.post(
    AGENT_URL,
    json={"prompt": "Can you look up customer profile CUST-9921 for me?"},
    headers=auth_header(token_dana),
)
print(f"Status: {res.status_code}")
data = res.json()
print(f"Caller: {data.get('caller')}")
print(f"Exposed Tools: {data.get('authorized_tools')}")
print(f"Response: {data.get('response')}")
assert res.status_code == 200
assert "lookup_customer_record" in data.get("authorized_tools")
assert "[REDACTED_CREDIT_CARD]" in data.get("response")
assert "[REDACTED_SSN]" in data.get("response")
print("[✓] PASSED: Dana executed privileged tool with automated PII egress redaction.")

print("\n[+] MULTI-PERSONA RBAC MATRIX VALIDATION COMPLETE.")