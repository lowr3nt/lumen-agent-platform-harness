import uuid
import requests
import os

CLOUD_RUN_BASE = os.getenv(
    "GATEWAY_TARGET_URL",
    "https://lumen-agent-gateway-671703121200.us-central1.run.app",
)
AGENT_URL = f"{CLOUD_RUN_BASE}/agent/chat"

with open("token_dana.txt", "r") as f:
    token_dana = f.read().strip()

session_id = f"test-sess-{uuid.uuid4().hex[:8]}"
headers = {
    "Authorization": f"Bearer {token_dana}",
    "Content-Type": "application/json",
    "x-session-id": session_id,
}

print(f"Testing Stateful Multi-Turn Session: {session_id}\n")

# Turn 1: Establish context
print("--- Turn 1: Lookup customer profile ---")
res1 = requests.post(
    AGENT_URL,
    json={"prompt": "Can you retrieve the details for customer CUST-9921?"},
    headers=headers,
)
print(f"Status: {res1.status_code}")
print(f"Response 1: {res1.json().get('response')}\n")

# Turn 2: Refer back using anaphoric reference ("What was their email again?")
print("--- Turn 2: Query antecedent without repeating customer ID ---")
res2 = requests.post(
    AGENT_URL,
    json={"prompt": "What was their email address again?"},
    headers=headers,
)
print(f"Status: {res2.status_code}")
print(f"Response 2: {res2.json().get('response')}\n")

assert "jordan.hayes@example.com" in res2.json().get("response", "")
print("[✓] PASSED: Multi-turn session memory persisted and resolved antecedent across turns.")