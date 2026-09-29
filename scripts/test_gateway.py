import os
import sys
import httpx

GATEWAY_URL = "http://localhost:8080/v1/tools/execute"
TOKEN_FILE = "token.txt"

if not os.path.exists(TOKEN_FILE):
    print(f"[-] Error: {TOKEN_FILE} not found. Please create it with your token string.")
    sys.exit(1)

with open(TOKEN_FILE, "r", encoding="utf-8") as f:
    token = f.read().strip()

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

def invoke_tool(test_name: str, tool_name: str, arguments: dict):
    print(f"\n--- {test_name}: Invoking '{tool_name}' ---")
    payload = {"tool_name": tool_name, "arguments": arguments}
    
    try:
        response = httpx.post(GATEWAY_URL, json=payload, headers=headers, timeout=10.0)
        print(f"Status Code: {response.status_code}")
        print("Response Body:")
        print(response.json())
    except httpx.HTTPError as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    # Test 1: Allowed Tool (Lumen-Marketing-Analysts)
    invoke_tool(
        test_name="Test 1 (Expected 200 OK)",
        tool_name="get_campaign_analytics",
        arguments={"campaign_id": "CAMP-SUMMER-2026"}
    )

    # Test 2: Forbidden Tool (Admin only - Should be rejected for Analysts)
    invoke_tool(
        test_name="Test 2 (Expected 403 Forbidden)",
        tool_name="purge_customer_data",
        arguments={"customer_id": "CUST-9912"}
    )

    # Test 3: Unregistered / Unknown Tool
    invoke_tool(
        test_name="Test 3 (Expected 403 Forbidden)",
        tool_name="unauthorized_shadow_tool",
        arguments={}
    )