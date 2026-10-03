import json
import re
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1
from google import genai
from google.genai import types

app = FastAPI(title="Lumen Zero-Trust Agent Gateway with Vertex AI & Model Armor")
security = HTTPBearer()

# --- Configuration ---
PROJECT_ID = "project-a661dfac-6f3d-4776-a43"
LOCATION = "us-central1"
MODEL_ARMOR_ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"
TEMPLATE_PATH = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/retail-agent-defense"

# Clients
armor_client = modelarmor_v1.ModelArmorClient(
    client_options=ClientOptions(api_endpoint=MODEL_ARMOR_ENDPOINT)
)

genai_client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION,
)

# --- RBAC Policy Matrix ---
TOOL_PERMISSIONS = {
    "get_campaign_analytics": ["Lumen-Marketing-Analysts", "Lumen-Data-Admins"],
    "lookup_customer_record": ["Lumen-Data-Admins"],
    "purge_customer_data": ["Lumen-Data-Admins"],
}

# --- Tool Implementations ---
def get_campaign_analytics(campaign_name: str) -> dict:
    """Retrieve performance statistics for a marketing campaign."""
    return {
        "campaign_id": "CAMP-SUMMER-2026",
        "campaign_name": campaign_name,
        "impressions": 452100,
        "clicks": 18230,
        "ctr": "4.03%",
    }

def lookup_customer_record(customer_id: str) -> dict:
    """Retrieve customer profile and account details for audits."""
    return {
        "customer_id": customer_id,
        "full_name": "Jordan Hayes",
        "email": "jordan.hayes@example.com",
        "credit_card": "4532-8921-3312-9011",
        "ssn": "000-12-3456",
        "notes": "Customer requested account audit.",
    }

def purge_customer_data(customer_id: str) -> dict:
    """Delete customer records from all operational data stores."""
    return {"status": f"Customer data for {customer_id} purged successfully."}

TOOL_REGISTRY = {
    "get_campaign_analytics": get_campaign_analytics,
    "lookup_customer_record": lookup_customer_record,
    "purge_customer_data": purge_customer_data,
}

class AgentInvocationRequest(BaseModel):
    prompt: str

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    try:
        return jwt.get_unverified_claims(credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed OIDC token",
        )

def sanitize_inbound_prompt(prompt_text: str):
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=TEMPLATE_PATH,
        user_prompt_data=modelarmor_v1.DataItem(text=prompt_text),
    )
    response = armor_client.sanitize_user_prompt(request=request)
    result = response.sanitization_result

    if result.filter_match_state.name == "MATCH_FOUND":
        triggered = list(result.filter_results.keys())
        if "pi_and_jailbreak" in triggered:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Safety Policy Violation: Prompt flagged by Model Armor ({', '.join(triggered)}).",
            )

def redact_sensitive_pii(text: str) -> str:
    text = re.sub(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]", text)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)
    return text

def sanitize_outbound_response(raw_text: str) -> str:
    request = modelarmor_v1.SanitizeModelResponseRequest(
        name=TEMPLATE_PATH,
        model_response_data=modelarmor_v1.DataItem(text=raw_text),
    )
    armor_client.sanitize_model_response(request=request)
    return redact_sensitive_pii(raw_text)

@app.post("/agent/chat")
def agent_chat(req: AgentInvocationRequest, claims: Dict = Depends(verify_token)):
    user_email = claims.get("sub", "unknown_user")
    user_groups: List[str] = claims.get("groups", [])

    # 1. Inbound Model Armor Check
    sanitize_inbound_prompt(req.prompt)

    # 2. RBAC Tool Filtering: Only provide tools the caller is authorized to use
    allowed_tools = [
        TOOL_REGISTRY[name]
        for name, groups in TOOL_PERMISSIONS.items()
        if any(grp in groups for grp in user_groups)
    ]

    # 3. Create Gemini Chat Session with caller's authorized tools
    chat = genai_client.chats.create(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            tools=allowed_tools,
            temperature=0.0,
            system_instruction=(
                "You are an enterprise AI assistant for Lumen Retail. "
                "Use the provided tools whenever appropriate to fulfill requests. "
                "Be concise and factual."
            ),
        ),
    )

    # 4. Model Call & Tool Execution
    response = chat.send_message(req.prompt)
    model_reply = response.text or ""

    # 5. Outbound Model Armor & PII Redaction
    sanitized_reply = sanitize_outbound_response(model_reply)

    return {
        "status": "success",
        "caller": user_email,
        "authorized_tools": [fn.__name__ for fn in allowed_tools],
        "response": sanitized_reply,
    }