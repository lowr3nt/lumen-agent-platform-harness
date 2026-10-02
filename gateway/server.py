import json
import re
from typing import Dict, List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1

app = FastAPI(title="Lumen Zero-Trust Agent Gateway with Bi-Directional Model Armor")
security = HTTPBearer()

# --- Configuration ---
OKTA_DOMAIN = "trial-6804593.okta.com"
AUDIENCE = "api://default"

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"
LOCATION = "us-central1"
TEMPLATE_ID = "retail-agent-defense"
MODEL_ARMOR_ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"
TEMPLATE_PATH = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/{TEMPLATE_ID}"

# Initialize Model Armor Client
armor_client = modelarmor_v1.ModelArmorClient(
    client_options=ClientOptions(api_endpoint=MODEL_ARMOR_ENDPOINT)
)

TOOL_PERMISSIONS = {
    "get_campaign_analytics": ["Lumen-Marketing-Analysts", "Lumen-Data-Admins"],
    "purge_customer_data": ["Lumen-Data-Admins"],
    "lookup_customer_record": ["Lumen-Data-Admins"],
}

class ToolInvocationRequest(BaseModel):
    tool: str
    prompt: Optional[str] = None
    parameters: Optional[Dict] = None

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    token = credentials.credentials
    try:
        claims = jwt.get_unverified_claims(token)
        return claims
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed OIDC token",
        )

def sanitize_inbound_prompt(prompt_text: str):
    """Enforces prompt defense using Model Armor."""
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=TEMPLATE_PATH,
        user_prompt_data=modelarmor_v1.DataItem(text=prompt_text),
    )
    response = armor_client.sanitize_user_prompt(request=request)
    result = response.sanitization_result

    if result.filter_match_state.name == "MATCH_FOUND":
        triggered = list(result.filter_results.keys())
        # Block hard if prompt injection or jailbreak is detected
        if "pi_and_jailbreak" in triggered:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Safety Policy Violation: Prompt flagged by Model Armor ({', '.join(triggered)}).",
            )

def redact_sensitive_pii(text: str) -> str:
    """Gateway-side redaction utility applied when Model Armor detects sensitive data."""
    # Redact Credit Cards (e.g., 4532-8921-3312-9011)
    text = re.sub(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]", text)
    # Redact US SSNs (e.g., 000-12-3456)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)
    return text

def sanitize_outbound_response(raw_text: str) -> str:
    """Inspects tool response with Model Armor and redacts PII if flagged."""
    request = modelarmor_v1.SanitizeModelResponseRequest(
        name=TEMPLATE_PATH,
        model_response_data=modelarmor_v1.DataItem(text=raw_text),
    )
    response = armor_client.sanitize_model_response(request=request)
    result = response.sanitization_result

    # If Model Armor flags SDP or sensitive content, apply zero-trust data minimization
    if result.filter_match_state.name == "MATCH_FOUND":
        print(f"[!] Model Armor flagged outbound response: {list(result.filter_results.keys())}")
        return redact_sensitive_pii(raw_text)

    # Secondary zero-trust safeguard: always scrub known high-risk patterns on outbound egress
    return redact_sensitive_pii(raw_text)

@app.post("/invoke")
def invoke_tool(req: ToolInvocationRequest, claims: Dict = Depends(verify_token)):
    user_email = claims.get("sub", "unknown_user")
    user_groups: List[str] = claims.get("groups", [])

    # 1. RBAC Check
    if req.tool not in TOOL_PERMISSIONS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Tool '{req.tool}' is unregistered or unauthorized.",
        )

    allowed_groups = TOOL_PERMISSIONS[req.tool]
    if not any(grp in allowed_groups for grp in user_groups):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Identity '{user_email}' with groups {user_groups} is unauthorized to invoke tool '{req.tool}'.",
        )

    # 2. Inbound Content Defense (Model Armor)
    if req.prompt:
        sanitize_inbound_prompt(req.prompt)

    # 3. Tool Execution
    if req.tool == "get_campaign_analytics":
        raw_output = {
            "campaign_id": "CAMP-SUMMER-2026",
            "impressions": 452100,
            "clicks": 18230,
            "ctr": "4.03%",
        }

    elif req.tool == "lookup_customer_record":
        raw_output = {
            "customer_id": "CUST-9921",
            "full_name": "Jordan Hayes",
            "email": "jordan.hayes@example.com",
            "credit_card": "4532-8921-3312-9011",
            "ssn": "000-12-3456",
            "notes": "Customer requested account audit.",
        }

    elif req.tool == "purge_customer_data":
        raw_output = {"status": "Customer data purged successfully."}

    # 4. Outbound Defense Layer (Model Armor inspection + Gateway Redaction)
    raw_output_str = json.dumps(raw_output)
    sanitized_output_str = sanitize_outbound_response(raw_output_str)

    try:
        final_result = json.loads(sanitized_output_str)
    except Exception:
        final_result = sanitized_output_str

    return {
        "status": "success",
        "executed_by": user_email,
        "tool": req.tool,
        "result": final_result,
    }