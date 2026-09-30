import os
from typing import Dict, List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1

app = FastAPI(title="Lumen Zero-Trust Agent Gateway with Model Armor")
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

# RBAC Policy Matrix
TOOL_PERMISSIONS = {
    "get_campaign_analytics": ["Lumen-Marketing-Analysts", "Lumen-Data-Admins"],
    "purge_customer_data": ["Lumen-Data-Admins"],
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

def sanitize_prompt(prompt_text: str):
    """Inspects incoming user prompt against Model Armor template."""
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=TEMPLATE_PATH,
        user_prompt_data=modelarmor_v1.DataItem(text=prompt_text),
    )
    response = armor_client.sanitize_user_prompt(request=request)
    result = response.sanitization_result

    if result.filter_match_state.name == "MATCH_FOUND":
        triggered = list(result.filter_results.keys())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety Policy Violation: Prompt flagged by Model Armor ({', '.join(triggered)}).",
        )

@app.post("/invoke")
def invoke_tool(req: ToolInvocationRequest, claims: Dict = Depends(verify_token)):
    user_email = claims.get("sub", "unknown_user")
    user_groups: List[str] = claims.get("groups", [])

    # 1. RBAC Check (Phase 1)
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

    # 2. Content Defense Layer (Phase 2 - Model Armor)
    if req.prompt:
        sanitize_prompt(req.prompt)

    # 3. Simulated Tool Execution
    if req.tool == "get_campaign_analytics":
        return {
            "status": "success",
            "executed_by": user_email,
            "tool": req.tool,
            "result": {
                "campaign_id": "CAMP-SUMMER-2026",
                "impressions": 452100,
                "clicks": 18230,
                "ctr": "4.03%",
                "restricted_pii": "[REDACTED_BY_GATEWAY_POLICY]",
            },
        }

    if req.tool == "purge_customer_data":
        return {
            "status": "success",
            "executed_by": user_email,
            "tool": req.tool,
            "result": "Tool 'purge_customer_data' executed successfully.",
        }