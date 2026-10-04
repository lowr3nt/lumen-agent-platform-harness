import json
import re
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1
from google import genai
from google.genai import types
# 3. Local Application Imports (Gateway Modules & Adapters)
from gateway.audit import log_audit_event
from gateway.session import get_session_history, append_session_turns
from gateway.adapters.snowflake import query_customer_record
from gateway.adapters.databricks import query_campaign_metrics
from gateway.dlp import redact_sensitive_payload

app = FastAPI(
    title="Lumen Agent Platform Gateway",
    version="1.1.0",
    description="Zero-trust, hardened gateway for enterprise generative agent workflows.",
)
security = HTTPBearer()

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"
LOCATION = "us-central1"
MODEL_ARMOR_ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"
TEMPLATE_PATH = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/retail-agent-defense"

armor_client = modelarmor_v1.ModelArmorClient(
    client_options=ClientOptions(api_endpoint=MODEL_ARMOR_ENDPOINT)
)

genai_client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION,
)

TOOL_PERMISSIONS = {
    "get_campaign_analytics": ["Lumen-Marketing-Analysts", "Lumen-Data-Admins"],
    "lookup_customer_record": ["Lumen-Data-Admins"],
    "purge_customer_data": ["Lumen-Data-Admins"],
}

def get_campaign_analytics(campaign_name: str = "Summer Campaign") -> dict:
    return {
        "campaign_id": "CAMP-SUMMER-2026",
        "campaign_name": campaign_name,
        "impressions": 452100,
        "clicks": 18230,
        "ctr": "4.03%",
    }

def lookup_customer_record(customer_id: str = "CUST-UNKNOWN") -> dict:
    return {
        "customer_id": customer_id,
        "full_name": "Jordan Hayes",
        "email": "jordan.hayes@example.com",
        "credit_card": "4532-8921-3312-9011",
        "ssn": "000-12-3456",
        "notes": "Customer requested account audit.",
    }

def purge_customer_data(customer_id: str = "CUST-UNKNOWN") -> dict:
    return {"status": f"Customer data for {customer_id} purged successfully."}

TOOL_REGISTRY = {
    "get_campaign_analytics": get_campaign_analytics,
    "lookup_customer_record": lookup_customer_record,
    "purge_customer_data": purge_customer_data,
}

class ToolInvocationRequest(BaseModel):
    tool: str
    prompt: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

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

def sanitize_inbound_prompt(prompt_text: str, principal: str, groups: List[str]):
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=TEMPLATE_PATH,
        user_prompt_data=modelarmor_v1.DataItem(text=prompt_text),
    )
    response = armor_client.sanitize_user_prompt(request=request)
    result = response.sanitization_result

    # Check if the overall response flagged a violation
    if result.filter_match_state.name == "MATCH_FOUND":
        actual_matches = []
        for filter_name, filter_res in result.filter_results.items():
            # Check match state per detector
            match_state = getattr(filter_res, "filter_match_state", None)
            if match_state and match_state.name == "MATCH_FOUND":
                actual_matches.append(filter_name)

        if actual_matches:
            log_audit_event(
                event_type="SECURITY_PROMPT_BLOCKED",
                severity="WARNING",
                principal=principal,
                groups=groups,
                action="inbound_prompt_sanitization",
                status="BLOCKED",
                details={"triggered_filters": actual_matches, "template": TEMPLATE_PATH},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Safety Policy Violation: Prompt flagged by Model Armor ({', '.join(actual_matches)}).",
            )

def redact_sensitive_pii(text: str, principal: str, groups: List[str]) -> str:
    new_text, cc_matches = re.subn(r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]", text)
    new_text, ssn_matches = re.subn(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", new_text)

    total_redactions = cc_matches + ssn_matches
    if total_redactions > 0:
        log_audit_event(
            event_type="SECURITY_PII_REDACTED",
            severity="NOTICE",
            principal=principal,
            groups=groups,
            action="outbound_egress_sanitization",
            status="REDACTED",
            details={
                "credit_card_instances": cc_matches,
                "ssn_instances": ssn_matches,
                "total_redactions": total_redactions,
            },
        )
    return new_text

def sanitize_outbound_response(raw_text: str, principal: str, groups: List[str]) -> str:
    request = modelarmor_v1.SanitizeModelResponseRequest(
        name=TEMPLATE_PATH,
        model_response_data=modelarmor_v1.DataItem(text=raw_text),
    )
    armor_client.sanitize_model_response(request=request)
    return redact_sensitive_pii(raw_text, principal, groups)

@app.post("/invoke")
def invoke_tool(req: ToolInvocationRequest, claims: Dict = Depends(verify_token)):
    user_email = claims.get("sub", "unknown_user")
    user_groups: List[str] = claims.get("groups", [])

    if req.tool not in TOOL_PERMISSIONS:
        log_audit_event(
            event_type="SECURITY_AUTHORIZATION_DENIED",
            severity="ERROR",
            principal=user_email,
            groups=user_groups,
            action="direct_tool_invocation",
            status="DENIED_UNREGISTERED_TOOL",
            details={"requested_tool": req.tool},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Tool '{req.tool}' is unregistered or unauthorized.",
        )

    allowed_groups = TOOL_PERMISSIONS[req.tool]
    if not any(grp in allowed_groups for grp in user_groups):
        log_audit_event(
            event_type="SECURITY_AUTHORIZATION_DENIED",
            severity="ERROR",
            principal=user_email,
            groups=user_groups,
            action="direct_tool_invocation",
            status="DENIED_INSUFFICIENT_PRIVILEGES",
            details={"requested_tool": req.tool, "required_groups": allowed_groups},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Identity '{user_email}' with groups {user_groups} is unauthorized to invoke tool '{req.tool}'.",
        )

    if req.prompt:
        sanitize_inbound_prompt(req.prompt, user_email, user_groups)

    fn = TOOL_REGISTRY[req.tool]
    params = req.parameters or {}

    log_audit_event(
        event_type="AGENT_TOOL_INVOKED",
        severity="INFO",
        principal=user_email,
        groups=user_groups,
        action="execute_tool",
        status="EXECUTING",
        details={"tool": req.tool, "invocation_mode": "direct_api"},
    )

    if req.tool == "get_campaign_analytics":
        raw_output = fn(params.get("campaign_name", "Summer Campaign"))
    elif req.tool == "lookup_customer_record":
        raw_output = fn(params.get("customer_id", "CUST-UNKNOWN"))
    elif req.tool == "purge_customer_data":
        raw_output = fn(params.get("customer_id", "CUST-UNKNOWN"))
    else:
        raw_output = fn(**params)

    raw_output_str = json.dumps(raw_output)
    sanitized_output_str = sanitize_outbound_response(raw_output_str, user_email, user_groups)

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

@app.post("/agent/chat")
def agent_chat(
    req: AgentInvocationRequest,
    claims: Dict = Depends(verify_token),
    x_session_id: Optional[str] = Header(None),
):
    user_email = claims.get("sub", "unknown_user")
    user_groups: List[str] = claims.get("groups", [])
    session_id = x_session_id or f"session-adhoc-{user_email}"

    # 1. Inbound Model Armor Check
    sanitize_inbound_prompt(req.prompt, user_email, user_groups)

    # 2. RBAC Dynamic Tool Pruning
    allowed_tools = [
        TOOL_REGISTRY[name]
        for name, groups in TOOL_PERMISSIONS.items()
        if any(grp in groups for grp in user_groups)
    ]

    # 3. Retrieve Session History from Firestore
    try:
        raw_history = get_session_history(session_id, user_email)
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Session belongs to a different principal.",
        )

    # Transform raw turns to types.Content for Vertex AI
    history_contents: List[types.Content] = []
    for turn in raw_history:
        history_contents.append(
            types.Content(
                role=turn["role"],
                parts=[types.Part.from_text(text=turn["text"])],
            )
        )

    log_audit_event(
        event_type="AGENT_SESSION_INITIATED",
        severity="INFO",
        principal=user_email,
        groups=user_groups,
        action="agent_chat",
        status="INITIALIZED",
        details={
            "session_id": session_id,
            "historical_turns_loaded": len(raw_history),
            "exposed_tools": [fn.__name__ for fn in allowed_tools],
        },
    )

    # 4. Initialize Multi-Turn Chat
    chat = genai_client.chats.create(
        model="gemini-2.5-flash",
        history=history_contents,
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

    response = chat.send_message(req.prompt)
    model_reply = response.text or ""

    # 5. Outbound PII Redaction
    sanitized_reply = sanitize_outbound_response(model_reply, user_email, user_groups)

    # 6. Save Turn History to Firestore
    append_session_turns(
        session_id=session_id,
        principal=user_email,
        user_prompt=req.prompt,
        model_response=sanitized_reply,
    )

    return {
        "status": "success",
        "session_id": session_id,
        "caller": user_email,
        "authorized_tools": [fn.__name__ for fn in allowed_tools],
        "response": sanitized_reply,
    }