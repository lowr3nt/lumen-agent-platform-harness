import os
import json
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1
from google import genai
from google.genai import types

# Local Application Imports
from gateway.audit import log_audit_event
from gateway.session import get_session_history, append_session_turns
from gateway.dlp import redact_sensitive_payload

app = FastAPI(
    title="Lumen Agent Platform Gateway",
    version="1.1.0",
    description="Zero-trust, hardened gateway for enterprise generative agent workflows.",
)
security = HTTPBearer()

# Flexible environment variable evaluation for local vs Cloud Build environments
PROJECT_ID = os.getenv("GCP_PROJECT_ID") or os.getenv("PROJECT_ID", "project-a661dfac-6f3d-4776-a43")
LOCATION = os.getenv("GCP_LOCATION") or os.getenv("LOCATION", "us-central1")
MODEL_ARMOR_ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"
TEMPLATE_PATH = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/retail-agent-defense"

# Shared test secret and identity provider configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "lumen-test-secret-key")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "lumen-identity-provider"

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
    token = credentials.credentials
    try:
        claims = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"verify_aud": False},
        )
        return claims
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired OIDC token: {str(exc)}",
        )

def _extract_triggered_filters(filter_results: Any) -> List[str]:
    """
    Names of the Model Armor filters whose result is MATCH_FOUND.

    Each filter result is a protobuf message whose text form contains the line
    "match_state: MATCH_FOUND" when that filter fired. The token includes the
    "match_state: " prefix on purpose: a bare "MATCH_FOUND" also matches
    "NO_MATCH_FOUND" and would flag every filter on every request. This also
    covers the SDP filter, where match_state is nested inside inspect_result.
    """
    return [
        name for name, result in filter_results.items()
        if "match_state: MATCH_FOUND" in str(result)
    ]

def sanitize_inbound_prompt(prompt_text: str, principal: str, groups: List[str]):
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=TEMPLATE_PATH,
        user_prompt_data=modelarmor_v1.DataItem(text=prompt_text),
    )
    response = armor_client.sanitize_user_prompt(request=request)
    result = response.sanitization_result

    match_state = getattr(result.filter_match_state, "name", str(result.filter_match_state))
    is_blocked = (
        match_state == "MATCH_FOUND"
        or result.filter_match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND
    )

    if is_blocked:
        triggered = _extract_triggered_filters(result.filter_results)
        flagged_filters = triggered if triggered else ["pi_and_jailbreak"]

        log_audit_event(
            event_type="SECURITY_PROMPT_BLOCKED",
            severity="WARNING",
            principal=principal,
            groups=groups,
            action="inbound_prompt_sanitization",
            status="BLOCKED",
            details={"triggered_filters": flagged_filters, "template": TEMPLATE_PATH},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety Policy Violation: Prompt flagged by Model Armor ({', '.join(flagged_filters)}).",
        )

def sanitize_outbound_response(raw_text: str, principal: str, groups: List[str]) -> str:
    # 1. Mask First: Egress DLP sanitization strips PII based on role
    masked_payload, _ = redact_sensitive_payload(raw_text, principal, groups)
    sanitized_text = str(masked_payload)

    # 2. Screen Second: Outbound Model Armor evaluation on sanitized text
    request = modelarmor_v1.SanitizeModelResponseRequest(
        name=TEMPLATE_PATH,
        model_response_data=modelarmor_v1.DataItem(text=sanitized_text),
    )
    response = armor_client.sanitize_model_response(request=request)
    result = response.sanitization_result

    match_state = getattr(result.filter_match_state, "name", str(result.filter_match_state))
    if match_state == "MATCH_FOUND" or result.filter_match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND:
        triggered = _extract_triggered_filters(result.filter_results)
        log_audit_event(
            event_type="SECURITY_MODEL_RESPONSE_BLOCKED",
            severity="ERROR",
            principal=principal,
            groups=groups,
            action="outbound_response_sanitization",
            status="BLOCKED",
            details={"triggered_filters": triggered, "template": TEMPLATE_PATH},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Model output blocked by enterprise safety policies.",
        )

    return sanitized_text

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

    # Inbound sanitization on prompt and parameter payload strings
    if req.prompt:
        sanitize_inbound_prompt(req.prompt, user_email, user_groups)

    params = req.parameters or {}
    for param_key, param_val in params.items():
        if isinstance(param_val, str):
            sanitize_inbound_prompt(param_val, user_email, user_groups)

    fn = TOOL_REGISTRY[req.tool]

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

    # 2. RBAC Dynamic Tool Pruning with Chat-Initiated Audit Logging
    def make_audited_tool(name: str, target_fn):
        def tool_wrapper(*args, **kwargs):
            log_audit_event(
                event_type="AGENT_TOOL_INVOKED",
                severity="INFO",
                principal=user_email,
                groups=user_groups,
                action="execute_tool",
                status="EXECUTING",
                details={"tool": name, "invocation_mode": "chat_agent"},
            )
            return target_fn(*args, **kwargs)
        tool_wrapper.__name__ = name
        tool_wrapper.__doc__ = target_fn.__doc__
        return tool_wrapper

    allowed_tools = [
        make_audited_tool(name, TOOL_REGISTRY[name])
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

    # 4. Multi-Turn Inference via Gemini
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

    # 5. Outbound DLP Redaction and Model Armor Sanitization
    sanitized_reply = sanitize_outbound_response(model_reply, user_email, user_groups)

    # 6. Persist Turn History
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
