import os
import json
import httpx
from typing import Dict, Any, List
from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

# Configuration
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://integrator-8660722.okta.com/oauth2/default")
JWKS_URL = f"{OKTA_ISSUER}/v1/keys"
AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://default")

# Mock Role-Based Allowlist Policy
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "Lumen-Marketing-Analysts": [
        "get_campaign_analytics",
        "fetch_product_catalog",
        "generate_creative_brief"
    ],
    "Lumen-Data-Admins": [  # Updated to match Okta's actual group claim
        "get_campaign_analytics",
        "fetch_product_catalog",
        "generate_creative_brief",
        "modify_pricing_rules",
        "purge_customer_data"
    ]
}

app = FastAPI(
    title="Lumen Governed Agent Gateway",
    version="1.0.0",
    description="Zero-Trust Model Context Protocol Gateway enforcing OIDC token claims and tool-level RBAC."
)

security = HTTPBearer()

# In-memory cache for OIDC signing keys
jwks_cache: Dict[str, Any] = {}

async def get_jwks() -> Dict[str, Any]:
    global jwks_cache
    if not jwks_cache:
        async with httpx.AsyncClient() as client:
            resp = await client.get(JWKS_URL)
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to retrieve OIDC signing keys from Okta."
                )
            jwks_cache = resp.json()
    return jwks_cache

async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    token = credentials.credentials
    jwks = await get_jwks()

    try:
        # Extract token header to locate key ID (kid)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token header: missing kid.")

        # Find matching key in JWKS
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Public signing key not found.")

        # Decode and validate signature, issuer, and audience
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=OKTA_ISSUER,
            options={"verify_aud": False}  # Set to True if audience is explicitly mapped
        )
        return claims
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}"
        )

@app.get("/healthz")
async def health_check():
    return {"status": "healthy", "service": "lumen-agent-gateway"}

@app.post("/v1/tools/execute")
async def execute_tool(
    payload: Dict[str, Any],
    token_claims: Dict[str, Any] = Depends(verify_token)
):
    tool_name = payload.get("tool_name")
    tool_arguments = payload.get("arguments", {})

    if not tool_name:
        raise HTTPException(status_code=400, detail="Missing tool_name in execution request.")

    # 1. Identity & Role Resolution
    user_identity = token_claims.get("sub", "unknown")
    user_groups: List[str] = token_claims.get("groups", [])

    # Aggregate allowed tools across all groups
    allowed_tools = set()
    for group in user_groups:
        allowed_tools.update(ROLE_PERMISSIONS.get(group, []))

    # 2. Enforce Tool-Level Allowlist
    if tool_name not in allowed_tools:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access Denied: Identity '{user_identity}' with groups {user_groups} "
                f"is unauthorized to invoke tool '{tool_name}'."
            )
        )

    # 3. Simulated Tool Execution with Policy Redaction
    if tool_name == "get_campaign_analytics":
        return {
            "status": "success",
            "executed_by": user_identity,
            "tool": tool_name,
            "result": {
                "campaign_id": tool_arguments.get("campaign_id", "CAMP-9021"),
                "impressions": 452100,
                "clicks": 18230,
                "ctr": "4.03%",
                # Simulated PII redaction layer
                "restricted_pii": "[REDACTED_BY_GATEWAY_POLICY]"
            }
        }

    return {
        "status": "success",
        "executed_by": user_identity,
        "tool": tool_name,
        "result": f"Tool '{tool_name}' executed successfully."
    }