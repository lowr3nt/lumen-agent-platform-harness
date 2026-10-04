from datetime import datetime, timezone
from typing import Any, Dict, List
from google.cloud import firestore

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"
db = firestore.Client(project=PROJECT_ID)

# Keep the sliding window bounded to avoid token exhaustion and prompt dilution
MAX_HISTORY_TURNS = 10

def get_session_history(session_id: str, principal: str) -> List[Dict[str, str]]:
    """
    Retrieves the conversation history for a given session and validates ownership.
    """
    doc_ref = db.collection("agent_sessions").document(session_id)
    doc = doc_ref.get()

    if not doc.exists:
        return []

    data = doc.to_dict()
    # Enforce session ownership to prevent cross-tenant/cross-user session hijacking
    if data.get("principal") != principal:
        raise PermissionError("Session principal mismatch.")

    return data.get("turns", [])

def append_session_turns(
    session_id: str,
    principal: str,
    user_prompt: str,
    model_response: str,
):
    """
    Appends the latest user turn and model response to the Firestore session record.
    """
    doc_ref = db.collection("agent_sessions").document(session_id)
    doc = doc_ref.get()

    now = datetime.now(timezone.utc).isoformat()
    new_turns = [
        {"role": "user", "text": user_prompt, "timestamp": now},
        {"role": "model", "text": model_response, "timestamp": now},
    ]

    if not doc.exists:
        doc_ref.set({
            "session_id": session_id,
            "principal": principal,
            "created_at": now,
            "updated_at": now,
            "turns": new_turns,
        })
    else:
        existing_turns = doc.to_dict().get("turns", [])
        updated_turns = (existing_turns + new_turns)[-(MAX_HISTORY_TURNS * 2):]
        doc_ref.update({
            "updated_at": now,
            "turns": updated_turns,
        })