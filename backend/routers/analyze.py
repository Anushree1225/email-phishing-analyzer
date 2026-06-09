from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uuid

router = APIRouter()

# We make the fields optional so FastAPI won't crash with a 422 if the key doesn't match perfectly
class EmailPayload(BaseModel):
    text: Optional[str] = None
    content: Optional[str] = None
    emailText: Optional[str] = None

@router.post("/analyze")
def analyze_email(payload: EmailPayload):
    # This checks all common keys that Claude might have named the text field in the UI component
    email_text = payload.text or payload.content or payload.emailText or ""
    
    # This print statement will let us confirm IN THE TERMINAL exactly what key it found
    print(f"--- Successfully Received Text! Length: {len(email_text)} ---")
    
    return {
        "risk_score": 87,
        "severity": "High",
        "reasons": [
            { "type": "credential_request", "message": "Email asks for credentials" },
            { "type": "urgent_language", "message": "Urgent language detected" }
        ],
        "recommended_action": [
            "Do not interact with this email",
            "Report it to the security team",
            "Delete the email immediately"
        ],
        "urls_found": [
            {
                "url": "http://micros0ft-verify.xyz/login",
                "safe": False,
                "redirect_chain": ["http://micros0ft-verify.xyz/login", "http://malware-host.ru/payload"]
            }
        ],
        "highlighted_content": [
            { "text": "Verify your account immediately", "reason": "Urgency trigger" }
        ],
        "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
        "scanned_at": datetime.utcnow().isoformat() + "Z"
    }