from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

router = APIRouter()

# --- 1. TEXT SCAN HANDLING ---
@router.post("/analyze")
def analyze_email(payload: Dict[str, Any]):
    print(f"--- [DEBUG] Frontend JSON payload keys received: {list(payload.keys())} ---")
    
    # Added "email_text" right at the front of the line to catch Claude's exact key!
    email_text = ""
    for key in ["email_text", "text", "content", "emailText", "email_content", "email"]:
        if key in payload and payload[key]:
            email_text = str(payload[key])
            break

    print(f"--- [TEXT SCAN] Successfully Received Text! Length: {len(email_text)} characters ---")
    return generate_mock_response(source_type="Pasted Text Details")


# --- 2. MULTI-FORMAT FILE SCAN HANDLING (.eml, .pdf, .png, .jpg, .jpeg) ---
@router.post("/analyze/file")
async def analyze_email_file(file: UploadFile = File(...)):
    filename = file.filename
    content_type = file.content_type
    
    print(f"--- [FILE SCAN] Request Intercepted ---")
    print(f"Filename: {filename}")
    print(f"Content-Type: {content_type}")
    
    # Extract extension safely
    file_extension = filename.split(".")[-1].lower() if "." in filename else ""
    
    # Validate against Week 1 allowed project scopes
    allowed_extensions = ["eml", "pdf", "png", "jpg", "jpeg"]
    if file_extension not in allowed_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file format .{file_extension}. Please upload .eml, .pdf, or image screenshots."
        )
        
    # Read raw binary data stream 
    file_bytes = await file.read()
    print(f"Successfully Buffered: {len(file_bytes)} bytes")
    
    # Week 2 Extraction routing visualization routing logic
    detected_format_label = "Unknown File Context"
    if file_extension == "eml":
        detected_format_label = "Raw EML Message Structure"
    elif file_extension == "pdf":
        detected_format_label = "PDF Electronic Document Document"
    elif file_extension in ["png", "jpg", "jpeg"]:
        detected_format_label = "Image Screenshot Data (OCR Target)"

    return generate_mock_response(source_type=f"{detected_format_label} ({filename})")


# --- CORE OUTPUT RESPONSE MATRIX MATCHING THE FRONTEND LOOK ---
def generate_mock_response(source_type: str):
    return {
        "risk_score": 87,
        "severity": "High",
        "reasons": [
            { "type": "credential_request", "message": "Email asks for credentials" },
            { "type": "input_source", "message": f"Source Verified: {source_type}" }
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