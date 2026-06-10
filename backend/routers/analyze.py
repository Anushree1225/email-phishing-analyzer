from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

# Import your custom EML parsing engine from the services folder
from services.eml_parser import parse_eml

router = APIRouter()

# --- 1. TEXT SCAN HANDLING ---
@router.post("/analyze")
def analyze_email(payload: Dict[str, Any]):
    print(f"--- [DEBUG] Frontend JSON payload keys received: {list(payload.keys())} ---")
    
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
    
    file_extension = filename.split(".")[-1].lower() if "." in filename else ""
    
    allowed_extensions = ["eml", "pdf", "png", "jpg", "jpeg"]
    if file_extension not in allowed_extensions:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file format .{file_extension}. Please upload .eml, .pdf, or image screenshots."
        )
        
    file_bytes = await file.read()
    print(f"Successfully Buffered: {len(file_bytes)} bytes")
    
    # 🎯 REAL ROUTING FOR WEEK 2 EXTRACTION
    if file_extension == "eml":
        try:
            # Parse the real file content
            eml_data = parse_eml(file_bytes)
            
            # ─────────────── 🖥️ TERMINAL FORENSIC MONITOR ───────────────
            print("\n" + "="*50)
            print(" 🛡️  RAW EML FORENSIC REPORT GENERATED")
            print("="*50)
            print(f" SENDER (FROM):   {eml_data['metadata']['from']}")
            print(f" RECIPIENT (TO):  {eml_data['metadata']['to']}")
            print(f" SUBJECT:         {eml_data['metadata']['subject']}")
            print(f" REPLY-TO:        {eml_data['metadata']['reply_to']}")
            print(f" SPOOF INDICATOR: {eml_data['metadata']['header_mismatch']} (From vs Reply-To Mismatch)")
            print("-"*50)
            print(" 🔐 EMAIL AUTHENTICATION STATUS")
            print(f"   SPF:   {eml_data['authentication']['spf']}")
            print(f"   DKIM:  {eml_data['authentication']['dkim']}")
            print(f"   DMARC: {eml_data['authentication']['dmarc']}")
            print("-"*50)
            print(f" 📄 TEXT BODY PREVIEW (First 200 Chars):\n {eml_data['body_preview'][:200]}...")
            print("="*50 + "\n")
            # ────────────────────────────────────────────────────────────

            # Combine real parsed headers with your baseline frontend output matrix
            base_response = generate_mock_response(source_type=f"Raw EML Message Structure ({filename})")
            base_response["eml_details"] = eml_data  
            return base_response
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"EML Processing failed: {str(e)}")
            
    elif file_extension == "pdf":
        detected_format_label = "PDF Electronic Document Document"
        return generate_mock_response(source_type=f"{detected_format_label} ({filename})")
        
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