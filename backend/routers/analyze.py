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
    
    # 🎯 REAL ROUTING FOR WEEK 2 EXTRACTION & RISK CALCULATION
    if file_extension == "eml":
        try:
            # Parse and execute real dynamic scoring logic on the file content
            eml_analysis = parse_eml(file_bytes)
            
            # ─────────────── 🖥️ SYSTEM TERMINAL TELEMETRY ───────────────
            print("\n" + "="*60)
            print(" 🛡️  DYNAMIC RISK SCORING EVALUATION COMPLETE")
            print("="*60)
            print(f" FILE:            {filename}")
            print(f" SENDER (FROM):   {eml_analysis['metadata']['from']}")
            print(f" SENDER DOMAIN:   {eml_analysis['metadata']['sender_domain']}")
            print(f" SUBJECT:         {eml_analysis['metadata']['subject']}")
            print(f" CALCULATED RISK: {eml_analysis['risk_score']}% ({eml_analysis['severity']} Severity)")
            print("-"*60)
            print(f" 🚨 THREAT FINDINGS MAPPED ({len(eml_analysis['reasons'])}):")
            for reason in eml_analysis['reasons']:
                print(f"   ⚠️  [{reason['type'].upper()}] - {reason['message']}")
            
            # 🌐 UPDATED: CORE DNS INTELLIGENCE + SOC ANALYST GUIDANCE IN CMD LINE
            print("-"*60)
            print(" 🌐 LIVE DNS FORENSICS EXTRACTED:")
            dns_info = eml_analysis['dns_intelligence']
            print(f"   📧 MX ROUTING INFRA:  {dns_info['mx_check']}")
            if dns_info['mx_records']:
                print(f"      Mapped targets:   {', '.join(dns_info['mx_records'])}")
            
            print(f"   🔒 DEPLOYED SPF TXT:  {dns_info['spf_record']}")
            print(f"      🧠 Guidance:       {dns_info['spf_analyst_note']}") # 🚀 Added!
            
            print(f"   🛡️  DMARC POLICY CORE: {dns_info['dmarc_policy']}")
            print(f"      🧠 Guidance:       {dns_info['dmarc_analyst_note']}") # 🚀 Added!

            # Construct response using the real runtime calculated score matrices!
            return {
                "risk_score": eml_analysis["risk_score"],
                "severity": eml_analysis["severity"],
                "reasons": eml_analysis["reasons"] if eml_analysis["reasons"] else [{"type": "clean", "message": "No immediate risk indicators found."}],
                "recommended_action": eml_analysis["recommended_action"],
                "urls_found": [], 
                "highlighted_content": [], 
                "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
                "scanned_at": datetime.utcnow().isoformat() + "Z",
                
                # 🎯 ADDED KEYS FOR ADVANCED SUB-PANELS
                "file_type": "eml", 
                "dns_intelligence": eml_analysis["dns_intelligence"],
                "eml_details": eml_analysis 
            }
            
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