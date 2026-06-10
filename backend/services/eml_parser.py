import email
from email import policy
import re

def clean_html_tags(html_text: str) -> str:
    """Strips HTML formatting tags to extract pure text content for analysis."""
    # Remove script and style blocks entirely
    clean_text = re.sub(r'<(script|style).*?>.*?</\1>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
    # Strip remaining HTML tags
    clean_text = re.sub(r'<[^>]*>', ' ', clean_text)
    # Collapse multiple spaces/newlines into a clean stream
    clean_text = re.sub(r'\s+', ' ', clean_text)
    return clean_text.strip()

def parse_eml(file_bytes: bytes) -> dict:
    """
    Advanced EML parser that extracts core metadata, handles HTML body sanitization,
    and runs a multi-vector heuristic risk calculation engine.
    """
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    # 1. Structural Metadata Extraction
    email_from = msg.get("From", "Unknown Sender")
    email_to = msg.get("To", "Unknown Recipient")
    email_subject = msg.get("Subject", "No Subject")
    reply_to = msg.get("Reply-To", "Not Specified")
    
    auth_results_header = msg.get("Authentication-Results", "")
    received_spf_header = msg.get("Received-SPF", "")
    
    # 2. Authentication Checks
    spf_status = "UNKNOWN"
    combined_spf_target = (received_spf_header + " " + auth_results_header).lower()
    if "spf=pass" in combined_spf_target or "pass (google.com" in combined_spf_target:
        spf_status = "PASS"
    elif "spf=fail" in combined_spf_target or "fail (google.com" in combined_spf_target:
        spf_status = "FAIL"
    elif "softfail" in combined_spf_target:
        spf_status = "SOFTFAIL"
    elif "none" in combined_spf_target:
        spf_status = "NONE"

    dkim_status = "UNKNOWN"
    dmarc_status = "UNKNOWN"
    dkim_match = re.search(r'dkim=(\w+)', auth_results_header.lower())
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results_header.lower())
    if dkim_match: dkim_status = dkim_match.group(1).upper()
    if dmarc_match: dmarc_status = dmarc_match.group(1).upper()

    header_mismatch = reply_to != "Not Specified" and email_from != reply_to

    # 3. Robust Body Extraction (Handles text AND dense HTML formatting)
    plain_body = ""
    html_body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            c_type = part.get_content_type()
            if c_type == "text/plain":
                plain_body += part.get_payload(decode=True).decode(errors="ignore")
            elif c_type == "text/html":
                html_body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        c_type = msg.get_content_type()
        if c_type == "text/html":
            html_body = msg.get_payload(decode=True).decode(errors="ignore")
        else:
            plain_body = msg.get_payload(decode=True).decode(errors="ignore")

    # If no pure plain text layer was found, clean the HTML layer down to raw text words
    extracted_text = plain_body if plain_body.strip() else clean_html_tags(html_body)

    # 🧮 4. THE RISK SCORING WEIGHT ENGINE (Heuristic Mapping)
    calculated_risk = 0
    reasons = []
    recommended_actions = ["Monitor account logs for suspicious activity"]

    if header_mismatch:
        calculated_risk += 25
        reasons.append({"type": "header_mismatch", "message": "Reply-To address differs from display sender domain."})
    
    if spf_status == "FAIL":
        calculated_risk += 30
        reasons.append({"type": "spf_fail", "message": "SPF validation failed—unauthorized server source."})
    elif spf_status in ["SOFTFAIL", "NONE"]:
        calculated_risk += 15
        reasons.append({"type": "spf_weak", "message": "Domain has a relaxed, spoofable mail deployment protocol."})

    if dkim_status == "FAIL":
        calculated_risk += 20
        reasons.append({"type": "dkim_fail", "message": "DKIM cryptographic signature verification is broken."})

    if dmarc_status == "FAIL":
        calculated_risk += 25
        reasons.append({"type": "dmarc_fail", "message": "DMARC alignment validation failed completely."})

    # Simple Keyword Heuristic checks before integrating the full AI model later
    lower_text = extracted_text.lower()
    if "lawsuit" in lower_text or "court" in lower_text or "notice" in lower_text:
        calculated_risk += 10
        reasons.append({"type": "legal_trigger", "message": "Contains sensitive legal or class-action settlement tracking keywords."})

    if "verify" in lower_text or "password" in lower_text or "login" in lower_text:
        calculated_risk += 20
        reasons.append({"type": "credential_request", "message": "Text structure indicates a verification or credential capture attempt."})

    # Bound risk score max at 100%
    final_risk_score = min(calculated_risk, 100)
    
    # Determine Severity Classification Label based on calculations
    severity = "Low"
    if final_risk_score >= 70:
        severity = "High"
        recommended_actions = ["Do not interact with this email", "Delete the email immediately", "Report it to your technical security team"]
    elif final_risk_score >= 35:
        severity = "Medium"
        recommended_actions = ["Exercise extreme caution when clicking any links", "Verify sender identity through an alternative channel"]

    return {
        "risk_score": final_risk_score,
        "severity": severity,
        "reasons": reasons,
        "recommended_action": recommended_actions,
        "metadata": {
            "from": email_from,
            "to": email_to,
            "subject": email_subject,
            "reply_to": reply_to,
            "header_mismatch": header_mismatch
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        },
        "clean_text_content": extracted_text[:1200]
    }