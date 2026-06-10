import email
from email import policy
import re

def parse_eml(file_bytes: bytes) -> dict:
    """
    Parses the raw byte stream of an EML file to extract transport headers,
    sender addresses, and authentication verification records.
    """
    # Convert raw memory bytes into an inspectable Python email object
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    # Extract structural user-facing headers
    email_from = msg.get("From", "Unknown Sender")
    email_to = msg.get("To", "Unknown Recipient")
    email_subject = msg.get("Subject", "No Subject")
    reply_to = msg.get("Reply-To", "Not Specified")
    
    # 🔍 Security Forensics: Pull Hidden Network Authentication Fields
    auth_results_header = msg.get("Authentication-Results", "")
    received_spf_header = msg.get("Received-SPF", "")
    
    # --- RIGOROUS EXTRACTOR LOGIC FOR SPF ---
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

    # --- REGEX EXTRACTOR LOGIC FOR DKIM & DMARC ---
    dkim_status = "UNKNOWN"
    dmarc_status = "UNKNOWN"
    
    dkim_match = re.search(r'dkim=(\w+)', auth_results_header.lower())
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results_header.lower())
    
    if dkim_match:
        dkim_status = dkim_match.group(1).upper()
    if dmarc_match:
        dmarc_status = dmarc_match.group(1).upper()

    # Match Check: Check if display sender matches where the replies actually go
    header_mismatch = False
    if reply_to != "Not Specified" and email_from != reply_to:
        header_mismatch = True

    # 📄 Extract Body Stream
    body_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_content = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body_content = msg.get_payload(decode=True).decode(errors="ignore")

    return {
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
        "body_preview": body_content.strip()[:1000]
    }