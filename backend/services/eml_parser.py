import email
from email import policy
import re
import dns.resolver  # 🚀 Used for live global DNS queries!

def clean_html_tags(html_text: str) -> str:
    """Strips HTML formatting tags to extract pure text content for analysis."""
    clean_text = re.sub(r'<(script|style).*?>.*?</\1>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
    clean_text = re.sub(r'<[^>]*>', ' ', clean_text)
    clean_text = re.sub(r'\s+', ' ', clean_text)
    return clean_text.strip()

def check_dns_records(domain: str) -> dict:
    """
    Queries live global DNS records and generates tactical SOC analyst interpretations
    to help junior security responders decipher raw protocol strings.
    """
    dns_report = {
        "mx_check": "NOT FOUND",
        "mx_records": [],
        "spf_record": "NOT FOUND",
        "spf_analyst_note": "No SPF configuration found. Senders cannot be verified.",
        "dmarc_policy": "NOT FOUND",
        "dmarc_analyst_note": "No DMARC policy found. Domain is highly vulnerable to identity spoofing."
    }
    
    if not domain or "." not in domain:
        return dns_report

    # 1. LIVE MX RECORDS LOOKUP
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        dns_report["mx_records"] = [str(r.exchange).strip(".") for r in mx_answers]
        if dns_report["mx_records"]:
            dns_report["mx_check"] = "VALID (Mail Servers Configured)"
    except Exception:
        dns_report["mx_check"] = "FAILED (No Mail Servers Found)"

    # 2. LIVE SPF RECORD LOOKUP & SOC INTERPRETATION
    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for r in txt_answers:
            txt_string = str(r).strip('"')
            if txt_string.startswith("v=spf1"):
                dns_report["spf_record"] = txt_string
                
                # Evaluate SPF enforcement flags
                if "-all" in txt_string:
                    dns_report["spf_analyst_note"] = "Strict Enforcement (-all). Unauthorized servers are strictly rejected by receivers."
                elif "~all" in txt_string:
                    dns_report["spf_analyst_note"] = "Relaxed Policy (~all). Softfail configuration; unauthorized mail is flagged but still delivered."
                elif "?all" in txt_string:
                    dns_report["spf_analyst_note"] = "Neutral Policy (?all). No policy enforcement; testing mode or unprotected configuration."
                else:
                    dns_report["spf_analyst_note"] = "Custom SPF mechanism deployed. Review listed include/ip4 blocks for source alignment."
                break
    except Exception:
        dns_report["spf_analyst_note"] = "FAILED: Domain completely lacks an SPF security record. High spoofing potential."

    # 3. LIVE DMARC POLICY LOOKUP & SOC INTERPRETATION
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in dmarc_answers:
            txt_string = str(r).strip('"')
            if txt_string.startswith("v=DMARC1"):
                dns_report["dmarc_policy"] = txt_string
                
                # Evaluate DMARC alignment actions
                if "p=reject" in txt_string:
                    dns_report["dmarc_analyst_note"] = "Strict Shield (p=reject). Any mail failing SPF/DKIM alignment is completely dropped at destination."
                elif "p=quarantine" in txt_string:
                    dns_report["dmarc_analyst_note"] = "Active Isolation (p=quarantine). Mismatched mail is automatically routed directly to Spam folders."
                elif "p=none" in txt_string:
                    dns_report["dmarc_analyst_note"] = "Monitoring Only (p=none). Domain owner tracking traffic metrics, but fake emails will still land in targets' inboxes."
                break
    except Exception:
        dns_report["dmarc_analyst_note"] = "FAILED: No active DMARC alignment record published. Mail clients cannot verify sender authenticity."

    return dns_report


def parse_eml(file_bytes: bytes) -> dict:
    """
    Advanced EML parser that conducts multi-vector heuristic risk calculations
    and integrates real-time global DNS lookup metrics.
    """
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    # 1. Structural Metadata Extraction
    email_from = msg.get("From", "Unknown Sender")
    email_to = msg.get("To", "Unknown Recipient")
    email_subject = msg.get("Subject", "No Subject")
    reply_to = msg.get("Reply-To", "Not Specified")
    
    auth_results_header = msg.get("Authentication-Results", "")
    received_spf_header = msg.get("Received-SPF", "")
    
    # Extract sender domain name using clean regex matching
    sender_domain = ""
    domain_match = re.search(r'@([\w\.-]+)', email_from)
    if domain_match:
        sender_domain = domain_match.group(1).strip(">").strip("]").lower()

    # 2. Execute Live External DNS Lookup Vector!
    dns_metrics = check_dns_records(sender_domain)

    # 3. Built-in Transport Authentication Checks
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

    # 4. Robust Body Extraction
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

    extracted_text = plain_body if plain_body.strip() else clean_html_tags(html_body)

    # 🧮 5. THE RISK SCORING WEIGHT ENGINE
    calculated_risk = 0
    reasons = []
    recommended_actions = ["Monitor account logs for suspicious activity"]

    if header_mismatch:
        calculated_risk += 25
        reasons.append({"type": "header_mismatch", "message": "Reply-To address differs from display sender domain."})
    
    if spf_status == "FAIL":
        calculated_risk += 30
        reasons.append({"type": "spf_fail", "message": "SPF validation failed—unauthorized server source."})
    elif spf_status in ["SOFTFAIL", "NONE", "UNKNOWN"]:
        calculated_risk += 15
        reasons.append({"type": "sender_verification", "message": "Domain has a relaxed, spoofable mail deployment protocol."})

    if dkim_status == "FAIL":
        calculated_risk += 20
        reasons.append({"type": "dkim_fail", "message": "DKIM cryptographic signature verification is broken."})

    if dmarc_status == "FAIL":
        calculated_risk += 25
        reasons.append({"type": "dmarc_fail", "message": "DMARC alignment validation failed completely."})

    # Domain Validation Weight Modifiers
    if dns_metrics["mx_check"].startswith("FAILED"):
        calculated_risk += 25
        reasons.append({"type": "lookalike_domain", "message": "Critical: Sending domain has no valid MX mail servers configured."})

    lower_text = extracted_text.lower()
    if "lawsuit" in lower_text or "court" in lower_text or "notice" in lower_text:
        calculated_risk += 10
        reasons.append({"type": "legal_trigger", "message": "Contains sensitive legal or class-action settlement tracking keywords."})

    if "verify" in lower_text or "password" in lower_text or "login" in lower_text:
        calculated_risk += 20
        reasons.append({"type": "credential_request", "message": "Text structure indicates a verification or credential capture attempt."})

    final_risk_score = min(calculated_risk, 100)
    
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
            "sender_domain": sender_domain,
            "header_mismatch": header_mismatch
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        },
        # 🌐 Injecting your requested real-time network lookup parameters cleanly!
        "dns_intelligence": dns_metrics,
        "clean_text_content": extracted_text[:1200]
    }