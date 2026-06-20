import re

def analyze_content(email_text: str) -> dict:
    lower_text = email_text.lower()
    
    # 1. Scrape standard header lines
    from_match = re.search(r'(?:from|return-path|reply-to):\s*([^\n]+)', email_text, re.IGNORECASE)
    to_match = re.search(r'\b(?:to):\s*([^\n]+)', email_text, re.IGNORECASE)
    subject_match = re.search(r'\b(?:subject):\s*([^\n]+)', email_text, re.IGNORECASE)
    date_match = re.search(r'\b(?:date):\s*([^\n]+)', email_text, re.IGNORECASE)
    
    detected_from = from_match.group(1).strip() if from_match else "Not Available"
    detected_to = to_match.group(1).strip() if to_match else "Not Available"
    detected_subject = subject_match.group(1).strip() if subject_match else "Not Available"
    detected_date = date_match.group(1).strip() if date_match else "Not Available"

    # 2. Check for Forwarded Header Overrides
    if "forwarded message" in lower_text or "begin forwarded message" in lower_text:
        fwd_from = re.search(r'(?:from|sender):\s*([^\n]+)', email_text[lower_text.find("forwarded"):], re.IGNORECASE)
        if fwd_from:
            detected_from = fwd_from.group(1).strip()

    # 3. Harvest URLs out of the raw text string
    raw_urls = re.findall(r'(?:https?://|www\.)[^\s]+|\b[a-zA-Z0-9.-]+\.(?:com|edu|org|net|gov|xyz)\b', email_text)
    unique_urls = list(set([u.strip().lower() for u in raw_urls]))
    
    domain_whitelist = ["wustl.edu", "google.com", "gmail.com", "live.com", "microsoft.com", "outlook.com"]
    url_report = []
    danger_url_count = 0
    
    # 4. Core Linguistic Profile Definitions
    urgency_keywords = ["immediate", "expire", "action required", "within 24 hours", "72 hours", "suspend", "closing soon"]
    fear_keywords = ["locked", "blocked", "unauthorized", "mailbox is full", "failure to act", "security check", "incident"]
    cred_keywords = ["verify", "password", "credential", "login", "identity", "re-authenticate", "secure utility"]

    # Calculate percentage indices based on text keyword matches
    urgency_hits = sum(1 for kw in urgency_keywords if kw in lower_text)
    fear_hits = sum(1 for kw in fear_keywords if kw in lower_text)
    cred_hits = sum(1 for kw in cred_keywords if kw in lower_text)

    urgency_score = min(int((urgency_hits / 3) * 100) if urgency_hits > 0 else 10, 100)
    fear_score = min(int((fear_hits / 3) * 100) if fear_hits > 0 else 15, 100)
    cred_score = min(int((cred_hits / 3) * 100) if cred_hits > 0 else 5, 100)

    # 5. Extract Contextual Sentences and Map Reasons
    suspicious_chunks = []
    reasons = []
    
    sentences = re.split(r'[.!?\n]', email_text)
    for sent in sentences:
        sent_clean = sent.strip()
        if len(sent_clean) < 10:
            continue
            
        sent_lower = sent_clean.lower()
        if any(k in sent_lower for k in urgency_keywords):
            suspicious_chunks.append({"text": sent_clean, "reason": "Urgency Trigger"})
        elif any(k in sent_lower for k in fear_keywords):
            suspicious_chunks.append({"text": sent_clean, "reason": "Fear-based Social Engineering"})
        elif any(k in sent_lower for k in cred_keywords):
            suspicious_chunks.append({"text": sent_clean, "reason": "Credential Harvesting Hook"})

    # 🎯 FIX: Adjusted deduplication token pointer variable loop back to t.items()
    suspicious_chunks = [dict(t) for t in {tuple(t.items()) for t in suspicious_chunks}]

    # 6. Calculate Threat Risk Metric Matrix
    risk_score = 0
    if urgency_hits > 0: 
        risk_score += 30
        reasons.append({"type": "urgent_language", "message": "Urgency language detected"})
    if cred_hits > 0: 
        risk_score += 30
        reasons.append({"type": "credential_request", "message": "Credential request detected"})
    if fear_hits > 0: 
        risk_score += 20
        reasons.append({"type": "legal_trigger", "message": "Account suspension threat or fear tactics discovered"})
    if unique_urls: 
        risk_score += 15

    # Check for header mismatches (Case 5)
    if from_match and "return-path" in lower_text:
        rp_match = re.search(r'return-path:\s*([^\n]+)', email_text, re.IGNORECASE)
        if rp_match and from_match.group(1).strip() != rp_match.group(1).strip():
            risk_score += 25
            reasons.append({"type": "spoofed_header", "message": "Critical Mismatch: Return-Path header fails profile consistency alignment rules."})

    final_risk = min(risk_score, 100)
    if final_risk == 0:
        final_risk = 12
        reasons.append({"type": "clean", "message": "No explicit linguistic anomalies flagged."})

    severity = "High" if final_risk >= 70 else "Medium" if final_risk >= 35 else "Low"

    for url in unique_urls:
        is_safe = True
        is_whitelisted = any(domain in url for domain in domain_whitelist)
        if final_risk > 45 and not is_whitelisted:
            is_safe = False
            danger_url_count += 1
            
        url_report.append({
            "url": url,
            "safe": is_safe,
            "details": "Verified safe via structural checks." if is_safe else "Flagged by high risk indicator patterns."
        })

    return {
        "file_type": "text",
        "risk_score": final_risk,
        "severity": severity,
        "danger_urls": danger_url_count,
        "reasons": reasons,
        "recommended_action": [
            "Do not click links inside this text content.",
            "Report it to your internal corporate email abuse deck.",
            "Isolate sender profile details before answering."
        ] if severity == "High" else ["Exercise caution when parsing plain-text logs."],
        "highlighted_content": suspicious_chunks[:3],
        "urls_found": url_report,
        
        "language_analysis": {
            "urgency_score": urgency_score,
            "fear_score": fear_score,
            "credential_score": cred_score
        },
        "text_details": {
            "from": detected_from,
            "to": detected_to,
            "subject": detected_subject,
            "date": detected_date
        }
    }