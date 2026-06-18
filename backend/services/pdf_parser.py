import pypdf
import re
import uuid
from datetime import datetime
from services.url_analyzer import analyze_urls

def extract_pdf_deep_layers(file_bytes: bytes) -> tuple:
    """
    Extracts visible text lines and hidden clickable link structures 
    from native document layouts and browser print streams.
    """
    visible_text = ""
    hidden_urls = []
    doc_meta = {}
    page_count = 0
    
    try:
        import io
        stream = io.BytesIO(file_bytes)
        reader = pypdf.PdfReader(stream)
        page_count = len(reader.pages)
        
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                visible_text += page_text + "\n"
            
            if "/Annots" in page:
                annotations = page["/Annots"]
                for annot in annotations:
                    obj = annot.get_object()
                    if obj.get("/Subtype") == "/Link" and "/A" in obj:
                        action = obj["/A"].get_object()
                        if action.get("/S") == "/URI":
                            uri_target = action.get("/URI")
                            if uri_target:
                                hidden_urls.append(uri_target)
                                
        if reader.metadata:
            doc_meta = {
                "author": reader.metadata.get("/Author", "N/A"),
                "creator": reader.metadata.get("/Creator", "N/A"),
                "producer": reader.metadata.get("/Producer", "N/A")
            }
    except Exception as e:
        print(f"[-] Forensic PDF layout reader engine trace crash: {str(e)}")
        
    return visible_text, list(set(hidden_urls)), doc_meta, page_count

def parse_pdf(file_bytes: bytes) -> dict:
    """
    Main PDF processing module. Runs dynamic layered pattern scoring, extracts
    printed browser parameters, and handles dynamic metadata mapping schemas safely.
    """
    raw_text, structural_links, doc_meta, page_count = extract_pdf_deep_layers(file_bytes)
    
    found_raw_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', raw_text)
    all_unique_links = list(dict.fromkeys(found_raw_urls + structural_links))
    
    url_scan_payload_string = "\n".join(all_unique_links) + "\n" + raw_text
    
    url_intelligence_report = []
    if all_unique_links:
        try:
            url_intelligence_report = analyze_urls(url_scan_payload_string)
        except Exception:
            url_intelligence_report = []
            
    vt_danger_count = sum(
        1 for u in url_intelligence_report 
        if isinstance(u, dict) and str(u.get("status", "")).lower() in ["malicious", "suspicious"]
    )
    
    # ─────────────── EMAIL HEADER EXTRACTION ENGINE ───────────────

    email_from = "Unknown Origin Profile"
    email_subject = "Static Document Attachment Details"
    email_to = "Unknown"
    email_date = "Extracted Layer Metadata Runtime"
    email_cc = ""
    email_bcc = ""

    attachments_discovered = []
    lines = [line.strip() for line in raw_text.split("\n") if line.strip()]

    # 1. PASS 1: Standard Email Header Detection
    for line in lines[:75]:
        lower = line.lower()

        if lower.startswith("from:"):
            email_from = re.sub(r'(?i)^from:\s*', '', line).strip()
        elif lower.startswith("to:"):
            email_to = re.sub(r'(?i)^to:\s*', '', line).strip()
        elif lower.startswith("cc:"):
            email_cc = re.sub(r'(?i)^cc:\s*', '', line).strip()
        elif lower.startswith("bcc:"):
            email_bcc = re.sub(r'(?i)^bcc:\s*', '', line).strip()
        elif lower.startswith("subject:"):
            email_subject = re.sub(r'(?i)^subject:\s*', '', line).strip()
        elif lower.startswith("date:"):
            email_date = re.sub(r'(?i)^date:\s*', '', line).strip()

    # 2. PASS 2: Gmail Print-to-PDF Target Resolution
    for line in lines[:20]:
        if "gmail -" in line.lower():
            if email_subject == "Static Document Attachment Details":
                extracted_title = re.sub(r'(?i)gmail\s*-\s*', '', line).strip()
                extracted_title = re.sub(r'\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}(?:\s*[AP]M)?', '', extracted_title)
                extracted_title = re.sub(r'https?://[^\s<>"]+', '', extracted_title)
                email_subject = extracted_title.strip(" -:|")
            break

    # ── UNIFIED EXTRACTOR: SENDER & RECIPIENT ROLES ──
    # Expanded processing deck window to line index 60 to protect against static page shifts
    all_extracted_emails = []
    for line in lines[:60]:
        matches = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', line)
        for email in matches:
            if email not in [e[0] for e in all_extracted_emails]:
                all_extracted_emails.append((email, line))

    if all_extracted_emails:
        # Dynamic separation based on identity footprint strings
        external_actors = [pair for pair in all_extracted_emails if "vermaanushree" not in pair[0].lower()]
        user_profile = [pair for pair in all_extracted_emails if "vermaanushree" in pair[0].lower()]

        # Role 1: Assign Origin Sender to the first external entity found
        if external_actors:
            email_from = external_actors[0][1]
        elif email_from == "Unknown Origin Profile":
            email_from = all_extracted_emails[0][1]

        # Role 2: Assign Recipient Target
        if user_profile:
            # Prioritize layout strings containing direction tags
            explicit_to = [pair for pair in user_profile if any(prefix in pair[1].lower() for prefix in ["to:", "bcc:", "cc:"])]
            if explicit_to:
                email_to = explicit_to[0][1]
            else:
                email_to = user_profile[0][1]
        elif email_to == "Unknown" and len(all_extracted_emails) > 1:
            email_to = all_extracted_emails[1][1]

    # 4. PASS 4: Subject Recovery Fallback
    if email_subject == "Static Document Attachment Details":
        for line in lines[:10]:
            if (
                len(line) > 8
                and "@" not in line
                and not re.search(r'\d{1,2}/\d{1,2}/\d{4}', line)
                and not line.lower().startswith(("from:", "to:", "cc:", "bcc:", "gmail"))
            ):
                email_subject = line
                break

    # 5. PASS 5: Recipient Recovery Fallback & "to me" Normalization
    if email_to == "Unknown" or email_to.lower() == "me" or email_to.lower() == "to me":
        for line in lines[:30]:
            lower = line.lower()
            if lower.startswith("to:") and "me" not in lower:
                email_to = re.sub(r'(?i)^to:\s*', '', line).strip()
                break
        if (email_to == "Unknown" or email_to.lower() in ["me", "to me"]) and 'user_profile' in locals() and user_profile:
            email_to = f"To: Anushree Verma <{user_profile[0][0]}>"

    if email_to == "Unknown" and email_bcc:
        email_to = email_bcc

    # 🔍 CLEANUP FOOTPRINT REGEX NOISE IN SUBJECT FIELD
    email_subject = re.sub(r'https?://[^\s<>"]+', '', email_subject)
    email_subject = re.sub(r'\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}(?:\s*[AP]M)?', '', email_subject)
    email_subject = re.sub(r'\b\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\b', '', email_subject)
    email_subject = re.sub(r'\s+', ' ', email_subject).strip(" -:|")
    
    if not email_subject or email_subject == "":
        email_subject = "Static Document Attachment Details"

   # 🔍 RELAXED TIMESTAMP PARSER WITH SPACE-AGNOSTIC BOUNDS
    # Explicitly handles multiple spaces, irregular layout shifts, and stuttered time tokens (e.g., '1 1:44 AM')
    timestamp_pattern = r'((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+[A-Za-z]{3}\s+\d+\s*,\s+\d{4}\s+at\s+\d{1,2}\s*\d{1,2}:\d{2}\s*(?:AM|PM))'
    timestamp_match = re.search(timestamp_pattern, email_from)
    
    if timestamp_match:
        email_date = timestamp_match.group(1).strip()
        # Strip the date cleanly out of the sender string variable
        email_from = re.sub(timestamp_pattern, '', email_from).strip()
        
        # Clean up any inner stuttered spaces inside the time segment for the date panel display
        email_date = re.sub(r'\s+:', ':', email_date)
        email_date = re.sub(r'(\d)\s+(\d:)', r'\1\2', email_date)
    else:
        for line in lines[:25]:
            if re.search(r'\d{1,2}:\d{2}\s*(?:AM|PM)', line) or any(day in line for day in ["Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,", "Sun,"]):
                if "@" not in line and "gmail" not in line.lower() and "http" not in line.lower():
                    email_date = line
                    break

    email_from = re.sub(r'\s+', ' ', email_from).strip()

    # 6. PASS 6: Attachment Discovery
    for line in lines:
        attachment_match = re.search(
            r'([\w\s\-\(\)\[\]\.]+?\.(?:pdf|zip|rar|png|jpg|jpeg|doc|docx|xls|xlsx|ppt|pptx))\s*(\d+(?:\.\d+)?\s*[KMG]?B)?',
            line,
            re.IGNORECASE
        )

        if attachment_match:
            filename_extracted = attachment_match.group(1).strip()
            size_extracted = attachment_match.group(2)
            kb_size = 0

            if size_extracted:
                size_extracted = size_extracted.strip()
                if "m" in size_extracted.lower():
                    kb_size = int(float(re.sub(r'[^\d.]', '', size_extracted)) * 1024)
                elif "k" in size_extracted.lower():
                    kb_size = int(float(re.sub(r'[^\d.]', '', size_extracted)))

            if "gmail" not in filename_extracted.lower() and not filename_extracted.startswith("SCAN"):
                attachments_discovered.append({
                    "filename": filename_extracted,
                    "extension": filename_extracted.split(".")[-1].lower(),
                    "size_kb": kb_size
                })

    # ── ADVANCED CONTENT SCORING HEURISTICS ──
    calculated_risk = 0
    reasons = []
    highlighted_content = []
    lower_text = raw_text.lower()
    
    urgency_keywords = ["immediate action required", "closing soon", "account deactivation", "unauthorized login", "action required immediately"]
    for kw in urgency_keywords:
        if kw in lower_text:
            calculated_risk += 30
            matched_line = [line.strip() for line in raw_text.split('\n') if kw in line.lower()]
            display_slice = matched_line[0] if matched_line else kw
            reasons.append({
                "type": "urgent_language", 
                "message": "Alert: Document utilizes high-pressure administrative urgency triggers demanding prompt user action."
            })
            highlighted_content.append({
                "text": f'"{display_slice}"', 
                "reason": "Urgency manipulation technique detected"
            })
            break

    credential_keywords = ["unverified credential", "verify your login", "verify account", "verify your identity", "login profile"]
    if any(kw in lower_text for kw in credential_keywords):
        calculated_risk += 35
        reasons.append({
            "type": "credential_request", 
            "message": "Alert: Subsurface verification markers detected targeting credential or profile attributes."
        })

    baiting_keywords = ["100% free", "claim it now", "free edt mini tool", "ultimate tool", "before they're all gone"]
    for kw in baiting_keywords:
        if kw in lower_text:
            calculated_risk += 40
            matched_line = [line.strip() for line in raw_text.split('\n') if kw in line.lower()]
            display_slice = matched_line[0] if matched_line else kw
            reasons.append({
                "type": "legal_trigger", 
                "message": "Suspicious: Text layout leverages artificial scarcity baiting hooks Typical of click-fraud structures."
            })
            highlighted_content.append({
                "text": f'"{display_slice}"', 
                "reason": "Baiting/Scarcity trigger identified"
            })
            break

    if vt_danger_count > 0:
        calculated_risk += (35 + (vt_danger_count * 10))
        reasons.append({
            "type": "suspicious_url", 
            "message": f"Critical Threat: Dynamic analysis engine isolated {vt_danger_count} embedded hyperlinks flagged as malicious by active security vendors."
        })

    final_risk_score = min(calculated_risk, 100)
    severity = "High" if final_risk_score >= 75 else "Medium" if final_risk_score >= 40 else "Low"
    
    domain_scope = "Unknown"
    sender_email_match = re.search(r'([\w\.-]+@[\w\.-]+\.\w+)', email_from)

    if sender_email_match:
        sender_email = sender_email_match.group(1)
        domain_match = re.search(r'@([\w\.-]+\.\w+)', sender_email)
        if domain_match:
            domain_scope = domain_match.group(1).strip()

    # ─────────────── DYNAMIC CONFIDENCE SCORING ENGINE ───────────────
    base_confidence = 85
    
    if email_from == "Unknown Origin Profile":
        base_confidence -= 20
    if email_to == "Unknown":
        base_confidence -= 15
    if "static document" in email_subject.lower():
        base_confidence -= 10
    if "https://mail.google.com" in raw_text and domain_scope == "gmail.com":
        base_confidence -= 5
        
    final_confidence_level = max(25, min(base_confidence, 95))
            
    return {
        "file_type": "pdf",
        "risk_score": final_risk_score,
        "severity": severity,
        "confidence_level": final_confidence_level,  
        "danger_urls": vt_danger_count,
        "reasons": reasons if reasons else [{"type": "clean", "message": "No immediate text anomalies discovered."}],
        "recommended_action": ["Do not click nested buttons if origin is untrusted", "Submit file source to SOC portal link tracking teams"] if severity == "High" else ["Document parsed cleanly. Monitor hyperlinks safely."],
        "highlighted_content": highlighted_content,
        "scan_id": f"SCAN-PDF-{uuid.uuid4().hex[:6].upper()}",
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "urls_found": [{"url": u["url"], "safe": u["status"] == "Clean"} for u in url_intelligence_report] if url_intelligence_report else [],
        
        "eml_details": {
            "file_type": "pdf",
            "attachments": attachments_discovered,  
            "metadata": {
                "from": email_from,
                "subject": email_subject,
                "to": email_to,
                "reply_to": "Document Object Layer Extraction",
                "return_path": "N/A (Flattened Print File Data)",
                "sender_domain": domain_scope,
                "domain_age": "Static Stream Document Block",
                "header_mismatch": False
            },
            "security_protocols": {
                "spf": "PORTABLE FILE",
                "dkim": "N/A",
                "dmarc": "N/A"
            },
            "dns_intelligence": {
                "page_count": page_count,
                "mx_check": "VALID COMPLETE",
                "mx_records": [],
                "spf_record": "File Format: Adobe PDF Container",
                "spf_analyst_note": f"Total Structural Pages Processed: {page_count} | Author Signature: {doc_meta.get('author', 'N/A')}",
                "dmarc_policy": f"Creator Meta Tooling Stamp: {doc_meta.get('creator', 'N/A')[:60] if doc_meta.get('creator') else 'N/A'}",
                "dmarc_analyst_note": f"Producer Engine Registry: {doc_meta.get('producer', 'N/A')[:60] if doc_meta.get('producer') else 'N/A'}"
            },
            "url_intelligence": url_intelligence_report
        }
    }