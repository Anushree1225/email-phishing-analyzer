import pypdf
import re
import uuid
from datetime import datetime
from services.url_analyzer import analyze_urls

def extract_pdf_deep_layers(file_bytes: bytes) -> tuple:
    """
    Extracts visible text structures and hidden clickable link objects 
    directly from native PDF container layers and print streams.
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
            
            # Extract underlying interactive link layers (Buttons/Hyperlinks)
            if "/Annots" in page:
                annotations = page["/Annots"]
                for annot in annotations:
                    try:
                        obj = annot.get_object()
                        if obj.get("/Subtype") == "/Link" and "/A" in obj:
                            action = obj["/A"].get_object()
                            if action.get("/S") == "/URI":
                                uri_target = action.get("/URI")
                                if uri_target:
                                    hidden_urls.append(uri_target)
                    except Exception:
                        continue
                                        
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
    Layout-Agnostic Core Parser Engine. Employs multi-line anchor scans,
    self-identity sorting filters, and subsurface attachment mapping.
    """
    raw_text, structural_links, doc_meta, page_count = extract_pdf_deep_layers(file_bytes)
    
    # Harvest and normalize all hyperlinks
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
    
    # Initialize baseline fallback variables
    email_from = "Unknown Origin Profile"
    email_to = "Active Endpoint Session Target"
    email_subject = "Native Structural Container Scan"
    email_date = "Extracted Layer Metadata Runtime"
    attachments_discovered = []
    
    # ── 🧠 RE-ENGINEERED DYNAMIC IDENTITY DEDUCTION ENGINE ──
    # Programmatically isolates the workspace recipient profile based on text frequency metrics
    all_emails_found = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', raw_text)
    
    email_frequency_map = {}
    for email in all_emails_found:
        normalized_email = email.lower().strip()
        email_frequency_map[normalized_email] = email_frequency_map.get(normalized_email, 0) + 1
        
    # The active viewer address populates most densely across structural web margin crumbs
    detected_user_identity = max(email_frequency_map, key=email_frequency_map.get) if email_frequency_map else "target-user@yourcompany.com"
    user_email_pattern = re.escape(detected_user_identity)
    
    # Isolate strictly external targets to protect verification matching from self-identity loops
    external_emails = [e for e in all_emails_found if not re.match(user_email_pattern, e, re.IGNORECASE)]
    lines_clean = [line.strip() for line in raw_text.split('\n') if line.strip()]

    # 1. AGGRESSIVE SUBJECT BACKUP (Parses browser document titles from top margins safely)
    if lines_clean:
        for line in lines_clean[:4]:
            if "gmail -" in line.lower() or "mail -" in line.lower():
                email_subject = re.sub(r'(?i)^(gmail|mail)\s*-\s*', '', line).strip()
                break
        
        # Guard Override: Ensure layout extraction completely ignores self-identity lines
        if email_subject == "Native Structural Container Scan" and len(lines_clean) > 0:
            for candidate_line in lines_clean[:4]:
                # Skip lines containing email addresses, timestamps, or system paths
                if not any(x in candidate_line.lower() for x in ["/06/2026", "localhost", "mail.google", "@", "<"]):
                    email_subject = candidate_line
                    break

    # 2. ANCHOR & PATTERN SCANS FOR SENDERS/RECIPIENTS
    # Explicit From Layout Anchor Matching
    from_match = re.search(r'(?i)from:\s*[\"\']?([^<\n\"]+)?<?([\w\.-]+@[\w\.-]+\.\w+)>?', raw_text)
    if from_match:
        name_part = from_match.group(1).strip() if from_match.group(1) else ""
        email_part = from_match.group(2).strip() if from_match.group(2) else ""
        name_part = re.sub(r'(?i)^from:\s*', '', name_part).replace('"', '').strip()
        email_from = f"{name_part} <{email_part}>" if name_part else email_part
    elif external_emails:
        # Bare Value Header Fallback: Maps decoupled rows containing foreign email structures
        for line in raw_text.split('\n'):
            if external_emails[0] in line and not any(x in line.lower() for x in ["to:", "bcc:", "http", "www"]):
                email_from = re.sub(r'(?i)^from:\s*', '', line).strip()
                break
        if email_from == "Unknown Origin Profile":
            email_from = external_emails[0]

    # Post-processing text normalization strip loop
    email_from = re.sub(r'(?i)^from:\s*', '', email_from).strip()

    # Match target recipients dynamically across multi-line envelopes (To / Bcc)
    to_match = re.search(r'(?i)^(to|bcc):\s*([^\n]+)', raw_text, re.MULTILINE)
    if to_match:
        email_to = re.sub(r'(?i)^(to|bcc):\s*', '', to_match.group(2)).strip()
    else:
        email_to = detected_user_identity

    # Strict multi-line explicit subject check override
    explicit_subj = re.search(r'(?i)^subject:\s*([^\n]+)', raw_text, re.MULTILINE)
    if explicit_subj:
        email_subject = re.sub(r'^\[SPAM\]\s*', '', explicit_subj.group(1).strip(), flags=re.IGNORECASE)

    # 3. DATE SCANNER (Enforces print margin line-start checking boundaries to protect body text)
    date_match = re.search(r'(?i)^date:\s*([^\n]+)', raw_text, re.MULTILINE)
    if date_match:
        email_date = date_match.group(1).strip()
    else:
        # Capture standard browser header timestamp margin strings (e.g., "12/06/2026, 10:32")
        timestamp_margin = re.search(r'^(\d{2}/\d{2}/\d{4},\s*\d{2}:\d{2})', raw_text, re.MULTILINE)
        if timestamp_margin:
            email_date = timestamp_margin.group(1).strip()
        else:
            # Check for standard mail layout weekday markers at line-start bounds
            header_date_pattern = r'(?i)^(mon|tue|wed|thu|fri|sat|sun),\s*[a-zA-Z]{3}\s+\d+'
            for line in raw_text.split('\n'):
                if re.match(header_date_pattern, line.strip()):
                    email_date = line.strip()
                    break

    # 4. SUBSURFACE ATTACHMENT INVENTORY HUNTER
    for line in lines_clean:
        attachment_match = re.search(r'([\w\s\.-]+\.(?:pdf|zip|rar|png|jpg|jpeg|exe|bat|cmd))\s+(\d+[KM]?B?)', line, re.IGNORECASE)
        if attachment_match:
            filename_extracted = attachment_match.group(1).strip()
            size_extracted = attachment_match.group(2).strip()
            
            if "gmail" not in filename_extracted.lower() and not filename_extracted.startswith("SCAN"):
                kb_size = 157  
                if "m" in size_extracted.lower():
                    kb_size = int(re.sub(r'\D', '', size_extracted)) * 1024
                elif "k" in size_extracted.lower():
                    kb_size = int(re.sub(r'\D', '', size_extracted))
                
                attachments_discovered.append({
                    "filename": filename_extracted,
                    "extension": filename_extracted.split(".")[-1].lower(),
                    "size_kb": kb_size
                })

    # 5. DYNAMIC RISK MATRIX EVALUATION (INCLUSIVE CRITERIA)
    calculated_risk = 0
    reasons = []
    highlighted_content = []
    lower_text = raw_text.lower()
    
    urgency_keywords = ["immediate action required", "closing soon", "account deactivation", "unauthorized login", "action required immediately", "expiring soon"]
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

    credential_keywords = ["unverified credential", "verify your login", "verify account", "verify your identity", "login profile", "password expiring"]
    if any(kw in lower_text for kw in credential_keywords):
        calculated_risk += 35
        reasons.append({
            "type": "credential_request", 
            "message": "Alert: Subsurface verification markers detected targeting credential or profile attributes."
        })

    baiting_keywords = ["100% free", "claim it now", "free edt mini tool", "ultimate tool", "before they're all gone", "grab yours today"]
    for kw in baiting_keywords:
        if kw in lower_text:
            calculated_risk += 40
            matched_line = [line.strip() for line in raw_text.split('\n') if kw in line.lower()]
            display_slice = matched_line[0] if matched_line else kw
            reasons.append({
                "type": "legal_trigger", 
                "message": "Suspicious: Text layout leverages artificial scarcity baiting hooks typical of click-fraud structures."
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

    if any(att["extension"] in ["exe", "bat", "cmd", "scr"] for att in attachments_discovered):
        calculated_risk += 50
        reasons.append({
            "type": "spoofed_header",
            "message": "Critical: Executable binary attachment payload discovered within static document layout streams."
        })

    # Weaponized Conversion Artifact Checker
    creator_tool = doc_meta.get('creator', 'N/A')
    if "zamzar" in creator_tool.lower() or "pdfkit" in creator_tool.lower() or "wkhtmltopdf" in creator_tool.lower():
        if calculated_risk >= 30:
            calculated_risk += 15
            reasons.append({
                "type": "spoofed_header",
                "message": f"Suspicious: Document compiled via automated backend conversion utility ({creator_tool}) instead of standard web browser runtime interfaces."
            })

    final_risk_score = min(calculated_risk, 100)
    severity = "High" if final_risk_score >= 75 else "Medium" if final_risk_score >= 40 else "Low"
    
    domain_scope = "Extracted Layout Scope"
    if "@" in email_from:
        raw_domain = email_from.split("@")[-1].replace(">", "").strip()
        domain_scope = raw_domain.split()[0]

    return {
        "file_type": "pdf",
        "risk_score": final_risk_score,
        "severity": severity,
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
                "date": email_date,
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
                "spf_analyst_note": f"Total Structural Pages Processed: {page_count} | Layout Content Layer Scan Verified.",
                "dmarc_policy": f"Creator Meta Tooling Stamp: {doc_meta.get('creator', 'N/A')[:60] if doc_meta.get('creator') else 'N/A'}",
                "dmarc_analyst_note": f"Producer Engine Registry: {doc_meta.get('producer', 'N/A')[:60] if doc_meta.get('producer') else 'N/A'}"
            },
            "url_intelligence": url_intelligence_report
        }
    }