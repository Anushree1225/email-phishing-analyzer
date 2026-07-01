import re
from fastapi import HTTPException

# 🎯 Broad contextual indicators that appear across email frames, headers, or footers
EMAIL_STRUCTURAL_INDICATORS = [
    "to me", "sender", "recipient", "reply", "forward",
    "inbox", "gmail", "outlook", "mail.", "unsubscribe", "view_pt", "view message",
    "secure link", "action required", "verify your", "facetime", "verification"
]

def enforce_email_structural_gate(extracted_text: str, format_type: str):
    """
    Unified Structural Gatekeeper: Checks if the extracted character streams 
    from EML, PDF, or image layouts contain verifiable email markers before running risk analysis.
    """
    if not extracted_text or len(extracted_text.strip()) < 5:
        raise HTTPException(
            status_code=400,
            detail="Validation Rejected: Please upload a valid email evidence file."
        )

    # Convert everything to lowercase for case-insensitive processing
    normalized_content = extracted_text.lower()

    # ── BRANCH 1: NATIVE EML BOUNDARY ──
    if format_type == "eml":
        has_eml_headers = any(
            kw in normalized_content for kw in ["from:", "to:", "subject:"]
        )
        if not has_eml_headers:
            raise HTTPException(
                status_code=400,
                detail="Validation Rejected: Please upload a valid email evidence file."
            )
        return

    # ── BRANCH 2: POLYMORPHIC PDF LAYERS & SCREENSHOT OCR STRINGS ──
    # 1. Flexible Email Address Checker (absorbs random spaces or artifacts around the @ symbol)
    email_address_regex = r'[\w\.-]+\s*@\s*[\w\.-]+\.\w+'
    has_email_routing_address = bool(re.search(email_address_regex, normalized_content))

    # 2. Resilient Header Token Parser: Removed \b boundaries to handle OCR container box lines (e.g. "|from:")
    has_from_header = "from" in normalized_content and ":" in normalized_content
    has_to_header = "to" in normalized_content and ":" in normalized_content
    has_subject_header = "subject" in normalized_content and ":" in normalized_content
    
    # Passes if at least two key email structural fields are present anywhere in the stream
    has_explicit_headers = sum([has_from_header, has_to_header, has_subject_header]) >= 2

    # 3. Keyword Pattern Matching
    matched_indicator_count = sum(
        1 for marker in EMAIL_STRUCTURAL_INDICATORS 
        if marker in normalized_content
    )

    # ⚖️ UNIVERSAL INCLUSION EVALUATION:
    is_valid_email_evidence = (
        has_email_routing_address or 
        has_explicit_headers or
        (matched_indicator_count >= 1)  # Keeps it highly inclusive for simulation templates
    )

    if not is_valid_email_evidence:
        raise HTTPException(
            status_code=400,
            detail="Validation Rejected: Please upload a valid email evidence file."
        )