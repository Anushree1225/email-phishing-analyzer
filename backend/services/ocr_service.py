import cv2
import easyocr
import numpy as np
import re

try:
    # Initialize EasyOCR once globally
    reader = easyocr.Reader(['en'], gpu=False)
except Exception as e:
    print(f"[-] OCR Framework initialization notice: {str(e)}")
    reader = None

def extract_text_and_qr_from_image(file_bytes: bytes) -> tuple:
    """
    Forensic Raster Analyzer: Processes image streams to extract layout text,
    tracks structural word bounding box coordinates, and decodes QR matrices.
    """
    extracted_text = ""
    discovered_urls = []
    ocr_blocks = []  # Holds coordinates for frontend visual boxing

    try:
        np_arr = np.frombuffer(file_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if img is None:
            return "Error: Unable to process or decode image layout container.", []

        # 1. LAYER 1: COMPUTER VISION QR DECODER
        qr_detector = cv2.QRCodeDetector()
        retval, decoded_info, _, _ = qr_detector.detectAndDecodeMulti(img)
        if retval:
            for url in decoded_info:
                if url and url.strip():
                    discovered_urls.append(url.strip())

        # 2. LAYER 2: DETAILED OCR TEXT & SPATIAL COORDINATE RECOVERY
        if reader:
            # Setting detail=1 returns bounding box dimensions + text strings
            raw_ocr = reader.readtext(img, detail=1)
            text_lines = []
            
            for box, text, confidence in raw_ocr:
                text_lines.append(text)
                # Format coordinates cleanly for the React frontend: [[x1, y1], [x2, y2]]
                ocr_blocks.append({
                    "text": text,
                    "points": [[int(pt[0]), int(pt[1])] for pt in box]
                })
            
            extracted_text = "\n".join(text_lines)
        else:
            extracted_text = "OCR Engine unavailable."

    except Exception as e:
        print(f"[-] Image module extraction deck trace crash: {str(e)}")
        extracted_text = f"Forensic image extraction crash exception: {str(e)}"

    # We return the text and urls directly. To pass ocr_blocks, 
    # we'll hook it right into your analyze.py router payload context next!
    return extracted_text, list(set(discovered_urls))