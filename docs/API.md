# 📡 API Documentation

# Email Phishing Analyzer API

This document describes the REST API endpoints exposed by the Email Phishing Analyzer backend.

Base URL (local development):

```text
http://localhost:8000
```

---

# Authentication

Currently, the API does not require authentication.

Future versions may implement:

* JWT Authentication
* User Accounts
* API Keys

---

# Endpoints Overview

| Method | Endpoint        | Description               |
| ------ | --------------- | ------------------------- |
| POST   | `/analyze/text` | Analyze pasted email text |
| POST   | `/analyze/file` | Analyze uploaded files    |

---

# 1. Analyze Email Text

Analyze raw email content pasted by the user.

## Endpoint

```http
POST /analyze/text
```

## Request Body

Content-Type:

```text
application/json
```

Example request:

```json
{
  "email_text": "Your account will be suspended. Click here immediately to verify your credentials."
}
```

---

## Successful Response

```json
{
  "risk_score": 78,
  "severity": "High",
  "file_type": "text",
  "danger_urls": 1,
  "reasons": [
    {
      "type": "urgency",
      "message": "Urgent language detected"
    },
    {
      "type": "credential_request",
      "message": "Credential harvesting attempt detected"
    }
  ],
  "recommended_action": [
    "Do not click suspicious links.",
    "Verify the sender independently."
  ]
}
```

---

## Response Fields

| Field              | Type    | Description                       |
| ------------------ | ------- | --------------------------------- |
| risk_score         | Integer | Final phishing risk score (0–100) |
| severity           | String  | Threat severity level             |
| file_type          | String  | Input type analyzed               |
| reasons            | Array   | List of detected indicators       |
| danger_urls        | Integer | Number of suspicious URLs         |
| recommended_action | Array   | Suggested remediation actions     |

---

# 2. Analyze Uploaded File

Analyze uploaded email files, PDFs, or screenshots.

Supported file types:

* `.eml`
* `.pdf`
* `.png`
* `.jpg`
* `.jpeg`

## Endpoint

```http
POST /analyze/file
```

## Request

Content-Type:

```text
multipart/form-data
```

Example using cURL:

```bash
curl -X POST "http://localhost:8000/analyze/file" \
-F "file=@sample.eml"
```

---

## Example Response

```json
{
  "file_type": "eml",
  "risk_score": 92,
  "severity": "Critical",
  "danger_urls": 2,
  "confidence_level": 91,
  "reasons": [
    {
      "type": "spoofed_header",
      "message": "SPF validation failed"
    }
  ],
  "eml_details": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  }
}
```

---

# File-Type Specific Responses

## EML Analysis

Additional response fields:

| Field       | Description                   |
| ----------- | ----------------------------- |
| eml_details | Email authentication metadata |
| spf         | SPF validation result         |
| dkim        | DKIM validation result        |
| dmarc       | DMARC validation result       |

---

## PDF Analysis

Additional response fields:

| Field          | Description                   |
| -------------- | ----------------------------- |
| extracted_text | Text extracted from the PDF   |
| urls_found     | URLs detected inside document |

---

## Image Analysis

Additional response fields:

| Field                 | Description                    |
| --------------------- | ------------------------------ |
| image_analysis        | OCR and image forensic results |
| extracted_content_raw | OCR extracted text             |
| qr_codes_found        | Number of QR codes detected    |
| visible_urls_count    | Number of visible URLs         |

Example:

```json
{
  "image_analysis": {
    "ocr_status": "SUCCESS",
    "dimensions": "1920x1080",
    "word_count": 134,
    "qr_codes_found": 1,
    "visible_urls_count": 2
  }
}
```

---

# Error Responses

## Invalid File Type

Status Code:

```text
400 Bad Request
```

Example:

```json
{
  "detail": "Unsupported file type."
}
```

---

## Empty Input

Status Code:

```text
400 Bad Request
```

Example:

```json
{
  "detail": "No email text provided."
}
```

---

## Internal Server Error

Status Code:

```text
500 Internal Server Error
```

Example:

```json
{
  "detail": "Analysis failed due to an internal server error."
}
```

---

# HTTP Status Codes

| Status Code | Meaning               |
| ----------- | --------------------- |
| 200         | Request successful    |
| 400         | Invalid request       |
| 422         | Validation error      |
| 500         | Internal server error |

---

# Example API Workflow

1. User uploads a suspicious email or screenshot.
2. Frontend sends request to backend.
3. Backend determines input type.
4. Appropriate analysis pipeline is executed.
5. Risk score and findings are generated.
6. Structured JSON response is returned.
7. Frontend renders the threat report dashboard.

---

# Future API Enhancements

* Authentication support
* Batch file analysis
* Report export API
* Threat intelligence integration
* Scan history endpoints
* Real-time URL reputation APIs
* SIEM connector endpoints
