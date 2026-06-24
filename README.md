# 🛡️ Email Phishing Analyzer

An advanced cybersecurity tool developed as part of the **Information Security Internship Project** by **Anushree Verma** and **Arpita Verma**.

The platform helps users identify phishing threats by analyzing multiple input formats of emails. Users can paste raw email text or upload `.eml` files, `.pdf` documents, and email screenshots (`.png`, `.jpg`, `.jpeg`).

The system combines email header analysis, PDF parsing, image-based OCR, QR-code scanning, linguistic analysis, and risk scoring to generate an instant, easy-to-understand threat report.

🔗 **Repository:** https://github.com/Anushree1225/email-phishing-analyzer

---

## 🚀 Key Features

### 📄 Multi-Format Analysis

The system supports multiple input formats:

* **Plain Text Emails** – Paste suspicious email content directly.
* **EML Files** – Upload complete email files with metadata and headers.
* **PDF Format** – Analyze PDF generate format of an email.
* **Image Screenshots** – Upload screenshots of emails..

---

### 🧠 Smart Input Detection

Automatically detects the uploaded content type and routes it to the appropriate analysis pipeline.

Supported formats include:

* `.txt`
* `.eml`
* `.pdf`
* `.png`
* `.jpg`
* `.jpeg`

---

### 📧 Email Header Security Analysis

For `.eml` files, the analyzer extracts hidden email metadata and validates:

* SPF authentication
* DKIM authentication
* DMARC policies
* Sender spoofing indicators
* Header inconsistencies

This helps determine whether an email may have originated from a forged or unauthorized source.

---

### 📑 PDF Threat Analysis

The PDF parser:

* Extracts embedded text.
* Identifies suspicious URLs.
* Detects social engineering language.
* Searches for phishing indicators hidden inside documents.

---

### 📸 Screenshot & Image Forensics

For image-based inputs (`.png`, `.jpg`, `.jpeg`), the analysis pipeline performs:

* OCR-based text extraction using EasyOCR.
* Detection of phishing keywords.
* Identification of suspicious links.
* QR code extraction and decoding.
* Highlighting of suspicious text regions inside the uploaded image.

---

### 🧩 Psychological Threat Profiling

The analyzer measures behavioral characteristics commonly found in phishing attacks.

#### **Urgency Index**

Detects time-pressure language such as:

> "Respond immediately"
> "Within 24 hours"
> "Act now"

#### **Fear Trigger Range**

Detects scare tactics such as:

> "Your account has been suspended"
> "Failure to comply will result in termination"

#### **Credential Harvesting Proximity**

Identifies attempts to obtain:

* Passwords
* Usernames
* OTPs
* Banking information
* Login credentials

---

### 🔗 URL Inspection

The system extracts and analyzes URLs found in:

* Email bodies
* PDFs
* OCR text
* QR codes

Suspicious domains and malicious indicators contribute to the overall risk score. VirustTotal API is used here, where in the email is send to the VirusTotal to check the status of the url if it is flagged as suspicious or not and it is reported back.

---

### ✅ Domain Whitelisting

Trusted domains from widely used services (for example Microsoft and Google) are treated with reduced suspicion to minimize false positives.

---

## 📊 Risk Scoring

Each analyzed sample receives:

* A numerical risk score (`0–100`)
* Threat severity classification:

  * Low
  * Medium
  * High
* Detailed explanations for detected indicators
* Recommended remediation actions
* Each Format of input presents a different set of reulsts ananlysis page.

---

## ⚠️ Limitations

* OCR analysis is currently supported only for image-based inputs (`.png`, `.jpg`, `.jpeg`).
* OCR accuracy depends on image quality, resolution, and text visibility.
* Image files do not contain email authentication metadata such as SPF, DKIM, or DMARC records.
* The tool uses heuristic-based threat detection and should be used as an assistance system rather than the sole source for security decisions.

---

## 🛠️ Technology Stack

### 🖥️ Frontend

* React 18
* JavaScript (ES6+)
* Tailwind CSS
* Lucide React Icons

Features include:

* Dark/Light theme switching
* Interactive dashboard
* Drag-and-drop uploads
* Threat visualization panels

### 🐍 Backend

* FastAPI
* Python 3
* Uvicorn
* Pydantic v2

The backend exposes REST APIs that process uploads and return structured threat intelligence reports.

### 📸 Analysis & Utilities

| Library              | Purpose                                 |
| -------------------- | --------------------------------------- |
| EasyOCR              | Optical Character Recognition           |
| OpenCV               | Image preprocessing and QR detection    |
| pypdf                | PDF parsing and text extraction         |
| Python email package | EML parsing and metadata extraction     |
| Regex (`re`)         | Pattern matching and content extraction |

---

## 📂 Project Structure

```text
email-phishing-analyzer/
│
├── backend/
│   ├── routers/
│   │   └── analyze.py
│   │
│   ├── services/
│   │   ├── content_analyzer.py
│   │   ├── eml_parser.py
│   │   ├── pdf_parser.py
│   │   ├── ocr_service.py
│   │   └── url_analyzer.py
│   │
│   └── main.py
│
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── FindingsList.jsx
│       │   ├── RiskCard.jsx
│       │   ├── UploadBox.jsx
│       │   ├── RecommendedActions.jsx
│       │   └── ScanProgress.jsx
│       │
│       └── pages/
│           └── Dashboard.jsx
│
├── docs/
│   ├── API.md
│   ├── Architecture.md
│   └── Research.md
│
├── README.md
└── requirements.txt
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/Anushree1225/email-phishing-analyzer.git
cd email-phishing-analyzer
```

### 2. Backend Setup

```bash
cd backend

python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

Run the backend:

```bash
uvicorn main:app --reload
```

Backend runs at:

```text
http://localhost:8000
```

### 3. Frontend Setup

Open a new terminal:

```bash
cd frontend

npm install

npm run dev
```

Frontend runs at:

```text
http://localhost:5173
```

---

## 📡 API Endpoints

### Analyze Text

```http
POST /analyze/text
```

### Analyze Uploaded File

```http
POST /analyze/file
```

Detailed request and response examples are available in:

```text
docs/API.md
```

---

## 🔮 Future Enhancements

* Attachment malware scanning
* Machine learning classification models
* SIEM integration
* Threat intelligence feed integration
* User authentication and scan history
* Report export functionality

---

## 👩‍💻 Authors

**Anushree Verma**
**Arpita Verma**

Developed under the **Information Security Internship Project**.

---

## 📄 License

This project is developed for educational and internship purposes.
