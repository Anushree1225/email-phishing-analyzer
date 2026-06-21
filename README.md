# 🛡️ Email Phishing Analyzer

An advanced cybersecurity tool that helps identify phishing threats by analyzing multiple formats. The platform allows users to paste raw email text or upload `.eml` files, `.pdf` documents, and email screenshots (`.png`, `.jpg`). It uses linguistic text analysis, computer-vision OCR, QR code scanning, and mail header checks to generate an instant, easy-to-understand risk report.

---

## 🚀 Key Features

* **Smart Input Detection**: Automatically detects what format you provided (text, image, PDF, or email file) and routes it to the right scanner.
* **Email File (.eml) Scanner**: Extracts hidden email headers to check if security protocols like SPF, DKIM, and DMARC are configured correctly or if the sender is fake.
* **PDF Link Extractor**: Parses portable documents to find subsurface links, hidden redirects, and suspicious language.
* **Screenshot (Image) Forensics**: Uses EasyOCR to extract visible text from screenshots and highlights dangerous keywords or buttons on your dashboard. It also catches links hidden inside visual QR codes.
* **Psychological Threat Profiling**: Scores pasted text or OCR data across three behavioral metrics to show the type of social engineering strategy being used:
  * **Urgency Index**: Measures panic and time-pressure phrases (e.g., *"within 24 hours"*).
  * **Fear Trigger Range**: Detects scare tactics (e.g., *"your account is suspended"*).
  * **Harvesting Proximity**: Checks for explicit login and password requests.
* **Domain Whitelisting**: Uses a built-in list of safe, high-reputation domains (like Google or Microsoft) to minimize false alarms on regular system notifications.

---

## 🛠️ Tech Stack

### 🖥️ Frontend (User Interface)
* **React 18**: Built using clean functional components and hooks for quick state updates.
* **Tailwind CSS**: Custom dark and light theme styles with a smooth, retro grid dashboard look.
* **Lucide Icons**: Crisp, descriptive icons to mark different threats.

### 🐍 Backend (Server API)
* **FastAPI**: Fast, asynchronous Python framework to process multiple scan tasks smoothly.
* **Uvicorn**: High-performance server runner.
* **Pydantic v2**: Handles strict data checks between frontend requests and backend responses.

### 📸 Utilities & Libraries
* **EasyOCR**: Deep-learning text recognition pipeline used to scan images.
* **OpenCV (cv2)**: Image processing library used to decode hidden QR code vectors.
* **Regex (re)**: Regular expressions used to pull out sender emails, domains, and fix messy text typos.

---

## 📂 Project Structure

```text
email-phishing-analyzer/
├── backend/                    # FastAPI Backend Source
│   ├── routers/
│   │   └── analyze.py          # Primary API route for Text and File uploads
│   ├── services/
│   │   ├── content_analyzer.py # Plain text linguistic parser and scoring logic
│   │   ├── eml_parser.py       # EML metadata extractor and header checker
│   │   ├── pdf_parser.py       # PDF document parser module
│   │   └── ocr_service.py      # OpenCV and EasyOCR layout handler
│   └── main.py                 # Server startup and whitelisted CORS policy rules
├── frontend/                   # React Frontend Source
│   └── src/
│       ├── components/
│       │   ├── FindingsList.jsx# Display controller for malicious headers and links
│       │   ├── RiskCard.jsx    # Circular risk percentage indicator
│       │   └── UploadBox.jsx   # Drag-and-drop file upload framework
│       └── pages/
│           └── Dashboard.jsx   # Main view layout containing light/dark mode hooks
└── docs/                       # Technical Documentation Repository
    ├── API.md                  # Endpoint request and response formats
    ├── Architecture.md         # Flowcharts and coordinate scaling math logic
    └── Research.md             # Background context on phishing tactics