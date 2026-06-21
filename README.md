# 🛡️ Multimodal Enterprise Email Phishing Forensic Engine

An advanced, end-to-end enterprise cyber-threat intelligence engine designed to process multiple forensic vector footprints (.eml files, .pdf assets, raster screenshot images, and raw plain-text dumps). The platform combines linguistic behavioral heuristics, computer-vision OCR text segment extraction, nested QR matrix routing decoders, and multi-layered network parameter lookups to generate immediate dynamic risk assessments.

---

## 🚀 System Capabilities & Feature Matrix

* **Multimodal Core Routing Deck**: Dynamically bifurcates evaluation pipelines using discrete asynchronous engine pools based on input signatures.
* **Forensic EML Dissection**: Extracts structural routing header footprints to validate cross-layer SPF, DKIM, and DMARC alignment states.
* **Static PDF Token Parsing**: Extracts deep subsurface embedded hyperlinks and contextual layout scripts from static container document objects.
* **Computer-Vision Forensic Deck**: Employs EasyOCR engine pipelines to recover text string boundaries from flat screenshot matrices, utilizing custom scale ratio vectors ($X_{\text{scale}} = \text{Client Width} / \text{Original Resolution Width}$) to render pixel-precise dashed boundaries.
* **Linguistic Behavioral Heuristics**: Runs concurrent regex stem arrays to profile cognitive psychology manipulation intensities across distinct vector indexes: **Urgency Index**, **Fear Trigger Range**, and **Harvester Proximity**.
* **High-Reputation Whitelisting Core**: Mitigates administrative header noise false-positives by actively screening structural base domain footprints against enterprise safe lists.

---

## 🛠️ Technological Infrastructure Stack

### 🖥️ Frontend Framework
* **React 18** (Functional hooks architecture, declarative DOM state loops)
* **Tailwind CSS Engine** (Fluid typography matrices, glassmorphism telemetry layers)
* **Lucide Icon Libraries** (Contextual infographic markers)

### 🐍 Backend Forensic Core
* **FastAPI** (ASGI execution deck, asynchronous performance processing)
* **Uvicorn** (High-throughput server infrastructure)
* **Pydantic v2** (Strict data structure enforce parameters)

### 📸 Computer Vision & Network Utilities
* **EasyOCR** (Deep-learning text recognition segment pipeline)
* **OpenCV (cv2)** (Raster image matrix buffers, pixel array transforms, QR Code decoders)
* **Regex Engine (re)** (Fuzzy typographical space-to-dot normalization rules)

---

## 📂 Project Architecture Map

```text
email-phishing-analyzer/
├── backend/                   # FastAPI ASGI Backend Core
│   ├── routers/
│   │   └── analyze.py         # Primary Dynamic File & Text API Gateway Routing
│   ├── services/
│   │   ├── content_analyzer.py# Plain-Text Scraper & Linguistic Score Engine
│   │   ├── eml_parser.py      # EML Header Envelope Extraction Service
│   │   ├── pdf_parser.py      # PDF Layout Extractor Module
│   │   └── ocr_service.py     # OpenCV & EasyOCR Image Forensics Deck
│   └── main.py                # System Startup Deck & Whitelisted CORS Policies
├── frontend/                  # React Single-Page Architecture
│   └── src/
│       ├── components/
│       │   ├── FindingsList.jsx# Polymorphic Metric Panel View Controller
│       │   ├── RiskCard.jsx    # SVG Threat Assessment Gauges
│       │   └── UploadBox.jsx   # Drag-and-Drop Event Handler Stream
│       └── pages/
│           └── Dashboard.jsx   # Master Layout Grid View & Theme Context Hooks
└── docs/                      # Technical Project Research Specifications
    ├── API.md                 # System Protocol Specification Endpoints
    ├── Architecture.md        # Pipeline Dataflows & Matrix Multipliers
    └── Research.md            # Linguistic Heuristics & Cyber-Threat Vectors

    