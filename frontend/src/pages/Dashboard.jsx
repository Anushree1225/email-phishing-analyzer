import { useState, useEffect, useRef } from "react";
import UploadBox from "../components/UploadBox";
import PasteEmailBox from "../components/PasteEmailBox";
import RiskCard from "../components/RiskCard";
import FindingsList from "../components/FindingsList";
import RecommendedActions from "../components/RecommendedActions";
import { analyzeEmail, analyzeEmailFile } from "../services/api";
import ScanProgress from "../components/ScanProgress";
import jsPDF from "jspdf";

/**
 * Dashboard - main page
 * Props:
 * dark         {boolean} - theme flag
 * toggleTheme  {fn}      - toggle dark/light mode
 */
export default function Dashboard({ dark, toggleTheme }) {
  const [tab, setTab]           = useState("paste"); // "paste" | "upload"
  const [emailText, setEmailText] = useState("");
  const [file, setFile]         = useState(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState(null);

  // Absolute positioning scale trackers for image highlight boxes
  const imgRef = useRef(null);
  const [imgScale, setImgScale] = useState({ x: 1, y: 1 });
  const [imagePreviewUrl, setImagePreviewUrl] = useState(null);

  // Build temporary object preview URL for uploaded asset stream
  useEffect(() => {
    if (!file) {
      setImagePreviewUrl(null);
      return;
    }
    const url = URL.createObjectURL(file);
    setImagePreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  const handleRecalculateScale = () => {
    if (!imgRef.current || !imgAnalysis.dimensions || imgAnalysis.dimensions === "Unknown") return;
    const [origWidth, origHeight] = imgAnalysis.dimensions.split('x').map(Number);
    setImgScale({
      x: imgRef.current.clientWidth / origWidth,
      y: imgRef.current.clientHeight / origHeight
    });
  };

  useEffect(() => {
    window.addEventListener('resize', handleRecalculateScale);
    return () => window.removeEventListener('resize', handleRecalculateScale);
  }, [result]);

  const handleAnalyze = async () => {
    setError(null);
    setResult(null); 

    if (tab === "paste" && !emailText.trim()) {
      setError("Please paste email content before analyzing.");
      return;
    }

    let activeFile = file;
    const fileInput = document.querySelector('input[type="file"]');
    if (tab === "upload" && fileInput && fileInput.files && fileInput.files[0]) {
      activeFile = fileInput.files[0];
    }

    if (tab === "upload" && !activeFile) {
      setError("Please upload an .eml or image file.");
      return;
    }

    setScanning(true);
    try {
      const data =
        tab === "paste"
          ? await analyzeEmail({ email_text: emailText })
          : await analyzeEmailFile(activeFile);
      
      console.log("🚀 Fresh Backend Packet Payload:", data); 
      setResult(data);
    } catch (err) {
      // 🎯 BULLETPROOF ERROR CHECKING CHAIN
      let serverErrorMessage = "Analysis failed. Please ensure the backend is running at the configured URL.";
      
      if (err.response && err.response.data) {
        if (typeof err.response.data.detail === "string") {
          serverErrorMessage = err.response.data.detail;
        } else if (err.response.data.message) {
          serverErrorMessage = err.response.data.message;
        }
      }
      
      setError(serverErrorMessage);
    } finally {
      setScanning(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setScanning(false);
    setError(null);
    setEmailText("");
    setFile(null);
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) fileInput.value = "";
  };

  // Function to generate and download the professional SOC PDF report
  const downloadPDF = () => {
    if (!result) return;

    const doc = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4",
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 15;
    const contentWidth = pageWidth - margin * 2;
    let y = 18;

    // Helper to add new page if content exceeds height limits
    const checkPageBreak = (neededHeight = 15) => {
      if (y + neededHeight > pageHeight - 20) {
        doc.addPage();
        y = 20;
      }
    };

    // Helper to draw clean modern section boxes
    const drawSectionBox = (title, startY, height) => {
      doc.setDrawColor(226, 232, 240);
      doc.setFillColor(248, 250, 252);
      doc.roundedRect(margin, startY, contentWidth, height, 2, 2, "FD");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);
      doc.text(title.toUpperCase(), margin + 5, startY + 7);

      doc.setDrawColor(203, 213, 225);
      doc.line(margin + 5, startY + 10, margin + contentWidth - 5, startY + 10);
    };

    // 1. HEADER
    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.setTextColor(15, 23, 42);
    doc.text("EMAIL PHISHING ANALYZER", pageWidth / 2, y, { align: "center" });

    y += 7;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(100, 116, 139);
    doc.text("Security Analysis Report", pageWidth / 2, y, { align: "center" });

    y += 5;
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y);

    // 2. SCAN INFORMATION
    y += 8;
    const scanId = result.scan_id || result.id || `SCAN-${Date.now().toString(36).toUpperCase()}`;
    const scanDate = result.scanned_at ? new Date(result.scanned_at).toLocaleString() : new Date().toLocaleString();
    const generatedOn = new Date().toLocaleString();

    doc.setFontSize(8.5);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(71, 85, 105);
    doc.text(`Scan ID:`, margin, y);
    doc.setFont("helvetica", "normal");
    doc.text(`${scanId}`, margin + 18, y);

    doc.setFont("helvetica", "bold");
    doc.text(`Scan Date:`, margin + 70, y);
    doc.setFont("helvetica", "normal");
    doc.text(`${scanDate}`, margin + 88, y);

    doc.setFont("helvetica", "bold");
    doc.text(`Generated On:`, margin + 135, y);
    doc.setFont("helvetica", "normal");
    doc.text(`${generatedOn}`, margin + 158, y);

    // 3. RISK SUMMARY BOX
    y += 8;
    const score = result.risk_score ?? result.score ?? 0;
    const severity = (result.severity || (score > 70 ? "HIGH" : score > 30 ? "MEDIUM" : "LOW")).toUpperCase();

    drawSectionBox("Risk Summary", y, 22);

    doc.setFontSize(11);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(15, 23, 42);
    doc.text(`Risk Score : `, margin + 8, y + 16);
    doc.setFont("helvetica", "normal");
    doc.text(`${score} / 100`, margin + 32, y + 16);

    doc.setFont("helvetica", "bold");
    doc.text(`Severity : `, margin + 90, y + 16);

    // Color code Severity badge (High -> Red, Medium -> Orange, Low -> Green)
    if (severity.includes("HIGH")) doc.setTextColor(220, 38, 38);
    else if (severity.includes("MEDIUM")) doc.setTextColor(217, 119, 6);
    else doc.setTextColor(22, 163, 74);

    doc.text(`${severity}`, margin + 110, y + 16);
    y += 28;

    // 4. THREAT INDICATORS
    if (result.reasons && result.reasons.length > 0) {
      checkPageBreak(30);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("Threat Indicators", margin, y);
      y += 3;
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(51, 65, 85);

      result.reasons.forEach((reason) => {
        checkPageBreak(8);
        const reasonText = typeof reason === "string" ? reason : reason.title || reason.description || reason.type || JSON.stringify(reason);
        const wrappedLines = doc.splitTextToSize(`• ${reasonText}`, contentWidth - 5);
        doc.text(wrappedLines, margin + 2, y);
        y += wrappedLines.length * 4.5;
      });
      y += 4;
    }

    // 5. URL ANALYSIS
    if (result.urls_found && result.urls_found.length > 0) {
      checkPageBreak(30);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("Detected URLs", margin, y);
      y += 3;
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;

      result.urls_found.forEach((u) => {
        const urlStr = typeof u === "string" ? u : u.url || u.link || "";
        const status = u.status || (u.suspicious ? "Suspicious" : "Clean");
        const redirects = u.redirect_chain || u.redirects || [];

        checkPageBreak(20);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9);
        doc.setTextColor(30, 41, 59);
        const urlLines = doc.splitTextToSize(urlStr, contentWidth - 10);
        doc.text(urlLines, margin + 2, y);
        y += urlLines.length * 4.5;

        doc.setFont("helvetica", "normal");
        doc.setTextColor(100, 116, 139);
        doc.text(`Status : `, margin + 5, y);
        
        if (status.toLowerCase().includes("suspicious") || status.toLowerCase().includes("malicious")) {
          doc.setTextColor(220, 38, 38);
        } else {
          doc.setTextColor(22, 163, 74);
        }
        doc.text(status, margin + 20, y);
        y += 5;

        if (redirects.length > 0) {
          doc.setFont("helvetica", "normal");
          doc.setTextColor(100, 116, 139);
          doc.text("Redirects :", margin + 5, y);
          y += 4.5;

          redirects.forEach((step) => {
            checkPageBreak(6);
            doc.text(`↓  ${step}`, margin + 10, y);
            y += 4.5;
          });
        }
        y += 2;
      });
      y += 4;
    }

    // 6. HIGHLIGHTED CONTENT
    if (result.highlighted_content && result.highlighted_content.length > 0) {
      checkPageBreak(30);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("Detected Phishing Phrases", margin, y);
      y += 3;
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;

      result.highlighted_content.forEach((item) => {
        checkPageBreak(12);
        const phrase = typeof item === "string" ? item : item.text || item.phrase || "";
        const reason = typeof item === "object" ? item.reason || item.type || "Suspicious Trigger" : "Suspicious Trigger";

        doc.setFont("helvetica", "bold");
        doc.setFontSize(9);
        doc.setTextColor(185, 28, 28);
        const phraseLines = doc.splitTextToSize(`"${phrase}"`, contentWidth - 10);
        doc.text(phraseLines, margin + 2, y);
        y += phraseLines.length * 4.5;

        doc.setFont("helvetica", "normal");
        doc.setTextColor(100, 116, 139);
        doc.text(`Reason : ${reason}`, margin + 6, y);
        y += 6;
      });
      y += 4;
    }

    // 7. RECOMMENDATIONS
    if (result.recommended_action && result.recommended_action.length > 0) {
      checkPageBreak(30);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text("Recommendations", margin, y);
      y += 3;
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, y, pageWidth - margin, y);
      y += 6;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(51, 65, 85);

      result.recommended_action.forEach((act) => {
        checkPageBreak(8);
        const actText = typeof act === "string" ? act : act.action || act.description || JSON.stringify(act);
        const wrappedAct = doc.splitTextToSize(`• ${actText}`, contentWidth - 5);
        doc.text(wrappedAct, margin + 2, y);
        y += wrappedAct.length * 4.5;
      });
      y += 6;
    }

    // 8. FOOTER
    checkPageBreak(25);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.5);
    doc.line(margin, pageHeight - 18, pageWidth - margin, pageHeight - 18);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text("Generated by Email Phishing Analyzer", pageWidth / 2, pageHeight - 12, { align: "center" });
    doc.text("© 2026", pageWidth / 2, pageHeight - 8, { align: "center" });

    // Save with precise standard file layout
    doc.save(`Email_Phishing_Report_${scanId}.pdf`);
  };

  const tabBtn = (id) => ({
    fontFamily: "'Space Mono', monospace",
    fontSize: "0.78rem",
    fontWeight: 700,
    padding: "0.55rem 1.2rem",
    borderRadius: 9,
    border: "none",
    background: tab === id ? "linear-gradient(135deg, #38bdf8, #818cf8)" : "transparent",
    color: tab === id ? "#fff" : dark ? "#64748b" : "#94a3b8",
    cursor: "pointer",
    transition: "all 0.2s",
    letterSpacing: 1,
  });

  const imagePanelStyles = {
    card: {
      background: dark ? "rgba(15,23,42,0.4)" : "rgba(255,255,255,0.7)",
      border: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`,
      padding: "1.25rem",
      borderRadius: 14,
      fontFamily: "'Space Mono', monospace"
    },
    label: {
      display: "block",
      fontSize: "0.65rem",
      color: dark ? "#64748b" : "#94a3b8",
      letterSpacing: "1px",
      textTransform: "uppercase"
    },
    value: {
      fontSize: "0.85rem",
      fontWeight: 700,
      color: dark ? "#cbd5e1" : "#334155"
    }
  };

  const textPanelStyles = {
    progressRow: {
      display: "flex",
      flexDirection: "column",
      gap: "0.4rem",
      fontFamily: "'Space Mono', monospace",
      fontSize: "0.72rem",
      textAlign: "left",
      color: dark ? "#e2e8f0" : "#334155"
    },
    progressBarOuter: {
      width: "100%",
      height: "8px",
      background: dark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)",
      borderRadius: "4px",
      overflow: "hidden"
    },
    checkItem: {
      display: "flex",
      alignItems: "center",
      gap: "0.5rem",
      fontFamily: "'Space Mono', monospace",
      fontSize: "0.78rem",
      color: dark ? "#cbd5e1" : "#334155",
      textAlign: "left"
    }
  };

  const imgAnalysis = result?.image_analysis || {};
  const cleanOcrText = imgAnalysis.extracted_content_raw || result?.extracted_text || "";

  return (
    <div style={{ minHeight: "100vh", background: dark
      ? "radial-gradient(ellipse at 20% 20%, #0c1e3a 0%, #070e1a 60%, #030712 100%)"
      : "radial-gradient(ellipse at 20% 20%, #e0f2fe 0%, #f8fafc 60%, #f1f5f9 100%)",
      transition: "background 0.4s ease",
    }}>

      {/* Header */}
      <header style={{
        padding: "1rem 2rem",
        display: "flex",
        alignItems: "center",
        justify: "space-between",
        borderBottom: `1px solid ${dark ? "rgba(56,189,248,0.12)" : "rgba(3,105,161,0.12)"}`,
        backdropFilter: "blur(12px)",
        position: "sticky",
        top: 0,
        zIndex: 50,
        background: dark ? "rgba(7,14,26,0.88)" : "rgba(248,250,252,0.88)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: "linear-gradient(135deg, #38bdf8, #818cf8)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18, boxShadow: "0 0 16px rgba(56,189,248,0.4)",
          }}>🛡</div>
          <div>
            <div style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, fontSize: "1rem", color: dark ? "#e2e8f0" : "#0f172a", letterSpacing: 1 }}>
              Email Phishing Analyzer
            </div>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.6rem", color: dark ? "#38bdf8" : "#0369a1", letterSpacing: 2 }}>
              CYBERSECURITY · THREAT INTEL
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.67rem", color: "#22c55e", display: "flex", alignItems: "center", gap: "0.35rem" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#22c55e", display: "inline-block", animation: "pulse 2s infinite" }} />
            SYSTEM ONLINE
          </div>
          <button
            onClick={toggleTheme}
            style={{
              fontFamily: "'Space Mono', monospace",
              fontSize: "0.73rem",
              fontWeight: 700,
              padding: "0.45rem 1rem",
              borderRadius: 8,
              border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
              background: dark ? "rgba(30,58,95,0.4)" : "rgba(226,232,240,0.8)",
              color: dark ? "#94a3b8" : "#475569",
              cursor: "pointer",
              letterSpacing: 1,
            }}
          >
            {dark ? "☀ LIGHT" : "🌙 DARK"}
          </button>
        </div>
      </header>

      {/* Main Body */}
      <main style={{ maxWidth: 1100, margin: "0 auto", padding: "2rem 1.25rem" }}>

        {/* INPUT PANEL */}
        {!result && !scanning && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            <div style={{ textAlign: "center", marginBottom: "2.5rem" }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", letterSpacing: 4, color: dark ? "#38bdf8" : "#0369a1", marginBottom: "0.75rem" }}>
                THREAT DETECTION PLATFORM
              </div>
              <h1 style={{ fontFamily: "'Sora', sans-serif", fontWeight: 700, fontSize: "clamp(1.8rem, 4vw, 2.8rem)", color: dark ? "#f1f5f9" : "#0f172a", lineHeight: 1.2, marginBottom: "0.75rem" }}>
                Analyze Phishing{" "}
                <span style={{ background: "linear-gradient(135deg, #38bdf8, #818cf8)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                  Threats
                </span>
              </h1>
              <p style={{ fontFamily: "'Sora', sans-serif", color: dark ? "#64748b" : "#94a3b8", fontSize: "0.95rem", maxWidth: 480, margin: "0 auto" }}>
                Upload or paste any email to receive an instant threat intelligence report.
              </p>
            </div>

            <div style={{
              display: "flex", gap: "0.5rem", marginBottom: "1.25rem",
              background: dark ? "rgba(15,23,42,0.6)" : "rgba(226,232,240,0.5)",
              borderRadius: 12, padding: "0.35rem", width: "fit-content",
            }}>
              <button style={tabBtn("paste")} onClick={() => setTab("paste")}>✏ Paste Email</button>
              <button style={tabBtn("upload")} onClick={() => setTab("upload")}>📁 Upload File</button>
            </div>

            <div style={{
              background: dark ? "rgba(15,23,42,0.8)" : "rgba(255,255,255,0.8)",
              border: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`,
              borderRadius: 18, padding: "1.75rem", marginBottom: "1rem",
              backdropFilter: "blur(8px)",
            }}>
              {tab === "paste"
                ? <PasteEmailBox dark={dark} value={emailText} onChange={setEmailText} />
                : <UploadBox dark={dark} file={file} onFileSelect={setFile} />
              }
            </div>

            {error && (
              <div style={{
                fontFamily: "'Space Mono', monospace", fontSize: "0.8rem", color: "#ef4444",
                padding: "0.75rem 1rem", background: "rgba(239,68,68,0.08)",
                border: "1px solid rgba(239,68,68,0.2)", borderRadius: 10, marginBottom: "1rem",
              }}>
                ⚠ {error}
              </div>
            )}

            <button
              onClick={handleAnalyze}
              style={{
                width: "100%", fontFamily: "'Space Mono', monospace", fontWeight: 700,
                fontSize: "0.9rem", letterSpacing: 2, padding: "1rem", borderRadius: 12,
                border: "none", background: "linear-gradient(135deg, #38bdf8 0%, #818cf8 100%)",
                color: "#fff", cursor: "pointer", boxShadow: "0 0 24px rgba(56,189,248,0.3)",
                transition: "all 0.2s",
              }}
            >
              🔍 ANALYZE {tab === "paste" ? "EMAIL TEXT" : "UPLOADED FILE"}
            </button>
          </div>
        )}

        {/* SCAN PROGRESS OVERLAY */}
        {scanning && (
          <div style={{ animation: "fadeUp 0.4s ease both" }}>
            <ScanProgress dark={dark} />
          </div>
        )}

        {/* RESULTS CORE COMPONENT BLOCKS */}
        {result && !scanning && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            
            {/* PDF NOTICE LINK BANNER */}
            {result.file_type === "pdf" && (
              <div style={{
                fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", lineHeight: "1.5",
                padding: "1rem 1.25rem", background: dark ? "rgba(245, 158, 11, 0.05)" : "rgba(245, 158, 11, 0.08)",
                border: "1px solid rgba(245, 158, 11, 0.25)", borderRadius: 12,
                color: dark ? "#fbbf24" : "#b45309", marginBottom: "1.5rem",
                display: "flex", alignItems: "start", gap: "0.8rem", textAlign: "left"
              }}>
                <span style={{ fontSize: "1.1rem", marginTop: "-2px" }}>⚠️</span>
                <div>
                  <strong style={{ letterSpacing: "0.5px" }}>FORENSIC CONFIGURATION NOTICE (CONFIDENCE ADJUSTED):</strong>
                  <br />
                  Flattened static portable document file block (.pdf) handled. Mail cryptographic routing vectors cannot be dynamically parsed. Trust parameters have been customized contextually.
                </div>
              </div>
            )}

            {/* IMAGE PLATFORM BANNER NOTICE */}
            {result.file_type === "image" && (
              <div style={{
                fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", lineHeight: "1.5",
                padding: "1rem 1.25rem", background: dark ? "rgba(56, 189, 248, 0.05)" : "rgba(3, 105, 161, 0.08)",
                border: `1px solid ${dark ? "rgba(56, 189, 248, 0.2)" : "rgba(3, 105, 161, 0.2)"}`, borderRadius: 12,
                color: dark ? "#38bdf8" : "#0369a1", marginBottom: "1.5rem",
                display: "flex", alignItems: "start", gap: "0.8rem", textAlign: "left"
              }}>
                <span style={{ fontSize: "1.1rem", marginTop: "-2px" }}>📷</span>
                <div>
                  <strong style={{ letterSpacing: "0.5px" }}>IMAGE FORENSICS NOTICE (VISUAL EVIDENCE CEILING):</strong>
                  <br />
                  Flat raster image asset format detected. Cryptographic transport parameters (SPF/DKIM/DMARC signatures) do not exist natively within raw pixel matrices. Threat scores are weighted entirely on deep-learning OCR keyword triggers and social engineering indicators.
                </div>
              </div>
            )}

            {/* Report layout navigation headers */}
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              flexWrap: "wrap", gap: "1rem", marginBottom: "1.5rem",
            }}>
              <div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", letterSpacing: 3, color: dark ? "#38bdf8" : "#0369a1", marginBottom: "0.3rem" }}>
                  ANALYSIS COMPLETE · {new Date(result.scanned_at).toLocaleString()}
                </div>
                <h2 style={{ fontFamily: "'Sora', sans-serif", fontWeight: 700, fontSize: "1.4rem", color: dark ? "#f1f5f9" : "#0f172a" }}>
                  Threat Intelligence Report
                </h2>
              </div>
              <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                <button
                  onClick={downloadPDF}
                  style={{
                    fontFamily: "'Space Mono', monospace", fontSize: "0.78rem", fontWeight: 700,
                    padding: "0.7rem 1.2rem", borderRadius: 10,
                    border: `1px solid ${dark ? "#38bdf8" : "#0369a1"}`,
                    background: "linear-gradient(135deg, #38bdf8 0%, #818cf8 100%)", color: "#fff", cursor: "pointer", letterSpacing: 1,
                    boxShadow: "0 0 12px rgba(56, 189, 248, 0.25)"
                  }}
                >
                  📄 Download PDF
                </button>
                <button
                  onClick={handleReset}
                  style={{
                    fontFamily: "'Space Mono', monospace", fontSize: "0.78rem", fontWeight: 700,
                    padding: "0.7rem 1.2rem", borderRadius: 10,
                    border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
                    background: "transparent", color: dark ? "#94a3b8" : "#64748b", cursor: "pointer", letterSpacing: 1,
                  }}
                >
                  ← NEW SCAN
                </button>
              </div>
            </div>

            {/* Results Display Panel Split Layout Split */}
            <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: "1.25rem", alignItems: "start" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                <RiskCard dark={dark} result={result} />
                <RecommendedActions dark={dark} actions={result.recommended_action} result={result} />
              </div>
              
              {/* SPECIALIZED PLAIN-TEXT REPORT WORKFLOW VIEW */}
              {result.file_type === "text" ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                  
                  {/* SOURCE PROFILE METADATA DETAILS CARD */}
                  <div style={{ ...imagePanelStyles.card, background: dark ? "rgba(30,58,95,0.15)" : "#fff", textAlign: "left" }}>
                    <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", borderBottom: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, paddingBottom: "0.5rem", marginBottom: "0.75rem", fontWeight: 700 }}>
                      📋 SOURCE INFOPROFILE SPECIFICATIONS
                    </h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.45rem", fontSize: "0.78rem" }}>
                      <div><span style={{ color: "#64748b" }}>Input Mechanism:</span> <strong style={{ color: "#38bdf8" }}>Pasted Plain Text Stream</strong></div>
                      <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><span style={{ color: "#64748b" }}>Detected Sender:</span> <strong style={{ color: dark ? "#cbd5e1" : "#334155" }}>{result.text_details?.from || "Not Available"}</strong></div>
                      <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><span style={{ color: "#64748b" }}>Detected Subject:</span> <strong style={{ color: dark ? "#cbd5e1" : "#334155" }}>{result.text_details?.subject || "Not Available"}</strong></div>
                      {result.text_details?.date && result.text_details.date !== "Not Available" && (
                        <div><span style={{ color: "#64748b" }}>Extracted Timestamp:</span> <strong style={{ color: dark ? "#cbd5e1" : "#334155" }}>{result.text_details.date}</strong></div>
                      )}
                    </div>
                  </div>

                  {/* LINGUISTIC DIALS & PROGRESS SLIDERS SECTION */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem", flexWrap: "wrap" }}>
                    
                    {/* Language Metrics Progression Panel */}
                    <div style={imagePanelStyles.card}>
                      <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", borderBottom: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, paddingBottom: "0.5rem", marginBottom: "0.8rem", fontWeight: 700 }}>
                        📊 LINGUISTIC INTENSITY PROFILING
                      </h3>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
                        <div style={textPanelStyles.progressRow}>
                          <div style={{ display: "flex", justifyContent: "space-between" }}><span>Urgency Index</span><th>{result.language_analysis?.urgency_score || 0}%</th></div>
                          <div style={textPanelStyles.progressBarOuter}><div style={{ width: `${result.language_analysis?.urgency_score || 0}%`, height: "100%", background: "#ef4444" }} /></div>
                        </div>
                        <div style={textPanelStyles.progressRow}>
                          <div style={{ display: "flex", justifyContent: "space-between" }}><span>Fear / Panic Trigger Range</span><th>{result.language_analysis?.fear_score || 0}%</th></div>
                          <div style={textPanelStyles.progressBarOuter}><div style={{ width: `${result.language_analysis?.fear_score || 0}%`, height: "100%", background: "#f59e0b" }} /></div>
                        </div>
                        <div style={textPanelStyles.progressRow}>
                          <div style={{ display: "flex", justifyContent: "space-between" }}><span>Credential Harvesting Proximity</span><th>{result.language_analysis?.credential_score || 0}%</th></div>
                          <div style={textPanelStyles.progressBarOuter}><div style={{ width: `${result.language_analysis?.credential_score || 0}%`, height: "100%", background: "#a855f7" }} /></div>
                        </div>
                      </div>
                    </div>

                    {/* Threat Layout Checkbox Verification Blocks */}
                    <div style={imagePanelStyles.card}>
                      <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", borderBottom: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, paddingBottom: "0.5rem", marginBottom: "0.8rem", fontWeight: 700 }}>
                        ⚙️ VECTOR SIGNATURE HEURISTICS
                      </h3>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
                        <div style={textPanelStyles.checkItem}>
                          <span>{result.language_analysis?.urgency_score > 30 ? "❌" : "✅"}</span>
                          <span style={{ textDecoration: result.language_analysis?.urgency_score > 30 ? "none" : "line-through", color: result.language_analysis?.urgency_score > 30 ? "#ef4444" : "#64748b" }}>Urgency language patterns identified</span>
                        </div>
                        <div style={textPanelStyles.checkItem}>
                          <span>{result.language_analysis?.credential_score > 30 ? "❌" : "✅"}</span>
                          <span style={{ textDecoration: result.language_analysis?.credential_score > 30 ? "none" : "line-through", color: result.language_analysis?.credential_score > 30 ? "#ef4444" : "#64748b" }}>Explicit credential requests found</span>
                        </div>
                        <div style={textPanelStyles.checkItem}>
                          <span>{result.language_analysis?.fear_score > 30 ? "❌" : "✅"}</span>
                          <span style={{ textDecoration: result.language_analysis?.fear_score > 30 ? "none" : "line-through", color: result.language_analysis?.fear_score > 30 ? "#f59e0b" : "#64748b" }}>Account suspension fear vectors hit</span>
                        </div>
                        <div style={textPanelStyles.checkItem}>
                          <span>{result.reasons?.some(r => r.type === "spoofed_header") ? "❌" : "✅"}</span>
                          <span style={{ textDecoration: result.reasons?.some(r => r.type === "spoofed_header") ? "none" : "line-through", color: result.reasons?.some(r => r.type === "spoofed_header") ? "#ef4444" : "#64748b" }}>Header routing mismatch discovered</span>
                        </div>
                      </div>
                    </div>

                  </div>

                  {/* THREAT FINDINGS AND URL EXPANSIONS PANEL SPLIT */}
                  <FindingsList
                    dark={dark}
                    reasons={result.reasons}
                    highlightedContent={result.highlighted_content}
                    urlsFound={result.urls_found}
                    emlDetails={null}
                    fileType="text"
                    confidenceLevel={75}
                  />

                </div>
              ) : result.file_type === "image" ? (
                /* 📸 RESTORED: NATIVE RASTER IMAGE ASSNET FORENSICS SPATIAL HIGHLIGHT VIEW */
                <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                  
                  {/* ⚡ SPATIAL CANVAS ANCHOR LOOP */}
                  {imagePreviewUrl && (
                    <div style={{ ...imagePanelStyles.card, padding: "1rem" }}>
                      <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", marginBottom: "0.75rem", fontWeight: 700 }}>
                        // THREAT TARGET SPATIAL DETECTION HIGHLIGHTS
                      </h3>
                      <div style={{ position: 'relative', display: 'inline-block', width: '100%', overflow: 'hidden', borderRadius: 8 }}>
                        <img 
                          ref={imgRef}
                          src={imagePreviewUrl} 
                          alt="Scanned Threat Input Layout" 
                          onLoad={handleRecalculateScale}
                          style={{ width: '100%', height: 'auto', display: 'block' }}
                        />
                        {imgAnalysis.ocr_blocks?.map((block, idx) => {
                          if (!block.suspicious) return null;
                          const minX = Math.min(...block.points.map(p => p[0]));
                          const minY = Math.min(...block.points.map(p => p[1]));
                          const maxX = Math.max(...block.points.map(p => p[0]));
                          const maxY = Math.max(...block.points.map(p => p[1]));
                          
                          const isButtonAction = block.role === "button";

                          return (
                            <div
                              key={idx}
                              title={isButtonAction ? `🚨 UNVERIFIED INTERACTIVE TRAP: "${block.text}"` : `Flagged Token Area: "${block.text}"`}
                              style={{
                                position: 'absolute',
                                top: `${minY * imgScale.y}px`,
                                left: `${minX * imgScale.x}px`,
                                width: `${(maxX - minX) * imgScale.x}px`,
                                height: `${(maxY - minY) * imgScale.y}px`,
                                border: isButtonAction ? '3px solid #a855f7' : '2px dashed #ef4444', 
                                backgroundColor: isButtonAction ? 'rgba(168, 85, 247, 0.15)' : 'rgba(239, 68, 68, 0.18)',
                                boxShadow: isButtonAction ? '0 0 12px rgba(168, 85, 247, 0.8)' : '0 0 6px rgba(239, 68, 68, 0.5)',
                                borderRadius: isButtonAction ? '6px' : '0px',
                                zIndex: 12,
                                transition: 'transform 0.2s',
                                cursor: 'pointer'
                              }}
                            />
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* LAYER 1: HIGHLIGHTED CARD GLANCE STATISTICS */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem" }}>
                    <div style={imagePanelStyles.card}>
                      <span style={imagePanelStyles.label}>OCR Status</span>
                      <span style={{ ...imagePanelStyles.value, color: "#10b981" }}>
                        {imgAnalysis.ocr_status || "SUCCESS"}
                      </span>
                    </div>
                    <div style={imagePanelStyles.card}>
                      <span style={imagePanelStyles.label}>QR Code Matrices</span>
                      <span style={{ ...imagePanelStyles.value, color: result.danger_urls > 0 ? "#ef4444" : dark ? "#cbd5e1" : "#334155" }}>
                        {imgAnalysis.qr_codes_found || 0} Found
                      </span>
                    </div>
                    <div style={imagePanelStyles.card}>
                      <span style={imagePanelStyles.label}>Visible URL Layouts</span>
                      <span style={{ ...imagePanelStyles.value, color: "#38bdf8" }}>
                        {imgAnalysis.visible_urls_count || 0} Found
                      </span>
                    </div>
                  </div>

                  {/* LAYER 2: TWIN SUMMARY ATTRIBUTES SECTION */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem", flexWrap: "wrap" }}>
                    
                    <div style={{ ...imagePanelStyles.card, background: dark ? "rgba(15,23,42,0.2)" : "#fff" }}>
                      <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", borderBottom: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, paddingBottom: "0.5rem", marginBottom: "0.5rem", fontWeight: 700 }}>
                        // IMAGE STRUCTURAL INTELLIGENCE
                      </h3>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.72rem" }}>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>Image Container:</span>
                          <strong style={{ color: dark ? "#cbd5e1" : "#334155" }}>{imgAnalysis.image_type || "PNG"}</strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>Raster Resolution:</span>
                          <strong style={{ color: dark ? "#cbd5e1" : "#334155" }}>{imgAnalysis.dimensions || "Unknown"}</strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>Recovered Tokens:</span>
                          <strong style={{ color: "#38bdf8" }}>{imgAnalysis.word_count || 0} Words</strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>OCR Target Range:</span>
                          <strong style={{ color: "#10b981" }}>{imgAnalysis.ocr_confidence || "92%"}</strong>
                        </div>
                      </div>
                    </div>

                    <div style={{ ...imagePanelStyles.card, background: dark ? "rgba(15,23,42,0.2)" : "#fff" }}>
                      <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", borderBottom: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, paddingBottom: "0.5rem", marginBottom: "0.5rem", fontWeight: 700 }}>
                        // FORENSIC EXTRACTION RESULTS
                      </h3>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.72rem" }}>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>Flagged Bounding Boxes:</span>
                          <strong style={{ color: imgAnalysis.ocr_blocks?.some(b => b.suspicious) ? "#ef4444" : "#10b981" }}>
                            {imgAnalysis.ocr_blocks?.filter(b => b.suspicious).length || 0} Blocks
                          </strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>Embedded QR URLs:</span>
                          <strong style={{ color: dark ? "#cbd5e1" : "#334155" }}>{imgAnalysis.qr_urls_count || 0}</strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>OCR Text Payload:</span>
                          <strong style={{ color: cleanOcrText ? "#38bdf8" : "#64748b" }}>
                            {cleanOcrText ? "Extracted" : "None"}
                          </strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span style={{ color: "#64748b" }}>Interactive Traps:</span>
                          <strong style={{ color: imgAnalysis.ocr_blocks?.some(b => b.role === "button") ? "#a855f7" : "#10b981" }}>
                            {imgAnalysis.ocr_blocks?.filter(b => b.role === "button").length || 0} Found
                          </strong>
                        </div>
                      </div>
                    </div>

                  </div>

                  {/* LAYER 3: RECONSTRUCTED OCR TEXT DUMP */}
                  {cleanOcrText && (
                    <div style={imagePanelStyles.card}>
                      <h3 style={{ fontSize: "0.72rem", color: "#38bdf8", borderBottom: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, paddingBottom: "0.5rem", marginBottom: "0.75rem", fontWeight: 700 }}>
                        // RECONSTRUCTED TEXT FROM IMAGE (OCR)
                      </h3>
                      <div style={{
                        background: dark ? "rgba(7,14,26,0.6)" : "rgba(241,245,249,0.8)",
                        border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
                        borderRadius: 8, padding: "0.85rem", fontSize: "0.75rem",
                        color: dark ? "#94a3b8" : "#475569", maxHeight: "140px", overflowY: "auto",
                        whiteSpace: "pre-wrap", textAlign: "left"
                      }}>
                        {cleanOcrText}
                      </div>
                    </div>
                  )}

                  {/* LAYER 4: FINDINGS LIST COMPONENT INTEGRATION */}
                  <FindingsList
                    dark={dark}
                    reasons={result.reasons}
                    highlightedContent={result.highlighted_content}
                    urlsFound={result.urls_found}
                    emlDetails={null}
                    fileType="image"
                    confidenceLevel={imgAnalysis.confidence_ceiling || 65}
                  />

                </div>
              ) : (
                /* STANDARD DEFAULT FILE ANALYSIS VIEW (.EML / .PDF) */
                <FindingsList
                  dark={dark}
                  reasons={result.reasons}
                  highlightedContent={result.highlighted_content}
                  urlsFound={result.urls_found}
                  emlDetails={result.eml_details}
                  fileType={result.file_type || "eml"}
                  confidenceLevel={result.file_type === "pdf" ? 80 : 98}
                />
              )}

            </div>
          </div>
        )}

      </main>
    </div>
  );
}