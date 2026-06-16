import { useState } from "react";
import UploadBox from "../components/UploadBox";
import PasteEmailBox from "../components/PasteEmailBox";
import RiskCard from "../components/RiskCard";
import FindingsList from "../components/FindingsList";
import RecommendedActions from "../components/RecommendedActions";
import { analyzeEmail, analyzeEmailFile } from "../services/api";
import ScanProgress from "../components/ScanProgress";

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

  const handleAnalyze = async () => {
    setError(null);
    setResult(null); 

    if (tab === "paste" && !emailText.trim()) {
      setError("Please paste email content before analyzing.");
      return;
    }

    // 🚀 STALE CACHE COUNTER-MEASURE:
    // If we are in upload mode, look directly at the DOM file input layer 
    // to guarantee we grab the fresh payload stream, even if state is lagging.
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
          : await analyzeEmailFile(activeFile); // Pass the verified live payload reference
      
      console.log("🚀 Fresh Backend Packet Payload:", data); 
      setResult(data);
    } catch {
      setError("Analysis failed. Please ensure the backend is running at the configured URL.");
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
    // Flush the DOM file field layout directly
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) fileInput.value = "";
  };

  // ── shared button styles ──────────────────────────────────────
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

  return (
    <div style={{ minHeight: "100vh", background: dark
      ? "radial-gradient(ellipse at 20% 20%, #0c1e3a 0%, #070e1a 60%, #030712 100%)"
      : "radial-gradient(ellipse at 20% 20%, #e0f2fe 0%, #f8fafc 60%, #f1f5f9 100%)",
      transition: "background 0.4s ease",
    }}>

      {/* ── Header ── */}
      <header style={{
        padding: "1rem 2rem",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
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
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.6" + "rem", color: dark ? "#38bdf8" : "#0369a1", letterSpacing: 2 }}>
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

      {/* ── Main ── */}
      <main style={{ maxWidth: 1100, margin: "0 auto", padding: "2rem 1.25rem" }}>

        {/* ── INPUT SECTION ── */}
        {!result && !scanning && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            {/* Hero */}
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

            {/* Tabs */}
            <div style={{
              display: "flex", gap: "0.5rem", marginBottom: "1.25rem",
              background: dark ? "rgba(15,23,42,0.6)" : "rgba(226,232,240,0.5)",
              borderRadius: 12, padding: "0.35rem", width: "fit-content",
            }}>
              <button style={tabBtn("paste")} onClick={() => setTab("paste")}>✏ Paste Email</button>
              <button style={tabBtn("upload")} onClick={() => setTab("upload")}>📁 Upload File</button>
            </div>

            {/* Input card */}
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

            {/* Analyze button */}
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

        {/* ── SCAN PROGRESS ── */}
        {scanning && (
          <div style={{ animation: "fadeUp 0.4s ease both" }}>
            <ScanProgress dark={dark} />
          </div>
        )}

        {/* ── RESULTS ── */}
        {result && !scanning && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            
            {result.file_type === "pdf" && (
              <div style={{
                fontFamily: "'Space Mono', monospace",
                fontSize: "0.72rem",
                lineHeight: "1.5",
                padding: "1rem 1.25rem",
                background: dark ? "rgba(245, 158, 11, 0.05)" : "rgba(245, 158, 11, 0.08)",
                border: "1px solid rgba(245, 158, 11, 0.25)",
                borderRadius: 12,
                color: dark ? "#fbbf24" : "#b45309",
                marginBottom: "1.5rem",
                display: "flex",
                alignItems: "flex-start",
                gap: "0.8rem",
                textAlign: "left"
              }}>
                <span style={{ fontSize: "1.1rem", marginTop: "-2px" }}>⚠️</span>
                <div>
                  <strong style={{ letterSpacing: "0.5px" }}>FORENSIC CONFIGURATION NOTICE (CONFIDENCE ADJUSTED):</strong>
                  <br />
                  Flattened static layout container (.pdf) detected. Because print output streams permanently discard underlying core mail transfer envelopes, real-time cryptographic verification (SPF/DKIM/DMARC server validation signatures) cannot be computed. 
                </div>
              </div>
            )}

            {/* Report header */}
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

            {/* Results grid */}
            <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: "1.25rem", alignItems: "start" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                <RiskCard dark={dark} result={result} />
                <RecommendedActions dark={dark} actions={result.recommended_action} result={result} />
              </div>
              <FindingsList
                dark={dark}
                reasons={result.reasons}
                highlightedContent={result.highlighted_content}
                urlsFound={result.urls_found}
                emlDetails={result.eml_details}
                fileType={result.file_type} 
              />
            </div>

            {/* Summary ribbon */}
            <div style={{
              marginTop: "1.25rem", padding: "1.1rem 1.5rem",
              background: dark ? "rgba(15,23,42,0.95)" : "rgba(248,250,252,0.95)",
              border: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, borderRadius: 14,
              display: "flex", alignItems: "center", flexWrap: "wrap", gap: "1.5rem",
            }}>
              {[
                { label: "RISK SCORE",  value: `${result.risk_score ?? 0}/100`,         color: "#ef4444" },
                { label: "SEVERITY",    value: result.severity || "Low",                color: result.risk_score >= 40 ? "#ef4444" : "#22c55e" },
                { label: "INDICATORS",  value: (result.reasons || []).filter(r => r.type !== "clean").length, color: "#f59e0b" },
                { label: "DANGER URLS", value: result.danger_urls ?? 0,                 color: result.danger_urls > 0 ? "#ef4444" : "#22c55e" },
                { label: "SCAN ID",     value: result.scan_id || "N/A",                 color: dark ? "#64748b" : "#94a3b8" },
              ].map((s, i) => (
                <div key={i}>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.63rem", letterSpacing: 2, color: dark ? "#475569" : "#94a3b8", marginBottom: "0.2rem" }}>
                    {s.label}
                  </div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, fontSize: "0.9rem", color: s.color }}>
                    {s.value}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}