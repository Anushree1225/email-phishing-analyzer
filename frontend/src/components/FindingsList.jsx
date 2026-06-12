import React, { useState } from 'react';

/**
 * FindingsList - renders threat indicators, highlighted suspicious content,
 * URL intelligence, advanced EML forensics, and file attachment payloads.
 */

const ICON_MAP = {
  credential_request: "🔑",
  lookalike_domain:   "🌐",
  sender_verification:"📧",
  urgent_language:     "⚡",
  suspicious_url:     "🔗",
  spoofed_header:     "🎭",
  legal_trigger:      "⚖️"
};

function SectionTitle({ label, dark }) {
  return (
    <div style={{
      fontFamily: "'Space Mono', monospace",
      fontWeight: 700,
      fontSize: "0.75rem",
      letterSpacing: 2,
      color: dark ? "#38bdf8" : "#0369a1",
      marginBottom: "0.9rem",
      textTransform: "uppercase",
    }}>
      {label}
    </div>
  );
}

export default function FindingsList({ dark, reasons, highlightedContent, urlsFound, emlDetails }) {
  // 🚀 TEMP DEBUGGER TRACE: Add this line right here!
  console.log("🕵️‍♂️ DEBUG PACKET ARRIVED:", { urlsFound, emlDetails });
  
  // ✅ FIXED: Dual fallback check to handle both nested and unnested API endpoints safely
  const intelligentUrls = emlDetails?.url_intelligence || emlDetails?.eml_details?.url_intelligence || [];
  
  // State handle for the collapsible verified safe link section
  const [showClean, setShowClean] = useState(false);

 // ── ✅ BULLETPROOF MATCHING: Convert status to lowercase before filtering ──
  const maliciousUrls = intelligentUrls.filter(u => {
    const status = u.status ? String(u.status).toLowerCase() : "";
    return status === "malicious" || status === "suspicious";
  });
  
  const cleanUrls = intelligentUrls.filter(u => {
    const status = u.status ? String(u.status).toLowerCase() : "";
    return status === "clean" || status === "harmless";
  });
  // Fallback structural rendering if the backend didn't supply virus total layers yet
  const formatFallback = intelligentUrls.length === 0 && urlsFound?.length > 0;

  const cardStyle = {
    background: dark ? "rgba(15,23,42,0.95)" : "rgba(248,250,252,0.95)",
    border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
    borderRadius: 16,
    padding: "1.75rem",
    display: "flex",
    flexDirection: "column",
    gap: "1.5rem",
  };

  const tableLabelStyle = {
    padding: "0.6rem 0.75rem",
    fontFamily: "'Space Mono', monospace",
    fontSize: "0.72rem",
    fontWeight: 700,
    color: dark ? "#64748b" : "#94a3b8",
    width: "160px",
    verticalAlign: "top",
    borderBottom: `1px solid ${dark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)"}`
  };

  const tableValueStyle = {
    padding: "0.6rem 0.75rem",
    fontFamily: "'Space Mono', monospace",
    fontSize: "0.72rem",
    color: dark ? "#e2e8f0" : "#334155",
    wordBreak: "break-all",
    borderBottom: `1px solid ${dark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)"}`
  };

  const renderAuthBadge = (protocol, status) => {
    const isPass = status === "PASS";
    const isFail = status === "FAIL";
    
    let bg = "rgba(148,163,184,0.1)";
    let border = "1px solid rgba(148,163,184,0.2)";
    let color = dark ? "#94a3b8" : "#64748b";

    if (isPass) {
      bg = "rgba(34,197,94,0.08)";
      border = "1px solid rgba(34,197,94,0.3)";
      color = "#22c55e";
    } else if (isFail) {
      bg = "rgba(239,68,68,0.08)";
      border = "1px solid rgba(239,68,68,0.3)";
      color = "#ef4444";
    }

    return (
      <div style={{
        flex: 1, padding: "0.6rem", background: bg, border: border, borderRadius: 10, textAlign: "center"
      }}>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.58rem", color: dark ? "#64748b" : "#94a3b8", letterSpacing: 1 }}>{protocol}</div>
        <div style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, fontSize: "0.85rem", color: color, marginTop: "0.15rem" }}>{status}</div>
      </div>
    );
  };

  return (
    <div style={cardStyle}>

      {/* ── 🛡️ EXTRACTION LAYER: ADVANCED EML FORENSICS PANEL ── */}
      {emlDetails && (
        <div style={{
          paddingBottom: "1.25rem",
          borderBottom: `1px dashed ${dark ? "rgba(56,189,248,0.15)" : "rgba(3,105,161,0.15)"}`,
          display: "flex", flexDirection: "column", gap: "1rem"
        }}>
          <div>
            <SectionTitle label="🔒 Security Protocol Verification" dark={dark} />
            <div style={{ display: "flex", gap: "0.5rem" }}>
              {renderAuthBadge("SPF (Sender Policy)", emlDetails.security_protocols?.spf || emlDetails.authentication?.spf)}
              {renderAuthBadge("DKIM (Signature)", emlDetails.security_protocols?.dkim || emlDetails.authentication?.dkim)}
              {renderAuthBadge("DMARC (Alignment)", emlDetails.security_protocols?.dmarc || emlDetails.authentication?.dmarc)}
            </div>
          </div>

          <div style={{
            padding: "0.9rem",
            background: emlDetails.metadata.header_mismatch 
              ? "rgba(239,68,68,0.04)" 
              : dark ? "rgba(30,58,95,0.2)" : "rgba(241,245,249,0.7)",
            border: `1px solid ${emlDetails.metadata.header_mismatch ? "rgba(239,68,68,0.2)" : dark ? "#1e3a5f" : "#e2e8f0"}`,
            borderRadius: 12, fontSize: "0.78rem", fontFamily: "'Space Mono', monospace"
          }}>
            <div style={{ color: dark ? "#38bdf8" : "#0369a1", fontWeight: 700, fontSize: "0.65rem", letterSpacing: 1, marginBottom: "0.4rem" }}>TRANSPATH METADATA</div>
            <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: dark ? "#cbd5e1" : "#334155" }}>
              <span style={{ color: dark ? "#475569" : "#94a3b8" }}>FROM:</span> {emlDetails.metadata.from}
            </div>
            <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
              <span style={{ color: dark ? "#475569" : "#94a3b8" }}>REPLY-TO:</span> {emlDetails.metadata.reply_to}
            </div>
            
            {emlDetails.metadata.return_path && (
              <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
                <span style={{ color: dark ? "#475569" : "#94a3b8" }}>RETURN-PATH:</span> {emlDetails.metadata.return_path}
              </div>
            )}
            
            {emlDetails.metadata.domain_age && (() => {
              const ageStr = emlDetails.metadata.domain_age;
              const isNew = ageStr.includes("(NEWLY CREATED)");
              const isSkipped = ageStr.includes("Skipped");
              
              const textAccentColor = isNew 
                ? "#f59e0b" 
                : isSkipped 
                  ? (dark ? "#64748b" : "#94a3b8") 
                  : (dark ? "#22c55e" : "#16a34a");
                  
              return (
                <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
                  <span style={{ color: dark ? "#475569" : "#94a3b8" }}>DOMAIN AGE:</span>{' '}
                  <span style={{ color: textAccentColor, fontWeight: isNew ? 700 : 500 }}>
                    {ageStr}
                  </span>
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* ── 🚨 THREAT INDICATORS ── */}
      {reasons && reasons.length > 0 && (
        <div>
          <SectionTitle label="⚠ Threat Indicators" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {reasons.map((r, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "0.75rem",
                  padding: "0.7rem 1rem",
                  background: dark ? "rgba(239,68,68,0.06)" : "rgba(239,68,68,0.04)",
                  border: "1px solid rgba(239,68,68,0.2)",
                  borderRadius: 10,
                  fontFamily: "'Space Mono', monospace",
                  fontSize: "0.8rem",
                  color: dark ? "#e2e8f0" : "#1e293b",
                }}
              >
                <span style={{ fontSize: 16, flexShrink: 0 }}>{ICON_MAP[r.type] || "⚠"}</span>
                {r.message}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 🌐 LIVE DNS FORENSICS GRID ── */}
      {emlDetails && emlDetails.dns_intelligence && (
        <div style={{
          marginTop: "0.25rem",
          padding: "1rem 1.25rem",
          background: dark ? "rgba(15,23,42,0.4)" : "rgba(248,250,252,0.6)",
          border: `1px solid ${dark ? "rgba(56,189,248,0.08)" : "#e2e8f0"}`,
          borderRadius: 12,
        }}>
          <div style={{ color: dark ? "#38bdf8" : "#0369a1", fontWeight: 700, fontSize: "0.65rem", letterSpacing: 1, marginBottom: "0.6rem", fontFamily: "'Space Mono', monospace" }}>
            NETWORK RESOLVER INTELLIGENCE
          </div>
          
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <tbody>
              <tr>
                <td style={tableLabelStyle}>TARGET DOMAIN</td>
                <td style={tableValueStyle}>
                  <strong style={{ color: dark ? "#38bdf8" : "#0369a1" }}>{emlDetails.metadata.sender_domain}</strong>
                </td>
              </tr>
              <tr>
                <td style={tableLabelStyle}>MX CHECK STATUS</td>
                <td style={tableValueStyle}>
                  <span style={{ color: emlDetails.dns_intelligence.mx_check.includes("VALID") ? "#22c55e" : "#ef4444", fontWeight: 600 }}>
                    {emlDetails.dns_intelligence.mx_check}
                  </span>
                  {emlDetails.dns_intelligence.mx_records?.length > 0 && (
                    <div style={{ fontSize: "0.65rem", color: dark ? "#64748b" : "#94a3b8", marginTop: 4 }}>
                      MX Hosts: {emlDetails.dns_intelligence.mx_records.join(", ")}
                    </div>
                  )}
                </td>
              </tr>
              <tr>
                <td style={tableLabelStyle}>SPF RECORD</td>
                <td style={tableValueStyle}>
                  <div style={{ color: emlDetails.dns_intelligence.spf_record.includes("FAILED") ? "#ef4444" : "#22c55e", fontSize: "0.68rem" }}>
                    {emlDetails.dns_intelligence.spf_record}
                  </div>
                  <div style={{ 
                    fontSize: "0.62rem", 
                    color: dark ? "#94a3b8" : "#475569", 
                    marginTop: 6, 
                    fontFamily: "sans-serif",
                    background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.02)",
                    padding: "4px 8px",
                    borderRadius: "4px",
                    display: "inline-block"
                  }}>
                    🧠 <span style={{ fontWeight: 600, color: dark ? "#38bdf8" : "#0284c7" }}>SOC Analyst Guidance:</span> {emlDetails.dns_intelligence.spf_analyst_note}
                  </div>
                </td>
              </tr>
              <tr>
                <td style={tableLabelStyle}>DMARC POLICY</td>
                <td style={tableValueStyle}>
                  <div style={{ color: emlDetails.dns_intelligence.dmarc_policy.includes("FAILED") ? "#ef4444" : "#22c55e", fontSize: "0.68rem" }}>
                    {emlDetails.dns_intelligence.dmarc_policy}
                  </div>
                  <div style={{ 
                    fontSize: "0.62rem", 
                    color: dark ? "#94a3b8" : "#475569", 
                    marginTop: 6, 
                    fontFamily: "sans-serif",
                    background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.02)",
                    padding: "4px 8px",
                    borderRadius: "4px",
                    display: "inline-block"
                  }}>
                    🧠 <span style={{ fontWeight: 600, color: dark ? "#38bdf8" : "#0284c7" }}>SOC Analyst Guidance:</span> {emlDetails.dns_intelligence.dmarc_analyst_note}
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {/* ── 📁 ATTACHMENT INVENTORY MODULE ── */}
      {emlDetails && emlDetails.attachments && emlDetails.attachments.length > 0 && (
        <div>
          <SectionTitle label="📎 Attachment Inventory" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {emlDetails.attachments.map((file, i) => {
              const dangerous_extensions = ["exe", "bat", "scr", "vbs", "cmd", "lnk", "zip", "rar"];
              const isDangerous = dangerous_extensions.includes(file.extension);
              
              return (
                <div 
                  key={i} 
                  style={{
                    padding: "0.75rem 1rem",
                    background: isDangerous 
                      ? "rgba(239,68,68,0.07)" 
                      : dark ? "rgba(34,197,94,0.04)" : "rgba(34,197,94,0.02)",
                    border: `1px solid ${isDangerous ? "rgba(239,68,68,0.25)" : "rgba(34,197,94,0.2)"}`,
                    borderRadius: 10,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "1rem"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", overflow: "hidden" }}>
                    <span style={{ fontSize: 13 }}>{isDangerous ? "🚫" : "✅"}</span>
                    <div style={{ overflow: "hidden" }}>
                      <span style={{ 
                        fontFamily: "'Space Mono', monospace", 
                        fontSize: "0.75rem", 
                        fontWeight: isDangerous ? 700 : 500,
                        color: isDangerous ? "#ef4444" : dark ? "#e2e8f0" : "#1e293b",
                        wordBreak: "break-all"
                      }}>
                        {file.filename}
                      </span>
                      <span style={{ 
                        fontFamily: "'Space Mono', monospace", 
                        fontSize: "0.65rem", 
                        color: dark ? "#64748b" : "#94a3b8", 
                        marginLeft: 10 
                      }}>
                        ({file.size_kb > 1024 ? `${(file.size_kb / 1024).toFixed(2)} MB` : `${file.size_kb} KB`})
                      </span>
                    </div>
                  </div>

                  {isDangerous && (
                    <span style={{ 
                      fontSize: '0.58rem', 
                      background: 'rgba(239,68,68,0.1)', 
                      color: '#ef4444', 
                      padding: '2px 6px', 
                      borderRadius: 4, 
                      fontWeight: 700,
                      fontFamily: 'sans-serif',
                      flexShrink: 0
                    }}>
                      CRITICAL PAYLOAD
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── 🔍 SUSPICIOUS CONTENT LAYER ── */}
      {highlightedContent?.length > 0 && (
        <div>
          <SectionTitle label="🔍 Suspicious Content" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {highlightedContent.map((h, i) => (
              <div
                key={i}
                style={{
                  padding: "0.65rem 0.9rem",
                  background: dark ? "rgba(245,158,11,0.07)" : "rgba(245,158,11,0.05)",
                  border: "1px solid rgba(245,158,11,0.28)",
                  borderRadius: 8,
                }}
              >
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.8rem", color: "#f59e0b", fontWeight: 700, marginBottom: 3 }}>
                  "{h.text}"
                </div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", color: dark ? "#94a3b8" : "#64748b" }}>
                  Reason: {h.reason}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 🔗 REFACTORED BULLETPROOF URL INTELLIGENCE INTERFACE ── */}
      {((intelligentUrls && intelligentUrls.length > 0) || (urlsFound && urlsFound.length > 0)) && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.9rem" }}>
            <SectionTitle label="🔗 URL Intelligence" dark={dark} />
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
            
            {/* Fallback View Mode: If reading older layout arrays before processing VT data layer */}
            {formatFallback && urlsFound.map((u, i) => (
              <div key={i} style={{
                padding: "0.75rem 1rem",
                background: u.safe ? (dark ? "rgba(34,197,94,0.04)" : "rgba(34,197,94,0.02)") : (dark ? "rgba(239,68,68,0.07)" : "rgba(239,68,68,0.04)"),
                border: `1px solid ${u.safe ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.25)"}`,
                borderRadius: 10, display: "flex", alignItems: "center", gap: "0.6rem"
              }}>
                <span style={{ fontSize: 13 }}>{u.safe ? "✅" : "🚫"}</span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.75rem", color: u.safe ? "#22c55e" : "#ef4444", wordBreak: "break-all" }}>{u.url}</span>
              </div>
            ))}

            {/* 🚨 DROPDOWN A: FLAGGED THREATS (Malicious / Suspicious) */}
            {maliciousUrls.length > 0 && (
              <div style={{ border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.02)", borderRadius: 12, padding: "0.75rem" }}>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", fontWeight: 700, color: "#ef4444", marginBottom: "0.5rem", letterSpacing: 1 }}>
                  🚫 FLAGGED THREATS ({maliciousUrls.length})
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                  {maliciousUrls.map((item, idx) => (
                    <div key={idx} style={{ padding: "0.6rem", background: "rgba(0,0,0,0.2)", borderRadius: 8, borderLeft: "3px solid #ef4444", fontSize: "0.72rem" }}>
                      <div style={{ fontFamily: "'Space Mono', monospace", color: dark ? "#e2e8f0" : "#1e293b", wordBreak: "break-all" }}>{item.url}</div>
                      <div style={{ fontSize: "0.62rem", color: "#f87171", marginTop: 4, fontFamily: "sans-serif" }}>
                        ⚠️ Threat Status: {item.details || "Flagged by active security vendors"}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 🟢 DROPDOWN B: VERIFIED SAFE LINKS (Collapsible) */}
            {cleanUrls.length > 0 && (
              <div style={{ border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`, borderRadius: 12, overflow: "hidden" }}>
                <button
                  type="button"
                  onClick={() => setShowClean(!showClean)}
                  style={{
                    width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.75rem 1rem",
                    background: dark ? "rgba(255,255,255,0.01)" : "rgba(0,0,0,0.01)", border: "none", cursor: "pointer", outline: "none"
                  }}
                >
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", fontWeight: 700, color: "#22c55e", letterSpacing: 1 }}>
                    🟢 VERIFIED SAFE LINKS ({cleanUrls.length})
                  </span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.65rem", color: "#64748b" }}>{showClean ? "[ CLOSE ]" : "[ EXPAND ]"}</span>
                </button>
                
                {showClean && (
                  <div style={{ padding: "0.75rem", background: "rgba(0,0,0,0.15)", borderTop: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, maxHeight: "150px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                    {cleanUrls.map((item, idx) => (
                      <div key={idx} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.5rem 0.6rem", background: dark ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.02)", borderRadius: 6, fontSize: "0.7rem", fontFamily: "'Space Mono', monospace", color: dark ? "#94a3b8" : "#475569" }}>
                        <span style={{ wordBreak: "break-all", maxWidth: "80%" }}>{item.url}</span>
                        <span style={{ fontSize: "0.58rem", background: "rgba(34,197,94,0.1)", color: "#22c55e", padding: "1px 4px", borderRadius: 3, fontWeight: 700 }}>CLEAN</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* 🛡️ IF COMPONENT HAS ZERO USER ACTIONABLE LINKS IN BOTH BUCKETS */}
            {intelligentUrls.length > 0 && maliciousUrls.length === 0 && cleanUrls.length === 0 && (
              <div style={{
                padding: "0.75rem 1rem",
                background: dark ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.01)",
                border: `1px dashed ${dark ? "rgba(56,189,248,0.15)" : "#cbd5e1"}`,
                borderRadius: 10, fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", color: "#64748b", textAlign: "center"
              }}>
                ℹ️ Links processed cleanly. No interface alerts generated.
              </div>
            )}

          </div>
        </div>
      )}
    </div>
  );
}