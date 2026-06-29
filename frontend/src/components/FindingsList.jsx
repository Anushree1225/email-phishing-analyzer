import React, { useState } from 'react';

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

export default function FindingsList({ dark, reasons, highlightedContent, urlsFound, emlDetails, fileType, confidenceLevel }) {
  
  const isPdf = fileType === "pdf" || emlDetails?.file_type === "pdf";
  const isImage = fileType === "image";
  const isText = fileType === "text";
  
  const intelligentUrls = emlDetails?.url_intelligence || [];
  const [showClean, setShowClean] = useState(false);

  const renderAuthBadge = (protocol, status) => {
    const isPass = status === "PASS";
    const isFail = status === "FAIL";
    let bg = "rgba(148,163,184,0.1)";
    let border = "1px solid rgba(148,163,184,0.2)";
    let color = dark ? "#94a3b8" : "#64748b";

    if (isPass) {
      bg = "rgba(34,197,94,0.08)"; border = "1px solid rgba(34,197,94,0.3)"; color = "#22c55e";
    } else if (isFail) {
      bg = "rgba(239,68,68,0.08)"; border = "1px solid rgba(239,68,68,0.3)"; color = "#ef4444";
    }

    return (
      <div style={{ flex: 1, padding: "0.6rem", background: bg, border: border, borderRadius: 10, textAlign: "center" }}>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.58rem", color: dark ? "#64748b" : "#94a3b8", letterSpacing: 1 }}>{protocol}</div>
        <div style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, fontSize: "0.85rem", color: color, marginTop: "0.15rem" }}>{status}</div>
      </div>
    );
  };

  const maliciousUrls = intelligentUrls.filter(u => {
    const status = u.status ? String(u.status).toLowerCase() : "";
    return status === "malicious" || status === "suspicious";
  });

  const finalMalicious = intelligentUrls.length > 0 
    ? maliciousUrls 
    : (urlsFound || []).filter(u => !u.safe).map(u => ({
        url: u.url,
        details: u.details || "Flagged by security vendor signatures"
      }));

  const finalClean = intelligentUrls.length > 0 
    ? intelligentUrls.filter(u => !maliciousUrls.some(m => m.url === u.url)) 
    : (urlsFound || []).filter(u => u.safe).map(u => ({ url: u.url }));

  const formatFallback = intelligentUrls.length === 0 && urlsFound?.length > 0 && finalMalicious.length === 0 && finalClean.length === 0;

  const cardStyle = {
    background: dark ? "rgba(15,23,42,0.95)" : "rgba(248,250,252,0.95)",
    border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
    borderRadius: 16,
    padding: isText ? "0px" : "1.75rem",
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

  const dmarcTagStyle = {
    padding: "0.4rem 0.6rem",
    fontSize: "0.7rem",
    fontFamily: "'Space Mono', monospace",
    borderBottom: `1px solid ${dark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)"}`,
    color: dark ? "#cbd5e1" : "#475569"
  };

  const metaSource = emlDetails?.metadata || {};
  const dnsSource = emlDetails?.dns_intelligence || {};
  const dmarcTags = dnsSource?.dmarc_tags || {};

  const hasThreats = reasons && reasons.length > 0 && reasons[0]?.type !== "clean";

  const finalConfidenceValue = confidenceLevel 
    || emlDetails?.confidence_level 
    || (hasThreats ? 65 : 85);

  const computedConfidence = isPdf 
    ? `${finalConfidenceValue}%` 
    : `${100 - (hasThreats ? 65 : 0)}%`;

  const confidenceColor = hasThreats ? "#ef4444" : "#22c55e";

  const dynamicFrom = metaSource?.from || "Unknown Origin Profile";
  const dynamicSubject = metaSource?.subject || "Native Structural Container Scan";
  const dynamicTo = metaSource?.to || "Active Endpoint Session Target";
  const dynamicDate = metaSource?.date || "Extracted Layer Metadata Runtime";

  return (
    <div style={isText ? { display: "flex", flexDirection: "column", gap: "1.25rem", width: "100%" } : cardStyle}>

      {/* ── 🔒 BOX 1: PROTOCOL VERIFICATION ── */}
      {!isImage && !isText && (
        <>
          {isPdf ? (
            <div>
              <SectionTitle label="📉 Confidence Level" dark={dark} />
              <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", fontFamily: "'Space Mono', monospace" }}>
                <div style={{ fontSize: "2.2rem", fontWeight: 700, color: confidenceColor }}>
                  {computedConfidence}
                </div>
                <div style={{ fontSize: "0.72rem", color: dark ? "#94a3b8" : "#64748b", lineHeight: "1.4", textAlign: "left" }}>
                  <strong style={{ color: hasThreats ? "#eab308" : "#22c55e", display: "block", marginBottom: "0.15rem" }}>
                    {hasThreats ? "FORENSIC CEILING ADJUSTED" : "DOCUMENT ANALYSIS TRUST VALIDATED"}
                  </strong>
                  {hasThreats 
                    ? "Flat container format (.pdf) parsed. Envelope mail signatures do not exist natively within layout streams."
                    : "Layout text streams fully cross-referenced clean. System adjusted trust configuration for static portable assets."}
                </div>
              </div>
            </div>
          ) : (
            <div>
              <SectionTitle label="🔒 Security Protocol Verification" dark={dark} />
              <div style={{ display: "flex", gap: "0.5rem" }}>
                {renderAuthBadge("SPF (Sender Policy)", emlDetails?.security_protocols?.spf || emlDetails?.authentication?.spf)}
                {renderAuthBadge("DKIM (Signature)", emlDetails?.security_protocols?.dkim || emlDetails?.authentication?.dkim)}
                {renderAuthBadge("DMARC (Alignment)", emlDetails?.security_protocols?.dmarc || emlDetails?.authentication?.dmarc)}
              </div>
            </div>
          )}
        </>
      )}

      {/* ── 📬 BOX 2: METADATA PANEL ── */}
      {!isImage && !isText && (
        <div style={{
          padding: "0.9rem",
          background: metaSource?.header_mismatch ? "rgba(239,68,68,0.04)" : dark ? "rgba(30,58,95,0.2)" : "rgba(241,245,249,0.7)",
          border: `1px solid ${metaSource?.header_mismatch ? "rgba(239,68,68,0.2)" : dark ? "#1e3a5f" : "#e2e8f0"}`,
          borderRadius: 12, fontSize: "0.78rem", fontFamily: "'Space Mono', monospace", textAlign: "left"
        }}>
          <div style={{ color: dark ? "#38bdf8" : "#0369a1", fontWeight: 700, fontSize: "0.65rem", letterSpacing: 1, marginBottom: "0.4rem" }}>
            {isPdf ? "📄 DOCUMENT SPECIFICATION METADATA" : "TRANSPATH METADATA"}
          </div>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: dark ? "#cbd5e1" : "#334155" }}>
            <span style={{ color: dark ? "#475569" : "#94a3b8" }}>{isPdf ? "EXTRACTED SENDER:" : "SENDER / FROM:"}</span> {dynamicFrom}
          </div>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
            <span style={{ color: dark ? "#475569" : "#94a3b8" }}>{isPdf ? "EXTRACTED SUBJECT:" : "SUBJECT CONTEXT:"}</span> {dynamicSubject}
          </div>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
            <span style={{ color: dark ? "#475569" : "#94a3b8" }}>{isPdf ? "PRINT / CAPTURE DATE:" : "TIMESTAMP / DATE:"}</span> {dynamicDate}
          </div>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
            <span style={{ color: dark ? "#475569" : "#94a3b8" }}>{isPdf ? "INTENDED RECIPIENT:" : "RECIPIENT / TO:"}</span> {dynamicTo}
          </div>
          {!isPdf && (
            <>
              <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
                <span style={{ color: dark ? "#475569" : "#94a3b8" }}>RETURN-PATH:</span> {metaSource?.return_path || "N/A"}
              </div>
              <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: "0.25rem", color: dark ? "#cbd5e1" : "#334155" }}>
                <span style={{ color: dark ? "#475569" : "#94a3b8" }}>DOMAIN AGE:</span>{' '}
                <span style={{ color: metaSource?.domain_age?.includes("(NEWLY CREATED)") ? "#f59e0b" : "#22c55e" }}>
                  {metaSource?.domain_age || "Unknown"}
                </span>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── ⚠ BOX 3: THREAT INDICATORS ROW ── */}
      {hasThreats && (
        <div style={{ textAlign: "left" }}>
          <SectionTitle label="⚠ Threat Indicators" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {reasons.map((r, i) => (
              <div key={i} style={{
                display: "flex", alignItems: "flex-start", gap: "0.75rem", padding: "0.7rem 1rem",
                background: dark ? "rgba(239,68,68,0.06)" : "rgba(239,68,68,0.04)",
                border: "1px solid rgba(239,68,68,0.2)", borderRadius: 10,
                fontFamily: "'Space Mono', monospace", fontSize: "0.8rem", color: dark ? "#e2e8f0" : "#1e293b",
              }}>
                <span style={{ fontSize: 16, flexShrink: 0 }}>{ICON_MAP[r.type] || "⚠"}</span>
                {r.message}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 💡 BOX 4: TECHNICAL EXTRACTIONS & DMARC RECORD TAGS ── */}
      {dnsSource && !isImage && !isText && (
        <div style={{
          marginTop: "0.25rem", padding: "1rem 1.25rem",
          background: dark ? "rgba(15,23,42,0.4)" : "rgba(248,250,252,0.6)",
          border: `1px solid ${dark ? "rgba(56,189,248,0.08)" : "#e2e8f0"}`, borderRadius: 12,
          textAlign: "left"
        }}>
          <div style={{ color: dark ? "#38bdf8" : "#0369a1", fontWeight: 700, fontSize: "0.65rem", letterSpacing: 1, marginBottom: "0.6rem", fontFamily: "'Space Mono', monospace" }}>
            {isPdf ? "⚙️ ARTIFACT FORENSICS & CONTAINER METADATA" : "NETWORK RESOLVER INTELLIGENCE"}
          </div>
          
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <tbody>
              {isPdf ? (
                <>
                  <tr>
                    <td style={tableLabelStyle}>SENDER DOMAIN SCOPE</td>
                    <td style={tableValueStyle}><strong style={{ color: dark ? "#38bdf8" : "#0369a1" }}>{metaSource?.sender_domain || "Extracted Layout Scope"}</strong></td>
                  </tr>
                  <tr>
                    <td style={tableLabelStyle}>CONTAINER FORMAT</td>
                    <td style={tableValueStyle}>Adobe PDF Portable Asset (Static Print)</td>
                  </tr>
                  <tr>
                    <td style={tableLabelStyle}>TOTAL VISUAL PAGES</td>
                    <td style={tableValueStyle}>{dnsSource?.page_count || 1} Page(s) processed</td>
                  </tr>
                </>
              ) : (
                <>
                  <tr>
                    <td style={tableLabelStyle}>TARGET DOMAIN</td>
                    <td style={tableValueStyle}><strong style={{ color: dark ? "#38bdf8" : "#0369a1" }}>{metaSource?.sender_domain}</strong></td>
                  </tr>
                  <tr>
                    <td style={tableLabelStyle}>MX CHECK STATUS</td>
                    <td style={tableValueStyle}>
                      <span style={{ color: dnsSource?.mx_check?.includes("VALID") ? "#22c55e" : "#ef4444", fontWeight: 600 }}>{dnsSource?.mx_check}</span>
                    </td>
                  </tr>
                  <tr>
                    <td style={tableLabelStyle}>SPF RECORD</td>
                    <td style={tableValueStyle}>
                      <div style={{ color: dnsSource?.spf_record?.includes("FAILED") || dnsSource?.spf_record?.includes("Not Found") ? "#ef4444" : "#22c55e", fontSize: "0.68rem" }}>{dnsSource?.spf_record}</div>
                      <div style={{ fontSize: "0.62rem", color: dark ? "#94a3b8" : "#475569", marginTop: 6, fontFamily: "sans-serif", background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.02)", padding: "4px 8px", borderRadius: "4px", display: "inline-block" }}>
                        🧠 <span style={{ fontWeight: 600, color: dark ? "#38bdf8" : "#0284c7" }}>SOC Analyst Guidance:</span> {dnsSource?.spf_analyst_note}
                      </div>
                    </td>
                  </tr>
                  <tr>
                    <td style={tableLabelStyle}>DMARC RECORD</td>
                    <td style={tableValueStyle}>
                      <div style={{ color: dnsSource?.dmarc_policy?.includes("FAILED") || dnsSource?.dmarc_policy?.includes("Not Found") ? "#ef4444" : "#22c55e", fontSize: "0.68rem" }}>{dnsSource?.dmarc_policy}</div>
                    </td>
                  </tr>
                </>
              )}
            </tbody>
          </table>

          {/* 🎯 FIXED: Renders the sub-tag table ONLY if a real record was found (Bypasses "DMARC Not Found" and PDF files) */}
          {dnsSource.dmarc_policy && 
           dnsSource.dmarc_policy !== "NOT FOUND" && 
           dnsSource.dmarc_policy !== "DMARC Not Found" && 
           !isPdf && (
            <div style={{ 
              marginTop: "1.25rem",
              paddingTop: "1.25rem",
              borderTop: `1px solid ${dark ? "rgba(255,255,255,0.04)" : "rgba(0,0,0,0.04)"}`
            }}>
              <div style={{ color: dark ? "#818cf8" : "#4f46e5", fontWeight: 700, fontSize: "0.62rem", letterSpacing: 1, marginBottom: "0.5rem", fontFamily: "'Space Mono', monospace" }}>
                📋 DMARC LIVE REGISTRY SUB-TAG MAP
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse", background: dark ? "rgba(0,0,0,0.2)" : "rgba(0,0,0,0.01)", borderRadius: "8px" }}>
                <thead>
                  <tr style={{ background: dark ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.02)" }}>
                    <th style={{ ...dmarcTagStyle, fontWeight: 700, width: "70px" }}>Tag</th>
                    <th style={{ ...dmarcTagStyle, fontWeight: 700, width: "130px" }}>Value</th>
                    <th style={{ ...dmarcTagStyle, fontWeight: 700 }}>Functional Descriptor</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={dmarcTagStyle}><strong>v</strong></td>
                    <td style={{ ...dmarcTagStyle, color: "#38bdf8" }}>{dmarcTags.v || "DMARC1"}</td>
                    <td style={dmarcTagStyle}>Protocol Version Rule Definition Specification</td>
                  </tr>
                  <tr>
                    <td style={dmarcTagStyle}><strong>p</strong></td>
                    <td style={{ ...dmarcTagStyle, color: dmarcTags.p === "reject" || dmarcTags.p === "quarantine" ? "#ef4444" : "#f59e0b", fontWeight: 700 }}>{dmarcTags.p || "N/A"}</td>
                    <td style={dmarcTagStyle}>Policy Enforcement action for failed message blocks</td>
                  </tr>
                  <tr>
                    <td style={dmarcTagStyle}><strong>pct</strong></td>
                    <td style={{ ...dmarcTagStyle, color: "#f59e0b" }}>{dmarcTags.pct || "100"}</td>
                    <td style={dmarcTagStyle}>Percentage of outbound streams subjected to alignment constraints</td>
                  </tr>
                  <tr>
                    <td style={dmarcTagStyle}><strong>rua</strong></td>
                    <td style={{ ...dmarcTagStyle, fontSize: "0.65rem" }}>{dmarcTags.rua || "N/A"}</td>
                    <td style={dmarcTagStyle}>Destination endpoint for XML aggregate report delivery arrays</td>
                  </tr>
                  <tr>
                    <td style={dmarcTagStyle}><strong>ruf</strong></td>
                    <td style={{ ...dmarcTagStyle, fontSize: "0.65rem" }}>{dmarcTags.ruf || "N/A"}</td>
                    <td style={dmarcTagStyle}>Destination endpoint for forensic failure alert streams</td>
                  </tr>
                  <tr>
                    <td style={dmarcTagStyle}><strong>fo</strong></td>
                    <td style={dmarcTagStyle}>{dmarcTags.fo || "0"}</td>
                    <td style={dmarcTagStyle}>Failure reporting options logic triggers configured</td>
                  </tr>
                </tbody>
              </table>
              <div style={{ fontSize: "0.62rem", color: dark ? "#94a3b8" : "#475569", marginTop: 10, fontFamily: "sans-serif", background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.02)", padding: "6px 10px", borderRadius: "4px", display: "block" }}>
                🧠 <span style={{ fontWeight: 600, color: dark ? "#38bdf8" : "#0284c7" }}>SOC Alignment Insight:</span> {dnsSource?.dmarc_analyst_note}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── 📁 BOX 5: ATTACHMENT INVENTORY ── */}
      {emlDetails?.attachments && emlDetails.attachments.length > 0 && !isText && (
        <div style={{ textAlign: "left" }}>
          <SectionTitle label="📎 Attachment Inventory" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {emlDetails.attachments.map((file, i) => {
              const dangerous_extensions = ["exe", "bat", "scr", "vbs", "cmd", "lnk", "zip", "rar"];
              const isDangerous = dangerous_extensions.includes(file.extension);
              return (
                <div key={i} style={{ padding: "0.75rem 1rem", background: isDangerous ? "rgba(239,68,68,0.07)" : dark ? "rgba(34,197,94,0.04)" : "rgba(34,197,94,0.02)", border: `1px solid ${isDangerous ? "rgba(239,68,68,0.25)" : "rgba(34,197,94,0.2)"}`, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", overflow: "hidden" }}>
                    <span style={{ fontSize: 13 }}>{isDangerous ? "🚫" : "✅"}</span>
                    <div style={{ overflow: "hidden" }}>
                      <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.75rem", fontWeight: isDangerous ? 700 : 500, color: isDangerous ? "#ef4444" : dark ? "#e2e8f0" : "#1e293b", wordBreak: "break-all" }}>{file.filename}</span>
                      <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.65rem", color: dark ? "#64748b" : "#94a3b8", marginLeft: 10 }}>({file.size_kb > 1024 ? `${(file.size_kb / 1024).toFixed(2)} MB` : `${file.size_kb} KB`})</span>
                    </div>
                  </div>
                  {isDangerous && <span style={{ fontSize: '0.58rem', background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '2px 6px', borderRadius: 4, fontWeight: 700, fontFamily: 'sans-serif', flexShrink: 0 }}>CRITICAL PAYLOAD</span>}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── 🔍 BOX 6: SUSPICIOUS CONTENT LAYER ── */}
      {highlightedContent?.length > 0 && (
        <div style={{ textAlign: "left" }}>
          <SectionTitle label="🔍 Suspicious Content Sentences" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {highlightedContent.map((h, i) => (
              <div key={i} style={{ padding: "0.65rem 0.9rem", background: dark ? "rgba(245,158,11,0.07)" : "rgba(245,158,11,0.05)", border: "1px solid rgba(245,158,11,0.28)", borderRadius: 8 }}>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.8rem", color: "#f59e0b", fontWeight: 700, marginBottom: 3 }}>"{h.text}"</div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", color: dark ? "#cbd5e1" : "#475569" }}>Reason: {h.reason}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 🔗 BOX 7: URL INTELLIGENCE ROW ── */}
      {((finalMalicious && finalMalicious.length > 0) || (finalClean && finalClean.length > 0) || (urlsFound && urlsFound.length > 0)) && (
        <div style={{ textAlign: "left" }}>
          <SectionTitle label="🔗 URL Intelligence" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
            
            {formatFallback && urlsFound.map((u, i) => (
              <div key={i} style={{ padding: "0.75rem 1rem", background: u.safe ? (dark ? "rgba(34,197,94,0.04)" : "rgba(34,197,94,0.02)") : (dark ? "rgba(239,68,68,0.07)" : "rgba(239,68,68,0.04)"), border: `1px solid ${u.safe ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.25)"}`, borderRadius: 10, display: "flex", alignItems: "center", gap: "0.6rem" }}>
                <span style={{ fontSize: 13 }}>{u.safe ? "✅" : "🚫"}</span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.75rem", color: u.safe ? "#22c55e" : "#ef4444", wordBreak: "break-all" }}>{u.url}</span>
              </div>
            ))}

            {finalMalicious.length > 0 && (
              <div style={{ border: "1px solid rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.02)", borderRadius: 12, padding: "0.75rem" }}>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", fontWeight: 700, color: "#ef4444", marginBottom: "0.5rem", letterSpacing: 1 }}>🚫 FLAGGED THREATS ({finalMalicious.length})</div>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                  {finalMalicious.map((item, idx) => (
                    <div key={idx} style={{ padding: "0.6rem", background: "rgba(0,0,0,0.25)", borderRadius: 8, borderLeft: "3px solid #ef4444", fontSize: "0.72rem" }}>
                      <div style={{ fontFamily: "'Space Mono', monospace", color: dark ? "#e2e8f0" : "#1e293b", wordBreak: "break-all" }}>{item.url}</div>
                      <div style={{ fontSize: "0.62rem", color: "#f87171", marginTop: 4, fontFamily: "sans-serif" }}>⚠️ Threat Status: {item.details || "Flagged by active security databases"}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}  

            {finalClean.length > 0 && (
              <div style={{ border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`, borderRadius: 12, overflow: "hidden" }}>
                <button type="button" onClick={() => setShowClean(!showClean)} style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.75rem 1rem", background: dark ? "rgba(255,255,255,0.01)" : "rgba(0,0,0,0.01)", border: "none", cursor: "pointer", outline: "none" }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", fontWeight: 700, color: "#22c55e", letterSpacing: 1 }}>🟢 VERIFIED SAFE LINKS ({finalClean.length})</span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.65rem", color: "#64748b" }}>{showClean ? "[ CLOSE ]" : "[ EXPAND ]"}</span>
                </button>
                {showClean && (
                  <div style={{ padding: "0.75rem", background: "rgba(0,0,0,0.15)", borderTop: `1px solid ${dark ? "#1e3a5f" : "#e2e8f0"}`, maxHeight: "150px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                    {finalClean.map((item, idx) => (
                      <div key={idx} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.5rem 0.6rem", background: dark ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.02)", borderRadius: 6, fontSize: "0.7rem", fontFamily: "'Space Mono', monospace", color: dark ? "#94a3b8" : "#475569" }}>
                        <span style={{ wordBreak: "break-all", maxWidth: "80%" }}>{item.url}</span>
                        <span style={{ fontSize: "0.58rem", background: "rgba(34,197,94,0.1)", color: "#22c55e", padding: "1px 4px", borderRadius: 3, fontWeight: 700 }}>CLEAN</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}