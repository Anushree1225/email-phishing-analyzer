/**
 * FindingsList - renders threat indicators, highlighted suspicious content,
 *               and URL intelligence (redirect chains, safe/danger badges).
 *
 * Props:
 *   dark              {boolean}  - theme flag
 *   reasons           {Array}    - array of { type, message } from API
 *   highlightedContent{Array}    - array of { text, reason }
 *   urlsFound         {Array}    - array of { url, safe, redirect_chain }
 */

const ICON_MAP = {
  credential_request: "🔑",
  lookalike_domain:   "🌐",
  sender_verification:"📧",
  urgent_language:    "⚡",
  suspicious_url:     "🔗",
  spoofed_header:     "🎭",
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

export default function FindingsList({ dark, reasons, highlightedContent, urlsFound }) {
  const cardStyle = {
    background: dark ? "rgba(15,23,42,0.95)" : "rgba(248,250,252,0.95)",
    border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
    borderRadius: 16,
    padding: "1.75rem",
    display: "flex",
    flexDirection: "column",
    gap: "1.5rem",
  };

  return (
    <div style={cardStyle}>

      {/* ── Threat Indicators ── */}
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
                animation: `slideIn 0.3s ease ${i * 0.07}s both`,
              }}
            >
              <span style={{ fontSize: 16, flexShrink: 0 }}>{ICON_MAP[r.type] || "⚠"}</span>
              {r.message}
            </div>
          ))}
        </div>
      </div>

      {/* ── Highlighted Suspicious Content ── */}
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

      {/* ── URL Intelligence ── */}
      {urlsFound?.length > 0 && (
        <div>
          <SectionTitle label="🔗 URL Intelligence" dark={dark} />
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {urlsFound.map((u, i) => (
              <div
                key={i}
                style={{
                  padding: "0.9rem 1rem",
                  background: u.safe
                    ? dark ? "rgba(34,197,94,0.06)" : "rgba(34,197,94,0.04)"
                    : dark ? "rgba(239,68,68,0.07)" : "rgba(239,68,68,0.04)",
                  border: `1px solid ${u.safe ? "rgba(34,197,94,0.25)" : "rgba(239,68,68,0.25)"}`,
                  borderRadius: 10,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: u.redirect_chain.length > 0 ? "0.55rem" : 0 }}>
                  <span style={{ fontSize: 14 }}>{u.safe ? "✅" : "🚫"}</span>
                  <span style={{
                    fontFamily: "'Space Mono', monospace",
                    fontSize: "0.78rem",
                    color: u.safe ? "#22c55e" : "#ef4444",
                    fontWeight: 700,
                    wordBreak: "break-all",
                  }}>
                    {u.url}
                  </span>
                </div>
                {u.redirect_chain.length > 0 && (
                  <div style={{ paddingLeft: "1.5rem" }}>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.67rem", color: "#f59e0b", marginBottom: "0.25rem" }}>
                      REDIRECT CHAIN:
                    </div>
                    {u.redirect_chain.map((r, j) => (
                      <div key={j} style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.7rem", color: dark ? "#94a3b8" : "#64748b", display: "flex", alignItems: "center", gap: "0.3rem" }}>
                        {j > 0 && <span style={{ color: "#f59e0b" }}>→</span>}
                        <span style={{ wordBreak: "break-all" }}>{r}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
