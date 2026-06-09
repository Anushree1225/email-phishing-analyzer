import { useState, useEffect } from "react";

/**
 * Returns color/label metadata for a given severity string
 */
export function severityMeta(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "high")   return { color: "#ef4444", bg: "rgba(239,68,68,0.12)",  label: "HIGH RISK",   icon: "🔴" };
  if (s === "medium") return { color: "#f59e0b", bg: "rgba(245,158,11,0.12)", label: "MEDIUM RISK", icon: "🟡" };
  return                     { color: "#22c55e", bg: "rgba(34,197,94,0.12)",  label: "LOW RISK",    icon: "🟢" };
}

/**
 * RiskCard - animated SVG donut gauge + severity badge
 * Props:
 *   dark   {boolean} - theme flag
 *   result {object}  - analysis result (risk_score, severity, scan_id, scanned_at)
 */
export default function RiskCard({ dark, result }) {
  const meta = severityMeta(result.severity);
  const [displayScore, setDisplayScore] = useState(0);

  // Animate score counter on mount
  useEffect(() => {
    let cur = 0;
    const id = setInterval(() => {
      cur += 2;
      if (cur >= result.risk_score) {
        setDisplayScore(result.risk_score);
        clearInterval(id);
      } else {
        setDisplayScore(cur);
      }
    }, 18);
    return () => clearInterval(id);
  }, [result.risk_score]);

  const R = 54;
  const circumference = 2 * Math.PI * R;
  const offset = circumference - (displayScore / 100) * circumference;

  return (
    <div
      style={{
        background: dark ? "rgba(15,23,42,0.95)" : "rgba(248,250,252,0.95)",
        border: `1px solid ${meta.color}40`,
        borderRadius: 16,
        padding: "2rem",
        boxShadow: `0 0 30px ${meta.color}18`,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: "1rem",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Top accent bar */}
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, ${meta.color}, transparent)` }} />

      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", letterSpacing: 3, color: dark ? "#64748b" : "#94a3b8", textTransform: "uppercase" }}>
        Threat Assessment
      </div>

      {/* Donut gauge */}
      <svg width="130" height="130" viewBox="0 0 130 130">
        <circle cx="65" cy="65" r={R} fill="none" stroke={dark ? "#1e293b" : "#e2e8f0"} strokeWidth="10" />
        <circle
          cx="65" cy="65" r={R}
          fill="none"
          stroke={meta.color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 65 65)"
          style={{ filter: `drop-shadow(0 0 8px ${meta.color})`, transition: "stroke-dashoffset 0.05s linear" }}
        />
        <text x="65" y="60" textAnchor="middle" fontSize="28" fontWeight="700" fontFamily="'Space Mono', monospace" fill={meta.color}>
          {displayScore}
        </text>
        <text x="65" y="78" textAnchor="middle" fontSize="11" fontFamily="'Space Mono', monospace" fill={dark ? "#64748b" : "#94a3b8"}>
          / 100
        </text>
      </svg>

      {/* Severity badge */}
      <div
        style={{
          background: meta.bg,
          border: `1px solid ${meta.color}50`,
          borderRadius: 999,
          padding: "0.35rem 1.2rem",
          fontFamily: "'Space Mono', monospace",
          fontWeight: 700,
          fontSize: "0.82rem",
          color: meta.color,
          letterSpacing: 2,
        }}
      >
        {meta.icon} {meta.label}
      </div>

      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: "0.68rem", color: dark ? "#475569" : "#94a3b8", textAlign: "center" }}>
        <div>{result.scan_id}</div>
        <div style={{ marginTop: 2 }}>{new Date(result.scanned_at).toLocaleTimeString()}</div>
      </div>
    </div>
  );
}
