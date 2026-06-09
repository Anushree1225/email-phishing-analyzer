import { useState, useEffect } from "react";

/**
 * ScanProgress - animated progress bar shown while the API call is in-flight
 * Props:
 *   dark {boolean} - theme flag
 */
const STEPS = [
  "Parsing email headers…",
  "Scanning URLs & domains…",
  "Analyzing language patterns…",
  "Checking sender reputation…",
  "Generating threat report…",
];

export default function ScanProgress({ dark }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const id = setInterval(
      () => setStep((s) => Math.min(s + 1, STEPS.length - 1)),
      520
    );
    return () => clearInterval(id);
  }, []);

  const pct = Math.round(((step + 1) / STEPS.length) * 100);

  return (
    <div style={{
      background: dark ? "rgba(15,23,42,0.95)" : "rgba(248,250,252,0.95)",
      border: `1px solid ${dark ? "#1e3a5f" : "#cbd5e1"}`,
      borderRadius: 16,
      padding: "2rem",
      marginBottom: "1.5rem",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "1.25rem" }}>
        <span style={{ fontSize: 22, animation: "spin 1s linear infinite", display: "inline-block" }}>⚙️</span>
        <span style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, fontSize: "1rem", color: dark ? "#38bdf8" : "#0369a1", letterSpacing: 1 }}>
          SCANNING IN PROGRESS
        </span>
      </div>

      {/* Progress bar */}
      <div style={{ background: dark ? "#0f172a" : "#e2e8f0", borderRadius: 999, height: 8, marginBottom: "1rem", overflow: "hidden" }}>
        <div style={{
          height: "100%",
          width: `${pct}%`,
          background: "linear-gradient(90deg, #38bdf8, #818cf8)",
          borderRadius: 999,
          transition: "width 0.5s ease",
          boxShadow: "0 0 12px rgba(56,189,248,0.55)",
        }} />
      </div>

      {/* Steps */}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
        {STEPS.map((s, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: "0.5rem",
            fontFamily: "'Space Mono', monospace", fontSize: "0.78rem",
            color: i < step ? "#22c55e" : i === step ? (dark ? "#38bdf8" : "#0369a1") : dark ? "#475569" : "#94a3b8",
            transition: "color 0.4s",
          }}>
            <span>{i < step ? "✓" : i === step ? "▶" : "○"}</span>
            {s}
          </div>
        ))}
      </div>

      <div style={{ marginTop: "1rem", fontFamily: "'Space Mono', monospace", fontSize: "0.72rem", color: dark ? "#64748b" : "#94a3b8", textAlign: "right" }}>
        {pct}% complete
      </div>
    </div>
  );
}
