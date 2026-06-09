/**
 * PasteEmailBox - large textarea for pasting raw email content
 * Props:
 *   dark     {boolean} - theme flag
 *   value    {string}  - controlled textarea value
 *   onChange {fn}      - called with new string on change
 */
export default function PasteEmailBox({ dark, value, onChange }) {
  const border = dark ? "#1e3a5f" : "#cbd5e1";

  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={`Paste raw email content here…\n\nFrom: security@micros0ft-verify.xyz\nTo: victim@company.com\nSubject: Urgent: Verify your account immediately\n\nDear User,\nClick here to confirm your identity or your account will be suspended within 24 hours.`}
      style={{
        width: "100%",
        minHeight: 220,
        fontFamily: "'Space Mono', monospace",
        fontSize: "0.8rem",
        lineHeight: 1.75,
        padding: "1.1rem 1.2rem",
        background: dark ? "rgba(15,23,42,0.7)" : "rgba(248,250,252,0.9)",
        border: `1px solid ${border}`,
        borderRadius: 12,
        color: dark ? "#e2e8f0" : "#1e293b",
        resize: "vertical",
        outline: "none",
        boxSizing: "border-box",
        transition: "border-color 0.2s",
      }}
      onFocus={(e) => (e.target.style.borderColor = "#38bdf8")}
      onBlur={(e) => (e.target.style.borderColor = border)}
    />
  );
}
