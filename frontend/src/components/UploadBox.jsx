import { useRef, useState, useCallback } from "react";

/**
 * UploadBox - drag-and-drop or click-to-upload for .eml / .pdf / image files
 * Props:
 * dark        {boolean}  - theme flag
 * file        {File|null}- currently selected file
 * onFileSelect {fn}      - called with File when user picks one
 */
export default function UploadBox({ dark, file, onFileSelect }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef();

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragging(false);
      const f = e.dataTransfer.files[0];
      if (f) onFileSelect(f);
    },
    [onFileSelect]
  );

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragging(true);
  };

  const borderColor = dragging ? "#38bdf8" : dark ? "#1e3a5f" : "#cbd5e1";
  const bg = dragging
    ? dark ? "rgba(56,189,248,0.07)" : "rgba(56,189,248,0.04)"
    : dark ? "rgba(15,23,42,0.6)" : "rgba(248,250,252,0.8)";

  return (
    <div
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={() => setDragging(false)}
      onClick={() => inputRef.current?.click()}
      style={{
        border: `2px dashed ${borderColor}`,
        borderRadius: 14,
        padding: "2.5rem 1.5rem",
        textAlign: "center",
        cursor: "pointer",
        background: bg,
        transition: "all 0.25s ease",
        boxShadow: dragging ? "0 0 24px rgba(56,189,248,0.15)" : "none",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".eml,.msg,.txt,.png,.jpg,.jpeg,.pdf"
        style={{ display: "none" }}
        onChange={(e) => onFileSelect(e.target.files[0])}
      />

      <div style={{ fontSize: 42, marginBottom: "0.75rem" }}>{file ? "📎" : "📂"}</div>

      {file ? (
        <>
          <div style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, color: "#22c55e", fontSize: "0.9rem" }}>
            {file.name}
          </div>
          <div style={{ fontSize: "0.72rem", color: dark ? "#64748b" : "#94a3b8", marginTop: "0.3rem", fontFamily: "'Space Mono', monospace" }}>
            {(file.size / 1024).toFixed(1)} KB · Click to replace
          </div>
        </>
      ) : (
        <>
          {/* 🚀 UPDATED: HEADER LABELS EXPLICITLY CAPTURING PDF FORMAT SUPPORT */}
          <div style={{ fontFamily: "'Space Mono', monospace", fontWeight: 700, color: dark ? "#94a3b8" : "#475569", fontSize: "0.9rem", letterSpacing: "0.5px" }}>
            DROP DATA ARTIFACT HERE (.EML / .PDF)
          </div>
          <div style={{ fontSize: "0.72rem", color: dark ? "#475569" : "#94a3b8", marginTop: "0.35rem", fontFamily: "'Space Mono', monospace" }}>
            or click to browse · .eml .pdf .msg .png .jpg
          </div>
        </>
      )}

      {/* 🚀 ADDED: SYSTEM ARCHITECTURE SPECIFICATIONS BLUEPRINT NOTE */}
      <div 
        onClick={(e) => e.stopPropagation()} // Prevents clicking the notice box from triggering file selection browser layout fields
        style={{
          marginTop: "1.75rem",
          padding: "0.65rem 1rem",
          background: dark ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.03)",
          border: dark ? "1px solid rgba(255,255,255,0.05)" : "1px solid rgba(0,0,0,0.05)",
          borderRadius: 8,
          fontFamily: "'Space Mono', monospace",
          fontSize: "0.65rem",
          color: dark ? "#64748b" : "#475569",
          maxWidth: "540px",
          margin: "1.75rem auto 0 auto",
          lineHeight: "1.4",
          textAlign: "left",
          cursor: "default"
        }}
      >
        💡 <strong>Processing Blueprint Note:</strong> Analysis strategy adapts by input format. 
        Native <code>.eml</code> artifacts offer full network signature validation (SPF/DKIM/DMARC). 
        Static <code>.pdf</code> data views are cross-referenced via textual threat heuristics and internal link annotation mappings.
      </div>
    </div>
  );
}