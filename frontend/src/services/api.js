import axios from "axios";

// 🚀 Use your actual workspace subdomain string from your frontend port link!
const API_BASE_URL = "https://super-duper-space-fiesta-97469x4xv6wv2x5x9-8000.app.github.dev";
const MOCK_RESPONSE = {
  risk_score: 87,
  severity: "High",
  reasons: [
    { type: "credential_request", message: "Email asks for credentials" },
    { type: "lookalike_domain", message: "Domain resembles Microsoft" },
    { type: "sender_verification", message: "Sender could not be verified" },
    { type: "urgent_language", message: "Urgent language detected" },
    { type: "suspicious_url", message: "Suspicious redirect URL found", url: "http://micros0ft-verify.xyz/login" },
    { type: "spoofed_header", message: "Email header shows signs of spoofing" },
  ],
  recommended_action: [
    "Do not interact with this email",
    "Report it to the security team",
    "Delete the email immediately",
    "Do not click any links or download attachments",
  ],
  urls_found: [
    {
      url: "http://micros0ft-verify.xyz/login",
      safe: false,
      redirect_chain: ["http://micros0ft-verify.xyz/login", "http://malware-host.ru/payload"],
    },
    {
      url: "https://support.microsoft.com",
      safe: true,
      redirect_chain: [],
    },
    {
      url: "http://bit.ly/3xPhish",
      safe: false,
      redirect_chain: ["http://bit.ly/3xPhish", "http://steal-creds.net"],
    },
  ],
  highlighted_content: [
    { text: "Verify your account immediately", reason: "Urgency trigger" },
    { text: "click here to confirm your identity", reason: "Credential phishing" },
    { text: "Your account will be suspended", reason: "Fear/threat language" },
  ],
  scan_id: "SCAN-2024-A7F3",
  scanned_at: new Date().toISOString(),
};

const USE_MOCK = false; // Set to false when backend is ready

// Simulated delay for mock
const mockDelay = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Analyze raw email text
 * POST /analyze
 */
export const analyzeEmail = async (payload) => {
  if (USE_MOCK) {
    await mockDelay(2800);
    return { ...MOCK_RESPONSE, scanned_at: new Date().toISOString() };
  }
  // 🚀 FIXED: Pointing cleanly to API_BASE_URL
  const res = await axios.post(`${API_BASE_URL}/analyze`, payload);
  return res.data;
};

/**
 * Analyze uploaded .eml or image file
 * POST /analyze/file (multipart/form-data)
 */
export const analyzeEmailFile = async (file) => {
  if (USE_MOCK) {
    await mockDelay(3200);
    return { ...MOCK_RESPONSE, scanned_at: new Date().toISOString() };
  }
  const formData = new FormData();
  formData.append("file", file);
  
  // 🚀 FIXED: Pointing cleanly to API_BASE_URL
  const res = await axios.post(`${API_BASE_URL}/analyze/file`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return res.data;
};