import type { Indicator, RiskTier } from "./analyzer";

const API_BASE = (import.meta.env.VITE_API_URL ?? "http://localhost:3001").replace(/\/+$/, "");

export type AiReview = { tier: RiskTier; summary: string; indicators: Indicator[] };
export type ChatMessage = { role: "user" | "model"; text: string };

// Asks the server for Gemini's opinion. Returns null if anything goes wrong,
// so the normal rule-based result is still shown.
export async function fetchAiReview(text: string): Promise<AiReview | null> {
  if (text.trim() === "") return null;
  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data?.tier !== "high-risk" && data?.tier !== "suspicious" && data?.tier !== "safe") return null;
    const indicators: Indicator[] = (Array.isArray(data.indicators) ? data.indicators : []).map((i: any) => ({
      label: String(i?.label ?? "Flagged by AI review"),
      severity: i?.severity === "critical" ? "critical" : "moderate",
      explanation: String(i?.explanation ?? ""),
      technical: "Source: Gemini AI review",
    }));
    return { tier: data.tier, summary: String(data.summary ?? ""), indicators };
  } catch {
    return null;
  }
}

// Sends a follow-up question about the scanned email. Returns null on failure.
export async function sendChat(text: string, messages: ChatMessage[]): Promise<string | null> {
  try {
    const res = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, messages }),
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return typeof data?.reply === "string" && data.reply !== "" ? data.reply : null;
  } catch {
    return null;
  }
}
