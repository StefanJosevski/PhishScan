import { useEffect, useRef, useState } from "react";
import { sendChat, type ChatMessage } from "./ai";

const SUGGESTIONS = [
  "Is it safe to click the link?",
  "What should I do now?",
  "How can I tell this is fake?",
];

// Gemini sometimes uses markdown; show it as plain text.
const plain = (t: string) => t.replace(/\*\*/g, "").replace(/`/g, "").replace(/^\s*[*-]\s+/gm, "• ");

export default function GeminiPanel({
  emailText, summary, hc,
}: {
  emailText: string;
  summary?: string;
  hc: boolean;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "nearest" });
  }, [messages, loading]);

  if (emailText.trim() === "") return null;

  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const cardBg = hc ? "#1F2937" : "white";
  const headerBg = hc ? "#111827" : "#F8FAFC";
  const borderColor = hc ? "#374151" : "#E2E8F0";
  const bubbleBg = hc ? "#111827" : "#F1F5F9";

  const send = async (raw: string) => {
    const text = raw.trim();
    if (!text || loading) return;
    const next: ChatMessage[] = [...messages, { role: "user", text }];
    setMessages(next);
    setInput("");
    setError("");
    setLoading(true);
    const reply = await sendChat(emailText, next);
    setLoading(false);
    if (reply) {
      setMessages([...next, { role: "model", text: reply }]);
    } else {
      setMessages(messages);
      setInput(text);
      setError("Gemini couldn't answer right now. Please try again in a moment.");
    }
  };

  return (
    <section aria-labelledby="gemini-heading" className="mb-7 rounded-2xl overflow-hidden" style={{ background: cardBg, border: `1.5px solid ${borderColor}` }}>
      <div className="px-5 py-3.5 flex flex-wrap items-center justify-between gap-2" style={{ background: headerBg, borderBottom: `1px solid ${borderColor}` }}>
        <h2 id="gemini-heading" className="text-base font-bold" style={{ color: textPrimary }}>Ask Gemini about this email</h2>
        <span className="text-xs" style={{ color: textSecondary }}>AI-generated. Double-check important decisions.</span>
      </div>

      <div className="px-5 py-4" role="log" aria-live="polite" aria-label="Conversation with Gemini">
        <div className="rounded-xl px-4 py-3 mb-3 text-sm leading-relaxed" style={{ background: bubbleBg, color: textPrimary }}>
          <span className="sr-only">Gemini: </span>
          {summary ? plain(summary) : "Ask me anything about this email."}
        </div>

        {messages.map((m, i) => (
          <div key={i} className={`flex mb-3 ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className="rounded-xl px-4 py-3 text-sm leading-relaxed whitespace-pre-wrap"
              style={{
                maxWidth: "85%",
                background: m.role === "user" ? "#2563EB" : bubbleBg,
                color: m.role === "user" ? "white" : textPrimary,
              }}
            >
              <span className="sr-only">{m.role === "user" ? "You: " : "Gemini: "}</span>
              {m.role === "user" ? m.text : plain(m.text)}
            </div>
          </div>
        ))}

        {loading && <p className="text-xs mb-2" style={{ color: textSecondary }}>Gemini is thinking…</p>}
        {error && <p role="alert" className="text-xs mb-2 font-medium" style={{ color: "#DC2626" }}>{error}</p>}
        <div ref={endRef} />
      </div>

      {messages.length === 0 && (
        <div className="px-5 pb-3 flex flex-wrap gap-2">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => send(s)}
              disabled={loading}
              className="px-3 py-1.5 rounded-full text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              style={{ border: `1px solid ${borderColor}`, color: hc ? "#93C5FD" : "#1D4ED8", background: "transparent", cursor: loading ? "not-allowed" : "pointer" }}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      <form
        onSubmit={(e) => { e.preventDefault(); send(input); }}
        className="flex gap-2 px-5 pb-3"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          maxLength={500}
          placeholder="Ask a follow-up question…"
          aria-label="Ask Gemini a follow-up question"
          className="flex-1 px-4 py-2.5 rounded-xl text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          style={{ border: `1.5px solid ${borderColor}`, background: hc ? "#111827" : "white", color: textPrimary }}
        />
        <button
          type="submit"
          disabled={loading || input.trim() === ""}
          className="px-5 py-2.5 rounded-xl text-sm font-bold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
          style={{
            background: loading || input.trim() === "" ? (hc ? "#374151" : "#CBD5E1") : "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)",
            cursor: loading || input.trim() === "" ? "not-allowed" : "pointer",
          }}
        >
          Ask
        </button>
      </form>

      <p className="px-5 pb-4 text-xs" style={{ color: textSecondary }}>
        The email text is sent to Google&apos;s Gemini to write this review and answer your questions.
      </p>
    </section>
  );
}
