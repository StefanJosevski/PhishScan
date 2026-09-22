import { useState, useEffect, useRef, useCallback } from "react";

// ─── Types ───────────────────────────────────────────────────────────────────
type View = "login" | "mfa" | "upload" | "scanning" | "high-risk" | "suspicious" | "safe" | "history" | "alerts" | "settings";
type ScanResult = "high-risk" | "suspicious" | "safe";
type UploadTab = "file" | "text";
type FontSize = "standard" | "large" | "xl";

interface AppSettings {
  fontSize: FontSize;
  highContrast: boolean;
  reduceMotion: boolean;
}

// ─── Static data ─────────────────────────────────────────────────────────────
const SCAN_STAGES = [
  { at: 0, msg: "Checking sender reputation…" },
  { at: 28, msg: "Scanning embedded links…" },
  { at: 58, msg: "Verifying SPF / DKIM / DMARC…" },
  { at: 82, msg: "Analysing message body for social engineering…" },
];

const SCAN_CHECKLIST = [
  { label: "Sender domain lookup", doneAt: 27 },
  { label: "Link & URL analysis", doneAt: 55 },
  { label: "Email authentication (SPF / DKIM / DMARC)", doneAt: 80 },
  { label: "Domain reputation & age", doneAt: 90 },
  { label: "Content & urgency language scan", doneAt: 98 },
];

const HIGH_RISK_INDICATORS = [
  {
    label: "Sender domain mismatch",
    plain: "This email claims to be from Acme Corp payroll, but it was actually sent from a Russian server with no connection to Acme Corp.",
    technical: "RFC5322 From: payroll@acme.com — actual SMTP envelope sender: mail.srv-track29.ru. Domain has no SPF authorisation for acme.com.",
    severity: "critical",
  },
  {
    label: "Suspicious embedded link",
    plain: "A button in the email labelled \"Verify your account\" secretly leads to a fake website designed to steal your login details.",
    technical: "Href resolves to hxxp://acme-secure-login.net/auth — registered 6 days ago, not an Acme Corp asset. VirusTotal: 14/87 engines flagged.",
    severity: "critical",
  },
  {
    label: "Email authentication completely failed",
    plain: "Standard security checks that legitimate senders always pass — all failed. This is a strong sign the email is forged.",
    technical: "SPF: fail (srv-track29.ru not in acme.com SPF record). DKIM: no valid signature. DMARC: p=reject — message should have been blocked.",
    severity: "critical",
  },
  {
    label: "Urgency and pressure language",
    plain: "The email uses threatening language to make you act without thinking — a classic manipulation tactic used in phishing.",
    technical: "Lexical classifier detected 7 urgency markers: 'immediate action required', 'account will be suspended', '24-hour deadline', 'verify now', 'urgent', 'failure to comply', 'lose access'. Threshold for High Risk: ≥4.",
    severity: "high",
  },
  {
    label: "Spoofed branding",
    plain: "The Acme Corp logo in the email is not hosted on Acme's website — it was loaded from an external server the attacker controls.",
    technical: "img src: hxxp://cdn.mail-assets-host.net/acme-logo.png. Pixel hash matches known phishing kit #PK-2041 in PhishScan database.",
    severity: "high",
  },
];

const SUSPICIOUS_INDICATORS = [
  {
    label: "Unfamiliar sender domain",
    plain: "The email comes from a domain you and your organisation have not exchanged email with before. This does not mean it is fake, but warrants a quick check.",
    technical: "Sender: hr-updates@hrplatform-notify.io — first contact with this domain. Reputation score: 61/100 (below 70 threshold). Domain age: 14 months.",
    severity: "medium",
  },
  {
    label: "Link passes through a redirect service",
    plain: "The link in this email does not go directly to its destination — it bounces through a shortening service first, which can hide where you are really going.",
    technical: "Redirect chain: t.co → bit.ly/3xR9kPa → hrplatform-notify.io/verify. Final domain not in organisation allowlist. TLS valid.",
    severity: "medium",
  },
  {
    label: "Mild urgency framing",
    plain: "The email uses slightly urgent language that could be legitimate but is also a common tactic to pressure people into acting quickly.",
    technical: "Lexical classifier detected 2 urgency markers: 'please respond by end of day', 'action required'. Below High Risk threshold of 4.",
    severity: "low",
  },
  {
    label: "Display name does not match sender address",
    plain: "The name shown in your email client says 'HR Department' but the actual email address is from a different, unfamiliar domain.",
    technical: "Display name: 'HR Department'. RFC5322 From: hr-noreply@hrplatform-notify.io. SPF: pass. DKIM: pass. DMARC: pass (p=none).",
    severity: "low",
  },
];

const SAFE_CHECKS = [
  { label: "Email headers & routing", result: "Pass" },
  { label: "SPF authentication", result: "Pass" },
  { label: "DKIM signature", result: "Pass" },
  { label: "DMARC policy alignment", result: "Pass" },
  { label: "Embedded links (3 found)", result: "All clean" },
  { label: "Sender domain reputation", result: "Trusted — 98/100" },
  { label: "Urgency / pressure language", result: "None detected" },
  { label: "Attachment scan", result: "Clean" },
];

const HISTORY_ITEMS = [
  { name: "invoice_Q3_2026.pdf", status: "high-risk", date: "11 Sep 2026, 09:14", user: "Sarah Kim", size: "214 KB" },
  { name: "welcome_offer.eml", status: "high-risk", date: "11 Sep 2026, 08:57", user: "Sarah Kim", size: "38 KB" },
  { name: "board_minutes_sept.docx", status: "safe", date: "11 Sep 2026, 08:02", user: "Sarah Kim", size: "1.1 MB" },
  { name: "shipping_update.msg", status: "safe", date: "10 Sep 2026, 17:44", user: "Sarah Kim", size: "61 KB" },
  { name: "password_reset.eml", status: "high-risk", date: "10 Sep 2026, 14:20", user: "Sarah Kim", size: "29 KB" },
  { name: "hr_policy_update.pdf", status: "safe", date: "10 Sep 2026, 11:06", user: "Sarah Kim", size: "445 KB" },
  { name: "urgent_wire_transfer.msg", status: "high-risk", date: "9 Sep 2026, 16:33", user: "Sarah Kim", size: "52 KB" },
];

const ALERT_ITEMS = [
  {
    id: 1,
    title: "High-risk email detected on shared mailbox",
    detail: "finance@acme.com received a phishing attempt impersonating CFO. File: wire_transfer_auth.eml",
    severity: "critical",
    time: "2 min ago",
    read: false,
  },
  {
    id: 2,
    title: "3 employees scanned the same phishing email",
    detail: "Coordinated phishing campaign detected. 3 users submitted invoice_Q3_2026.pdf within 10 minutes.",
    severity: "high",
    time: "18 min ago",
    read: false,
  },
  {
    id: 3,
    title: "New phishing domain spoofing your brand",
    detail: "acme-secure-login.net was registered 6 days ago and is being used in active phishing campaigns.",
    severity: "high",
    time: "1 hr ago",
    read: false,
  },
  {
    id: 4,
    title: "DMARC policy weakened — action recommended",
    detail: "Your DMARC policy changed from p=reject to p=none at 03:12 UTC. Review your DNS records.",
    severity: "medium",
    time: "6 hr ago",
    read: true,
  },
  {
    id: 5,
    title: "Monthly summary: 23 scans, 7 threats blocked",
    detail: "August 2026 report is ready. Threat rate: 30%. Top vector: domain impersonation.",
    severity: "info",
    time: "Yesterday",
    read: true,
  },
];

// ─── Icons (inline SVG wrappers) ─────────────────────────────────────────────
const Icon = {
  upload: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  clock: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
  bell: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>,
  settings: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06-.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
  check: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
  chevronRight: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>,
  chevronLeft: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>,
  file: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
  shield: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  warning: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  shieldCheck: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>,
  info: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
  phone: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12 19.79 19.79 0 0 1 1.61 3.43 2 2 0 0 1 3.6 1.25h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.37a16 16 0 0 0 6 6l1.27-.9a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>,
  eye: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
  eyeOff: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
  logout: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: string }) {
  if (status === "high-risk") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold" style={{ background: "#FEE2E2", color: "#DC2626", border: "1px solid #FECACA" }}>
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#DC2626" }} aria-hidden />
        High Risk
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold" style={{ background: "#D1FAE5", color: "#065F46", border: "1px solid #BBF7D0" }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#059669" }} aria-hidden />
      Safe
    </span>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className="relative flex-shrink-0 rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
      style={{ width: 44, height: 24, background: checked ? "#2563EB" : "#CBD5E1" }}
    >
      <span
        className="absolute top-0.5 left-0.5 rounded-full bg-white shadow transition-transform duration-200"
        style={{ width: 20, height: 20, transform: checked ? "translateX(20px)" : "translateX(0)" }}
      />
    </button>
  );
}

// ─── Toast ───────────────────────────────────────────────────────────────────
function Toast({ message, type, onDismiss }: { message: string; type: "success" | "error" | "info"; onDismiss: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 4000);
    return () => clearTimeout(t);
  }, [onDismiss]);

  const colors = {
    success: { bg: "#F0FDF4", border: "#BBF7D0", text: "#065F46", icon: "#059669" },
    error: { bg: "#FFF5F5", border: "#FECACA", text: "#991B1B", icon: "#DC2626" },
    info: { bg: "#EFF6FF", border: "#DBEAFE", text: "#1E40AF", icon: "#3B82F6" },
  }[type];

  return (
    <div
      role="alert"
      className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-5 py-4 rounded-2xl shadow-xl"
      style={{ background: colors.bg, border: `1.5px solid ${colors.border}`, maxWidth: 360 }}
    >
      <span style={{ color: colors.icon }} aria-hidden>
        {type === "success" ? <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
          : type === "error" ? Icon.warning
          : Icon.info}
      </span>
      <p className="text-sm font-semibold flex-1" style={{ color: colors.text }}>{message}</p>
      <button onClick={onDismiss} aria-label="Dismiss notification" style={{ color: colors.icon }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
  );
}

// ─── Sidebar ─────────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: "upload", label: "Upload", icon: Icon.upload },
  { id: "history", label: "Scan History", icon: Icon.clock },
  { id: "alerts", label: "Alerts", icon: Icon.bell, badge: 3 },
  { id: "settings", label: "Settings", icon: Icon.settings },
];

function Sidebar({
  activeNav, onNav, onLogout, hc,
}: {
  activeNav: string;
  onNav: (id: string) => void;
  onLogout: () => void;
  hc: boolean;
}) {
  const bg = hc ? "#000000" : "#0F172A";
  const border = hc ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.06)";

  return (
    <aside
      className="fixed left-0 top-0 bottom-0 flex flex-col z-20"
      style={{ width: 240, background: bg, borderRight: `1px solid ${border}` }}
    >
      {/* Logo */}
      <div className="px-5 pt-6 pb-5" style={{ borderBottom: `1px solid ${border}` }}>
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center rounded-xl" style={{ width: 38, height: 38, background: "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)" }}>
            <span style={{ color: "white" }}>{Icon.shield}</span>
          </div>
          <div>
            <div className="font-bold text-base leading-tight tracking-tight" style={{ color: "white" }}>PhishScan</div>
            <div className="text-xs font-medium" style={{ color: hc ? "#94A3B8" : "#64748B" }}>Email Security</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 overflow-y-auto" aria-label="Main navigation">
        <p className="px-3 mb-2 text-xs font-semibold uppercase tracking-widest" style={{ color: hc ? "#64748B" : "#475569" }}>Main</p>
        {NAV_ITEMS.map((item) => {
          const active = activeNav === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNav(item.id)}
              aria-current={active ? "page" : undefined}
              className="w-full flex items-center gap-3 px-3 py-3 rounded-lg mb-0.5 text-sm font-medium transition-colors duration-150 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
              style={{
                background: active ? (hc ? "rgba(37,99,235,0.3)" : "rgba(37,99,235,0.15)") : "transparent",
                color: active ? "#60A5FA" : (hc ? "#CBD5E1" : "#94A3B8"),
                border: active ? `1px solid rgba(37,99,235,0.3)` : "1px solid transparent",
              }}
            >
              <span aria-hidden style={{ color: active ? "#60A5FA" : (hc ? "#64748B" : "#64748B") }}>{item.icon}</span>
              <span className="flex-1">{item.label}</span>
              {item.badge && (
                <span className="flex items-center justify-center w-5 h-5 rounded-full text-xs font-bold" style={{ background: "#DC2626", color: "white" }} aria-label={`${item.badge} unread alerts`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* User */}
      <div className="px-3 pb-4 pt-3" style={{ borderTop: `1px solid ${border}` }}>
        <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg" style={{ background: hc ? "rgba(255,255,255,0.08)" : "rgba(255,255,255,0.04)" }}>
          <div className="flex items-center justify-center rounded-full text-sm font-bold flex-shrink-0" style={{ width: 34, height: 34, background: "linear-gradient(135deg,#6366F1,#8B5CF6)", color: "white" }}>SK</div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold truncate" style={{ color: "white" }}>Sarah Kim</p>
            <p className="text-xs truncate" style={{ color: hc ? "#94A3B8" : "#64748B" }}>IT Security Analyst</p>
          </div>
          <button
            onClick={onLogout}
            aria-label="Sign out"
            title="Sign out"
            className="flex-shrink-0 p-1.5 rounded-md transition-colors duration-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
            style={{ color: hc ? "#94A3B8" : "#475569" }}
          >
            {Icon.logout}
          </button>
        </div>
      </div>
    </aside>
  );
}

// ─── TopBar ───────────────────────────────────────────────────────────────────
function TopBar({ crumb, hc }: { crumb: string; hc: boolean }) {
  return (
    <div
      className="sticky top-0 z-10 flex items-center justify-between px-8 h-14"
      style={{
        background: hc ? "rgba(0,0,0,0.95)" : "rgba(248,250,252,0.9)",
        backdropFilter: "blur(12px)",
        borderBottom: `1px solid ${hc ? "rgba(255,255,255,0.12)" : "#E2E8F0"}`,
      }}
    >
      <div className="flex items-center gap-2 text-xs" style={{ color: hc ? "#94A3B8" : "#94A3B8" }}>
        <span style={{ color: hc ? "#CBD5E1" : undefined }}>PhishScan</span>
        <span aria-hidden style={{ color: hc ? "#64748B" : undefined }}>{Icon.chevronRight}</span>
        <span className="font-semibold" style={{ color: hc ? "white" : "#475569" }}>{crumb}</span>
      </div>
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium" style={{ background: hc ? "rgba(37,99,235,0.2)" : "#EFF6FF", color: hc ? "#93C5FD" : "#3B82F6", border: hc ? "1px solid rgba(37,99,235,0.4)" : "1px solid #DBEAFE" }}>
        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 inline-block" aria-hidden />
        Engine v3.1 &middot; Live
      </div>
    </div>
  );
}

// ─── Login Screen ─────────────────────────────────────────────────────────────
function LoginScreen({ onSuccess }: { onSuccess: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!email.trim()) { setError("Please enter your email address."); return; }
    if (!password) { setError("Please enter your password."); return; }
    setLoading(true);
    setTimeout(() => { setLoading(false); onSuccess(); }, 900);
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ background: "#F8FAFC" }}>
      <div className="w-full" style={{ maxWidth: 420 }}>
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center rounded-2xl mb-4" style={{ width: 56, height: 56, background: "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)" }}>
            <span style={{ color: "white" }}><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-900">Sign in to PhishScan</h1>
          <p className="text-sm mt-1" style={{ color: "#64748B" }}>Protect your organisation from phishing attacks</p>
        </div>

        {/* Card */}
        <div className="rounded-2xl bg-white p-8 shadow-sm" style={{ border: "1px solid #E2E8F0" }}>
          <form onSubmit={handleSubmit} noValidate>
            {error && (
              <div role="alert" className="flex items-center gap-2.5 px-4 py-3 rounded-xl mb-5 text-sm font-medium" style={{ background: "#FEF2F2", border: "1px solid #FECACA", color: "#DC2626" }}>
                <span aria-hidden style={{ flexShrink: 0 }}>{Icon.warning}</span>
                {error}
              </div>
            )}

            <div className="mb-5">
              <label htmlFor="login-email" className="block text-sm font-semibold mb-2" style={{ color: "#374151" }}>Email address</label>
              <input
                id="login-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@acme.com"
                className="w-full px-4 py-3 rounded-xl text-sm focus:outline-none transition-shadow duration-150"
                style={{ border: "1.5px solid #CBD5E1", color: "#0F172A", background: "white" }}
                onFocus={(e) => { e.target.style.border = "1.5px solid #2563EB"; e.target.style.boxShadow = "0 0 0 3px rgba(37,99,235,0.1)"; }}
                onBlur={(e) => { e.target.style.border = "1.5px solid #CBD5E1"; e.target.style.boxShadow = "none"; }}
              />
            </div>

            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <label htmlFor="login-password" className="block text-sm font-semibold" style={{ color: "#374151" }}>Password</label>
                <button type="button" className="text-xs font-medium text-blue-600 hover:underline focus:outline-none focus-visible:underline">Forgot password?</button>
              </div>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPw ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full px-4 py-3 pr-12 rounded-xl text-sm focus:outline-none transition-shadow duration-150"
                  style={{ border: "1.5px solid #CBD5E1", color: "#0F172A", background: "white" }}
                  onFocus={(e) => { e.target.style.border = "1.5px solid #2563EB"; e.target.style.boxShadow = "0 0 0 3px rgba(37,99,235,0.1)"; }}
                  onBlur={(e) => { e.target.style.border = "1.5px solid #CBD5E1"; e.target.style.boxShadow = "none"; }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  aria-label={showPw ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                  style={{ color: "#94A3B8" }}
                >
                  {showPw ? Icon.eyeOff : Icon.eye}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-semibold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 transition-all duration-150"
              style={{ background: loading ? "#93C5FD" : "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)", boxShadow: loading ? "none" : "0 4px 12px rgba(37,99,235,0.3)", cursor: loading ? "not-allowed" : "pointer" }}
            >
              {loading ? (
                <>
                  <svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><circle cx="12" cy="12" r="10" strokeOpacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10" /></svg>
                  Signing in&hellip;
                </>
              ) : (
                <><span aria-hidden>{Icon.shield}</span> Sign In</>
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-xs mt-6" style={{ color: "#94A3B8" }}>
          Protected by PhishScan &copy; 2026 Acme Corp. All rights reserved.
        </p>
      </div>
    </div>
  );
}

// ─── MFA Screen ───────────────────────────────────────────────────────────────
function MFAScreen({ onSuccess, onBack }: { onSuccess: () => void; onBack: () => void }) {
  const [digits, setDigits] = useState(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const refs = useRef<(HTMLInputElement | null)[]>([]);

  const handleChange = (i: number, val: string) => {
    if (!/^\d*$/.test(val)) return;
    const next = [...digits];
    next[i] = val.slice(-1);
    setDigits(next);
    setError("");
    if (val && i < 5) refs.current[i + 1]?.focus();
    if (next.every((d) => d !== "") && next.join("").length === 6) {
      setLoading(true);
      setTimeout(() => { setLoading(false); onSuccess(); }, 800);
    }
  };

  const handleKeyDown = (i: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !digits[i] && i > 0) {
      const next = [...digits];
      next[i - 1] = "";
      setDigits(next);
      refs.current[i - 1]?.focus();
    }
    if (e.key === "ArrowLeft" && i > 0) refs.current[i - 1]?.focus();
    if (e.key === "ArrowRight" && i < 5) refs.current[i + 1]?.focus();
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (digits.some((d) => !d)) { setError("Please enter all 6 digits."); return; }
    setLoading(true);
    setTimeout(() => { setLoading(false); onSuccess(); }, 800);
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ background: "#F8FAFC" }}>
      <div className="w-full" style={{ maxWidth: 420 }}>
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center rounded-2xl mb-4" style={{ width: 56, height: 56, background: "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)" }}>
            <span style={{ color: "white" }}>{Icon.shield}</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-900">Two-factor authentication</h1>
          <p className="text-sm mt-1 text-center" style={{ color: "#64748B" }}>Enter the 6-digit code from your authenticator app.</p>
        </div>

        <div className="rounded-2xl bg-white p-8 shadow-sm" style={{ border: "1px solid #E2E8F0" }}>
          <form onSubmit={handleSubmit} noValidate>
            {error && (
              <div role="alert" className="flex items-center gap-2.5 px-4 py-3 rounded-xl mb-5 text-sm font-medium" style={{ background: "#FEF2F2", border: "1px solid #FECACA", color: "#DC2626" }}>
                <span aria-hidden>{Icon.warning}</span>
                {error}
              </div>
            )}

            <div className="flex gap-3 justify-center mb-6" role="group" aria-label="6-digit verification code">
              {digits.map((d, i) => (
                <input
                  key={i}
                  ref={(el) => { refs.current[i] = el; }}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={d}
                  onChange={(e) => handleChange(i, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(i, e)}
                  aria-label={`Digit ${i + 1}`}
                  className="text-center text-xl font-bold rounded-xl focus:outline-none transition-all duration-150"
                  style={{
                    width: 48, height: 56,
                    border: `2px solid ${d ? "#2563EB" : "#CBD5E1"}`,
                    background: d ? "#EFF6FF" : "white",
                    color: "#0F172A",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                  onFocus={(e) => { e.target.style.border = "2px solid #2563EB"; e.target.style.boxShadow = "0 0 0 3px rgba(37,99,235,0.1)"; }}
                  onBlur={(e) => { e.target.style.border = `2px solid ${d ? "#2563EB" : "#CBD5E1"}`; e.target.style.boxShadow = "none"; }}
                />
              ))}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-semibold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 transition-all duration-150"
              style={{ background: loading ? "#93C5FD" : "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)", boxShadow: loading ? "none" : "0 4px 12px rgba(37,99,235,0.3)", cursor: loading ? "not-allowed" : "pointer" }}
            >
              {loading ? (
                <><svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10" strokeOpacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10"/></svg> Verifying&hellip;</>
              ) : (
                <><span aria-hidden>{Icon.check}</span> Verify Code</>
              )}
            </button>

            <div className="flex items-center justify-between mt-4">
              <button type="button" onClick={onBack} className="text-sm font-medium text-blue-600 hover:underline focus:outline-none focus-visible:underline flex items-center gap-1">
                <span aria-hidden>{Icon.chevronLeft}</span> Back
              </button>
              <button type="button" className="text-sm font-medium text-blue-600 hover:underline focus:outline-none focus-visible:underline">Resend code</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

// ─── Upload Screen ─────────────────────────────────────────────────────────────
function UploadScreen({
  onScan, hc, reduceMotion,
}: {
  onScan: (result: ScanResult, filename: string) => void;
  hc: boolean;
  reduceMotion: boolean;
}) {
  const [tab, setTab] = useState<UploadTab>("file");
  const [dragOver, setDragOver] = useState(false);
  const [droppedFile, setDroppedFile] = useState<string | null>(null);
  const [pasteText, setPasteText] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const contentBg = hc ? "#111827" : "#F8FAFC";
  const cardBg = hc ? "#1F2937" : "white";
  const borderColor = hc ? "#374151" : "#E2E8F0";
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";

  const RECENT = [
    { name: "invoice_Q3_2026.pdf", status: "high-risk", time: "2 min ago" },
    { name: "welcome_offer.eml", status: "high-risk", time: "14 min ago" },
    { name: "board_minutes_sept.docx", status: "safe", time: "1 hr ago" },
    { name: "shipping_update.msg", status: "safe", time: "3 hr ago" },
  ];

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) setDroppedFile(f.name);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) setDroppedFile(f.name);
  };

  const handleScan = () => {
    const canScan = (tab === "file" && droppedFile) || (tab === "text" && pasteText.trim());
    if (!canScan) return;
    const filename = tab === "file" ? (droppedFile ?? "upload.txt") : "pasted-content.txt";
    const r = Math.random();
    const result: ScanResult = r < 0.4 ? "high-risk" : r < 0.7 ? "suspicious" : "safe";
    onScan(result, filename);
  };

  const canScan = (tab === "file" && droppedFile) || (tab === "text" && pasteText.trim().length > 0);

  return (
    <div className="max-w-3xl mx-auto px-8 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight mb-1" style={{ color: textPrimary }}>New Phishing Scan</h1>
        <p className="text-sm" style={{ color: textSecondary }}>Upload an email or file, or paste raw text, to detect phishing indicators and assess risk.</p>
      </div>

      {/* Tab toggle */}
      <div className="mb-5 inline-flex rounded-xl p-1" style={{ background: hc ? "#1F2937" : "#F1F5F9" }}>
        {(["file", "text"] as UploadTab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            aria-pressed={tab === t}
            className="px-5 py-2 rounded-lg text-sm font-semibold transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            style={{
              background: tab === t ? (hc ? "#374151" : "white") : "transparent",
              color: tab === t ? (hc ? "white" : "#0F172A") : textSecondary,
              boxShadow: tab === t ? "0 1px 3px rgba(0,0,0,0.08)" : "none",
            }}
          >
            {t === "file" ? "Upload File" : "Paste Text"}
          </button>
        ))}
      </div>

      {/* Drop zone or textarea */}
      {tab === "file" ? (
        <>
          <input ref={fileInputRef} type="file" accept=".eml,.msg,.txt,.png,.jpg,.jpeg,.pdf" className="sr-only" onChange={handleFileInput} aria-label="Browse files" />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            aria-label={droppedFile ? `Selected file: ${droppedFile}. Click to change.` : "Click or drag and drop a file to upload"}
            className="w-full flex flex-col items-center justify-center rounded-2xl mb-5 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 transition-all duration-200"
            style={{
              border: `2.5px dashed ${dragOver ? "#2563EB" : (droppedFile ? "#10B981" : (hc ? "#4B5563" : "#CBD5E1"))}`,
              background: dragOver ? "rgba(37,99,235,0.04)" : (droppedFile ? (hc ? "rgba(16,185,129,0.08)" : "#F0FDF4") : (hc ? "#1F2937" : "#FAFBFD")),
              minHeight: 200,
              padding: "2.5rem",
              cursor: "pointer",
              transition: reduceMotion ? "none" : undefined,
            }}
          >
            {droppedFile ? (
              <>
                <div className="flex items-center justify-center rounded-2xl mb-4" style={{ width: 56, height: 56, background: "#D1FAE5" }}>
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                </div>
                <p className="text-sm font-bold mb-1" style={{ color: "#065F46", fontFamily: "'JetBrains Mono', monospace" }}>{droppedFile}</p>
                <p className="text-xs" style={{ color: "#059669" }}>File ready &mdash; click to replace</p>
              </>
            ) : (
              <>
                <div className="flex items-center justify-center rounded-2xl mb-4" style={{ width: 56, height: 56, background: dragOver ? "rgba(37,99,235,0.1)" : (hc ? "#374151" : "#EFF6FF") }}>
                  <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke={dragOver ? "#2563EB" : "#3B82F6"} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                </div>
                <p className="text-sm font-semibold mb-1" style={{ color: textPrimary }}>Drag &amp; drop your email or file here</p>
                <p className="text-xs" style={{ color: textSecondary }}>or <span className="text-blue-600 font-semibold">click to browse</span></p>
                <div className="flex flex-wrap gap-2 mt-5 justify-center">
                  {[".eml", ".msg", ".txt", ".png", ".jpg", ".pdf"].map((ext) => (
                    <span key={ext} className="px-2.5 py-1 rounded-md text-xs font-medium" style={{ background: hc ? "#374151" : "#E2E8F0", color: hc ? "#D1D5DB" : "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{ext}</span>
                  ))}
                </div>
              </>
            )}
          </button>
        </>
      ) : (
        <div className="rounded-2xl overflow-hidden mb-5" style={{ border: `1.5px solid ${borderColor}` }}>
          <div className="px-4 py-2.5 flex items-center gap-2" style={{ background: hc ? "#1F2937" : "#F8FAFC", borderBottom: `1px solid ${borderColor}` }}>
            <span aria-hidden style={{ color: textSecondary }}>{Icon.file}</span>
            <span className="text-xs font-medium" style={{ color: textSecondary }}>Paste raw email headers, message body, or any suspicious text</span>
          </div>
          <textarea
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            placeholder="Paste email content here&#8230;"
            aria-label="Email or message text to scan"
            className="w-full resize-none text-sm focus:outline-none"
            rows={10}
            style={{ padding: "1rem", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, lineHeight: 1.8, background: cardBg, color: textPrimary }}
          />
        </div>
      )}

      {/* Info callout */}
      <div className="rounded-xl p-4 mb-6 flex gap-3" style={{ background: hc ? "rgba(37,99,235,0.15)" : "#EFF6FF", border: `1px solid ${hc ? "rgba(37,99,235,0.35)" : "#DBEAFE"}` }}>
        <span className="flex-shrink-0 mt-0.5" style={{ color: "#3B82F6" }} aria-hidden>{Icon.info}</span>
        <div>
          <p className="text-xs font-bold mb-2" style={{ color: hc ? "#93C5FD" : "#1E40AF" }}>What PhishScan analyses</p>
          <div className="flex flex-wrap gap-x-5 gap-y-1.5">
            {["Email headers & routing", "Embedded links & URLs", "SPF / DKIM / DMARC records", "Sender domain reputation", "Urgency & pressure language", "Spoofed branding signatures"].map((item) => (
              <span key={item} className="text-xs flex items-center gap-1.5" style={{ color: hc ? "#93C5FD" : "#1E40AF" }}>
                <span aria-hidden>{Icon.check}</span>{item}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Scan button */}
      <button
        onClick={handleScan}
        disabled={!canScan}
        className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-bold text-white mb-10 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
        style={{
          background: canScan ? "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)" : (hc ? "#374151" : "#E2E8F0"),
          color: canScan ? "white" : (hc ? "#6B7280" : "#9CA3AF"),
          boxShadow: canScan ? "0 4px 14px rgba(37,99,235,0.3)" : "none",
          cursor: canScan ? "pointer" : "not-allowed",
          transition: reduceMotion ? "none" : "all 0.15s",
        }}
        aria-disabled={!canScan}
      >
        <span aria-hidden>{Icon.shield}</span>
        {canScan ? "Scan for Phishing" : (tab === "file" ? "Add a file to scan" : "Paste content to scan")}
      </button>

      {/* Recent scans */}
      <div>
        <h2 className="text-sm font-bold mb-3" style={{ color: textPrimary }}>Recent Scans</h2>
        <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${borderColor}` }}>
          {RECENT.map((scan, i) => (
            <div
              key={scan.name}
              className="flex items-center gap-3 px-4 py-3.5"
              style={{ borderTop: i > 0 ? `1px solid ${hc ? "#1F2937" : "#F1F5F9"}` : "none", background: cardBg }}
            >
              <span className="flex items-center justify-center rounded-lg flex-shrink-0" style={{ width: 32, height: 32, background: hc ? "#374151" : "#F8FAFC" }} aria-hidden>{Icon.file}</span>
              <span className="flex-1 text-xs font-medium truncate" style={{ fontFamily: "'JetBrains Mono', monospace", color: textPrimary }}>{scan.name}</span>
              <StatusBadge status={scan.status} />
              <span className="text-xs flex-shrink-0" style={{ color: textSecondary }}>{scan.time}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Scanning Screen ───────────────────────────────────────────────────────────
function ScanningScreen({
  filename, onDone, reduceMotion, hc,
}: {
  filename: string;
  onDone: () => void;
  reduceMotion: boolean;
  hc: boolean;
}) {
  const [progress, setProgress] = useState(0);
  const [stageMsg, setStageMsg] = useState(SCAN_STAGES[0].msg);
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const cardBg = hc ? "#1F2937" : "white";
  const borderColor = hc ? "#374151" : "#E2E8F0";

  const tick = useCallback(() => {
    setProgress((p) => {
      const next = Math.min(100, p + (reduceMotion ? 20 : 0.9));
      SCAN_STAGES.forEach((s) => { if (next >= s.at && p < s.at) setStageMsg(s.msg); });
      if (next >= 100) setTimeout(onDone, 600);
      return next;
    });
  }, [onDone, reduceMotion]);

  useEffect(() => {
    const interval = setInterval(tick, reduceMotion ? 200 : 25);
    return () => clearInterval(interval);
  }, [tick, reduceMotion]);

  const pct = Math.floor(progress);
  const currentStageMsg = SCAN_STAGES.reduce((acc, s) => progress >= s.at ? s.msg : acc, SCAN_STAGES[0].msg);

  return (
    <div className="max-w-2xl mx-auto px-8 py-16 flex flex-col items-center">
      {/* Animated shield */}
      <div
        className="flex items-center justify-center rounded-full mb-8"
        style={{
          width: 80, height: 80,
          background: "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)",
          boxShadow: reduceMotion ? "none" : "0 0 0 16px rgba(37,99,235,0.1)",
          animation: reduceMotion ? "none" : "pulse 2s infinite",
        }}
      >
        <span style={{ color: "white" }}>
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </span>
      </div>

      <h1 className="text-xl font-bold mb-1 text-center" style={{ color: textPrimary }}>Scanning for phishing indicators&hellip;</h1>
      <p className="text-sm mb-2 text-center" style={{ color: textSecondary, fontFamily: "'JetBrains Mono', monospace" }}>{filename}</p>
      <p className="text-sm font-medium mb-8 text-center" style={{ color: "#3B82F6" }} aria-live="polite" aria-atomic>{currentStageMsg}</p>

      {/* Progress bar */}
      <div className="w-full rounded-full mb-2 overflow-hidden" style={{ height: 10, background: hc ? "#374151" : "#E2E8F0" }} role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
        <div
          className="h-full rounded-full"
          style={{
            width: `${pct}%`,
            background: "linear-gradient(90deg,#2563EB,#60A5FA)",
            transition: reduceMotion ? "none" : "width 0.04s linear",
          }}
        />
      </div>
      <div className="w-full flex justify-between text-xs mb-10" style={{ color: textSecondary }}>
        <span aria-hidden>{pct}% complete</span>
        <span aria-hidden>{pct < 100 ? "Scanning…" : "Done"}</span>
      </div>

      {/* Checklist */}
      <div className="w-full rounded-2xl p-6" style={{ background: cardBg, border: `1px solid ${borderColor}` }}>
        <h2 className="text-sm font-bold mb-4" style={{ color: textPrimary }}>Checks in progress</h2>
        <ul className="space-y-3">
          {SCAN_CHECKLIST.map((item) => {
            const done = pct >= item.doneAt;
            const active = !done && pct >= (item.doneAt - 28);
            return (
              <li key={item.label} className="flex items-center gap-3">
                <span
                  className="flex items-center justify-center rounded-full flex-shrink-0"
                  style={{
                    width: 22, height: 22,
                    background: done ? "#D1FAE5" : (active ? "#EFF6FF" : (hc ? "#374151" : "#F1F5F9")),
                    border: active && !done ? "2px solid #3B82F6" : "none",
                    transition: reduceMotion ? "none" : "all 0.3s",
                  }}
                  aria-hidden
                >
                  {done ? (
                    <span style={{ color: "#059669" }}>{Icon.check}</span>
                  ) : active ? (
                    <svg className="animate-spin" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" strokeWidth="3"><circle cx="12" cy="12" r="10" strokeOpacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>
                  ) : (
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: hc ? "#6B7280" : "#CBD5E1", display: "block" }} />
                  )}
                </span>
                <span
                  className="text-sm"
                  style={{
                    color: done ? (hc ? "#6EE7B7" : "#059669") : (active ? (hc ? "white" : "#0F172A") : textSecondary),
                    fontWeight: active || done ? 600 : 400,
                    transition: reduceMotion ? "none" : "color 0.3s",
                  }}
                  aria-live={active ? "polite" : undefined}
                >
                  {item.label}
                  {done && <span className="ml-2 text-xs" style={{ color: hc ? "#6EE7B7" : "#10B981" }}>&#10003;</span>}
                </span>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

// ─── Shared: ExpandableIndicator ─────────────────────────────────────────────
function ExpandableIndicator({
  label, plain, technical, severity, hc, accentColor,
}: {
  label: string;
  plain: string;
  technical: string;
  severity: string;
  hc: boolean;
  accentColor: "red" | "amber";
}) {
  const [open, setOpen] = useState(false);

  const isRed = accentColor === "red";
  const styles = {
    bg: isRed ? (hc ? "#1a0000" : "#FFF5F5") : (hc ? "#1a1000" : "#FFFBEB"),
    border: isRed ? (hc ? "#5a1212" : "#FECACA") : (hc ? "#78350F" : "#FDE68A"),
    headingColor: isRed ? (hc ? "#FCA5A5" : "#991B1B") : (hc ? "#FCD34D" : "#92400E"),
    textColor: isRed ? (hc ? "#FCA5A5" : "#7F1D1D") : (hc ? "#FCD34D" : "#78350F"),
    tagBg: isRed ? (hc ? "#7F1D1D" : "#FEE2E2") : (hc ? "#78350F" : "#FEF3C7"),
    tagColor: isRed ? (hc ? "#FCA5A5" : "#DC2626") : (hc ? "#FCD34D" : "#B45309"),
    techBg: isRed ? (hc ? "#2d0000" : "#FEF2F2") : (hc ? "#2d1a00" : "#FFFAEB"),
    linkColor: isRed ? (hc ? "#F87171" : "#DC2626") : (hc ? "#FBBF24" : "#B45309"),
    dotColor: isRed ? "#DC2626" : "#D97706",
  };
  const isCritical = severity === "critical";

  return (
    <div className="rounded-xl" style={{ background: styles.bg, border: `1px solid ${styles.border}`, overflow: "hidden" }}>
      <div className="px-5 py-4 flex gap-3">
        <span className="flex-shrink-0 mt-0.5" aria-hidden>
          {isCritical
            ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={styles.dotColor} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={styles.dotColor} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          }
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <p className="text-sm font-bold" style={{ color: styles.headingColor }}>{label}</p>
            <span className="px-1.5 py-0.5 rounded text-xs font-bold uppercase tracking-wide" style={{ background: styles.tagBg, color: styles.tagColor }}>{severity}</span>
          </div>
          <p className="text-sm leading-relaxed mb-2" style={{ color: styles.textColor }}>{plain}</p>
          <button
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            className="flex items-center gap-1 text-xs font-semibold focus:outline-none focus-visible:underline"
            style={{ color: styles.linkColor }}
          >
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" style={{ transform: open ? "rotate(90deg)" : "rotate(0)", transition: "transform 0.15s" }}><polyline points="9 18 15 12 9 6"/></svg>
            {open ? "Hide technical details" : "Show technical details"}
          </button>
        </div>
      </div>
      {open && (
        <div className="mx-5 mb-4 px-4 py-3 rounded-lg text-xs leading-relaxed" style={{ background: styles.techBg, border: `1px solid ${styles.border}`, fontFamily: "'JetBrains Mono', monospace", color: styles.textColor }}>
          {technical}
        </div>
      )}
    </div>
  );
}

// ─── High Risk Screen ──────────────────────────────────────────────────────────
type InteractionChoice = "link" | "file" | "info" | "none" | null;

const INTERACTION_NEXT_STEPS: Record<string, string[]> = {
  link: [
    "Close any browser tab or window that opened immediately.",
    "Do not enter a username, password, or any personal information on any page that loaded.",
    "Run a security scan on your device using your company antivirus software.",
    "Report this email using the button below — select 'Clicked a link' in the form.",
  ],
  file: [
    "Do not open the file if you have not already done so.",
    "If you already opened it, disconnect your device from the network (turn off Wi-Fi).",
    "Contact IT Security immediately — they will guide you through a malware scan.",
    "Report this email using the button below — select 'Downloaded a file' in the form.",
  ],
  info: [
    "Go to the real website (type the address yourself, do not click any link) and change your password now.",
    "Enable two-factor authentication on that account if you have not already.",
    "Check your other accounts that use the same password and change those too.",
    "Report this email using the button below — select 'Entered information' in the form.",
  ],
  none: [
    "Good — no further steps needed on your end.",
    "Please report this email so IT Security can block the sender and protect your colleagues.",
  ],
};

function HighRiskScreen({
  onBack, filename, hc, reduceMotion, onToast,
}: {
  onBack: () => void;
  filename: string;
  hc: boolean;
  reduceMotion: boolean;
  onToast: (msg: string, type: "success" | "error" | "info") => void;
}) {
  const [reported, setReported] = useState(false);
  const [interaction, setInteraction] = useState<InteractionChoice>(null);
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const cardBg = hc ? "#1F2937" : "white";
  const borderColor = hc ? "#374151" : "#E2E8F0";

  const handleReport = () => {
    if (reported) return;
    setReported(true);
    onToast("Reported to IT Security — ticket #PS-12345 created.", "success");
  };

  const interactionOptions: { id: InteractionChoice; label: string; icon: React.ReactNode }[] = [
    { id: "link", label: "I clicked a link", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg> },
    { id: "file", label: "I downloaded a file", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> },
    { id: "info", label: "I entered information", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> },
    { id: "none", label: "No, I did not interact", icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg> },
  ];

  return (
    <div className="max-w-3xl mx-auto px-8 py-10">
      <button onClick={onBack} className="flex items-center gap-1.5 text-sm mb-6 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-md px-1" style={{ color: textSecondary }}>
        <span aria-hidden>{Icon.chevronLeft}</span> Back to Upload
      </button>

      {/* Banner */}
      <div className="rounded-2xl px-6 py-5 mb-7 flex items-start gap-4" style={{ background: hc ? "#1a0000" : "#FEF2F2", border: `2px solid ${hc ? "#7F1D1D" : "#FCA5A5"}` }} role="alert" aria-label="High Risk result">
        <div className="flex items-center justify-center rounded-xl flex-shrink-0" style={{ width: 52, height: 52, background: hc ? "#7F1D1D" : "#FEE2E2" }}>
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#DC2626" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div className="flex-1">
          <div className="flex flex-wrap items-center gap-2.5 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide" style={{ background: "#DC2626", color: "white" }}>High Risk</span>
            <span className="text-xs font-semibold" style={{ color: hc ? "#FCA5A5" : "#DC2626" }}>5 issues found</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight" style={{ color: hc ? "#FCA5A5" : "#991B1B" }}>This email is very likely a phishing attempt.</h1>
        </div>
      </div>

      {/* File row */}
      <div className="flex items-center gap-3 mb-7 px-4 py-3 rounded-xl" style={{ background: hc ? "#1F2937" : "#F8FAFC", border: `1px solid ${borderColor}` }}>
        <span aria-hidden style={{ color: textSecondary }}>{Icon.file}</span>
        <span className="text-xs font-medium flex-1 truncate" style={{ fontFamily: "'JetBrains Mono', monospace", color: textPrimary }}>{filename}</span>
        <span className="text-xs flex-shrink-0" style={{ color: textSecondary }}>Scanned just now</span>
      </div>

      {/* ── Section 1: What to do ── */}
      <section aria-labelledby="what-to-do" className="mb-7">
        <div className="flex items-center gap-2 mb-3">
          <span className="flex items-center justify-center rounded-full w-6 h-6 text-xs font-bold flex-shrink-0" style={{ background: "#DC2626", color: "white" }} aria-hidden>1</span>
          <h2 id="what-to-do" className="text-base font-bold" style={{ color: textPrimary }}>What to do right now</h2>
        </div>
        <div className="rounded-2xl px-5 py-5" style={{ background: hc ? "#1a0000" : "#FFF5F5", border: `1px solid ${hc ? "#5a1212" : "#FECACA"}` }}>
          <ul className="space-y-3">
            {[
              "Do not click any links or download any attachments in this email.",
              "Do not enter your username, password, or any personal information on any website linked from this email.",
              "Report this email to IT Security using the button at the bottom of this page.",
            ].map((step, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="flex items-center justify-center rounded-full flex-shrink-0 mt-0.5" style={{ width: 20, height: 20, background: hc ? "#7F1D1D" : "#FEE2E2" }} aria-hidden>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#DC2626" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </span>
                <span className="text-sm leading-relaxed" style={{ color: hc ? "#FCA5A5" : "#7F1D1D" }}>{step}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* ── Section 2: Why flagged ── */}
      <section aria-labelledby="why-flagged" className="mb-7">
        <div className="flex items-center gap-2 mb-3">
          <span className="flex items-center justify-center rounded-full w-6 h-6 text-xs font-bold flex-shrink-0" style={{ background: "#DC2626", color: "white" }} aria-hidden>2</span>
          <h2 id="why-flagged" className="text-base font-bold" style={{ color: textPrimary }}>Why this was flagged</h2>
        </div>
        <div className="flex flex-col gap-2.5">
          {HIGH_RISK_INDICATORS.map((ind, i) => (
            <ExpandableIndicator key={i} label={ind.label} plain={ind.plain} technical={ind.technical} severity={ind.severity} hc={hc} accentColor="red" />
          ))}
        </div>
      </section>

      {/* ── Section 3: Interaction question ── */}
      <section aria-labelledby="did-you-interact" className="mb-7">
        <div className="flex items-center gap-2 mb-3">
          <span className="flex items-center justify-center rounded-full w-6 h-6 text-xs font-bold flex-shrink-0" style={{ background: "#DC2626", color: "white" }} aria-hidden>3</span>
          <h2 id="did-you-interact" className="text-base font-bold" style={{ color: textPrimary }}>Did you already interact with this email?</h2>
        </div>
        <p className="text-sm mb-4" style={{ color: textSecondary }}>Select the option that applies. We will show you the right next steps.</p>
        <div className="grid grid-cols-2 gap-2.5 mb-4" role="group" aria-label="Interaction options">
          {interactionOptions.map(({ id, label, icon }) => {
            const selected = interaction === id;
            const isNone = id === "none";
            return (
              <button
                key={id}
                onClick={() => setInteraction(id)}
                aria-pressed={selected}
                className="flex items-center gap-2.5 px-4 py-3.5 rounded-xl text-sm font-semibold text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 transition-all duration-150"
                style={{
                  border: `2px solid ${selected ? (isNone ? "#059669" : "#DC2626") : (hc ? "#374151" : "#E2E8F0")}`,
                  background: selected ? (isNone ? (hc ? "#052e16" : "#F0FDF4") : (hc ? "#1a0000" : "#FFF5F5")) : (hc ? "#1F2937" : "white"),
                  color: selected ? (isNone ? (hc ? "#6EE7B7" : "#065F46") : (hc ? "#FCA5A5" : "#991B1B")) : textPrimary,
                }}
              >
                <span aria-hidden style={{ flexShrink: 0, color: selected ? (isNone ? "#059669" : "#DC2626") : textSecondary }}>{icon}</span>
                {label}
              </button>
            );
          })}
        </div>

        {/* Next steps reveal */}
        {interaction && (
          <div
            className="rounded-xl px-5 py-4"
            role="region"
            aria-label="Next steps"
            aria-live="polite"
            style={{
              background: interaction === "none" ? (hc ? "#052e16" : "#F0FDF4") : (hc ? "#1a0000" : "#FFF5F5"),
              border: `1px solid ${interaction === "none" ? (hc ? "#14532d" : "#BBF7D0") : (hc ? "#5a1212" : "#FECACA")}`,
              transition: reduceMotion ? "none" : "all 0.2s",
            }}
          >
            <p className="text-xs font-bold uppercase tracking-widest mb-3" style={{ color: interaction === "none" ? (hc ? "#6EE7B7" : "#065F46") : (hc ? "#FCA5A5" : "#991B1B") }}>
              Next steps
            </p>
            <ol className="space-y-2.5">
              {INTERACTION_NEXT_STEPS[interaction].map((step, i) => (
                <li key={i} className="flex items-start gap-3">
                  <span className="flex items-center justify-center rounded-full flex-shrink-0 text-xs font-bold mt-0.5" style={{ width: 20, height: 20, background: interaction === "none" ? (hc ? "#14532d" : "#D1FAE5") : (hc ? "#7F1D1D" : "#FEE2E2"), color: interaction === "none" ? (hc ? "#6EE7B7" : "#059669") : (hc ? "#FCA5A5" : "#DC2626") }} aria-hidden>{i + 1}</span>
                  <span className="text-sm leading-relaxed" style={{ color: interaction === "none" ? (hc ? "#6EE7B7" : "#065F46") : (hc ? "#FCA5A5" : "#7F1D1D") }}>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        )}
      </section>

      {/* Reported confirmation banner */}
      {reported && (
        <div className="flex items-center gap-3 px-5 py-4 rounded-xl mb-5" style={{ background: hc ? "#052e16" : "#F0FDF4", border: "1.5px solid #BBF7D0" }} role="status" aria-live="polite">
          <span className="flex items-center justify-center rounded-full flex-shrink-0" style={{ width: 28, height: 28, background: "#D1FAE5" }} aria-hidden>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          </span>
          <div>
            <p className="text-sm font-bold" style={{ color: hc ? "#6EE7B7" : "#065F46" }}>Reported to IT Security</p>
            <p className="text-xs" style={{ color: hc ? "#6EE7B7" : "#047857" }}>Ticket <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>#PS-12345</span> has been created. The IT Security team will follow up.</p>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        <button
          onClick={handleReport}
          disabled={reported}
          className="flex-1 flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-2"
          style={{
            background: reported ? (hc ? "#374151" : "#F0FDF4") : "linear-gradient(135deg,#DC2626 0%,#B91C1C 100%)",
            color: reported ? (hc ? "#9CA3AF" : "#065F46") : "white",
            boxShadow: reported ? "none" : "0 4px 12px rgba(220,38,38,0.3)",
            cursor: reported ? "not-allowed" : "pointer",
          }}
          aria-disabled={reported}
        >
          {reported
            ? <><span aria-hidden><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg></span> Reported to IT Security</>
            : <><span aria-hidden>{Icon.phone}</span> Report to IT Security</>
          }
        </button>
        <button onClick={onBack} className="px-5 py-3.5 rounded-xl text-sm font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500" style={{ background: hc ? "#374151" : "#F1F5F9", color: hc ? "#D1D5DB" : "#475569", border: `1px solid ${hc ? "#4B5563" : "#E2E8F0"}` }}>
          New Scan
        </button>
      </div>
    </div>
  );
}

// ─── Suspicious Screen ─────────────────────────────────────────────────────────
function SuspiciousScreen({
  onBack, filename, hc, onToast,
}: {
  onBack: () => void;
  filename: string;
  hc: boolean;
  onToast: (msg: string, type: "success" | "error" | "info") => void;
}) {
  const [reported, setReported] = useState(false);
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const borderColor = hc ? "#374151" : "#E2E8F0";

  const handleReport = () => {
    if (reported) return;
    setReported(true);
    onToast("Reported to IT Security — ticket #PS-12346 created.", "success");
  };

  return (
    <div className="max-w-3xl mx-auto px-8 py-10">
      <button onClick={onBack} className="flex items-center gap-1.5 text-sm mb-6 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-md px-1" style={{ color: textSecondary }}>
        <span aria-hidden>{Icon.chevronLeft}</span> Back to Upload
      </button>

      {/* Banner — amber, question-mark diamond icon */}
      <div className="rounded-2xl px-6 py-5 mb-7 flex items-start gap-4" style={{ background: hc ? "#1a1000" : "#FFFBEB", border: `2px solid ${hc ? "#78350F" : "#FCD34D"}` }} role="alert" aria-label="Suspicious result">
        <div className="flex items-center justify-center rounded-xl flex-shrink-0" style={{ width: 52, height: 52, background: hc ? "#78350F" : "#FEF3C7" }}>
          {/* Distinct caution shape: question-mark in a diamond-ish shield */}
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#D97706" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
          </svg>
        </div>
        <div className="flex-1">
          <div className="flex flex-wrap items-center gap-2.5 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide" style={{ background: "#D97706", color: "white" }}>Suspicious</span>
            <span className="text-xs font-semibold" style={{ color: hc ? "#FCD34D" : "#92400E" }}>4 caution signals found</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight" style={{ color: hc ? "#FCD34D" : "#92400E" }}>This email has some unusual characteristics.</h1>
        </div>
      </div>

      {/* File row */}
      <div className="flex items-center gap-3 mb-7 px-4 py-3 rounded-xl" style={{ background: hc ? "#1F2937" : "#F8FAFC", border: `1px solid ${borderColor}` }}>
        <span aria-hidden style={{ color: textSecondary }}>{Icon.file}</span>
        <span className="text-xs font-medium flex-1 truncate" style={{ fontFamily: "'JetBrains Mono', monospace", color: textPrimary }}>{filename}</span>
        <span className="text-xs flex-shrink-0" style={{ color: textSecondary }}>Scanned just now</span>
      </div>

      {/* ── Section 1: Be cautious ── */}
      <section aria-labelledby="be-cautious" className="mb-7">
        <div className="flex items-center gap-2 mb-3">
          <span className="flex items-center justify-center rounded-full w-6 h-6 text-xs font-bold flex-shrink-0" style={{ background: "#D97706", color: "white" }} aria-hidden>1</span>
          <h2 id="be-cautious" className="text-base font-bold" style={{ color: textPrimary }}>Be cautious before acting</h2>
        </div>
        <div className="rounded-2xl px-5 py-5" style={{ background: hc ? "#1a1000" : "#FFFBEB", border: `1px solid ${hc ? "#78350F" : "#FDE68A"}` }}>
          <ul className="space-y-3">
            {[
              "Do not click any links until you have confirmed this email is genuine.",
              "Contact the sender directly using a phone number or email address you already trust — not the contact details in this email.",
              "If the email is asking you to log in or share information, visit the website by typing the address yourself rather than clicking a link.",
            ].map((step, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="flex items-center justify-center rounded-full flex-shrink-0 mt-0.5" style={{ width: 20, height: 20, background: hc ? "#78350F" : "#FEF3C7" }} aria-hidden>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#D97706" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </span>
                <span className="text-sm leading-relaxed" style={{ color: hc ? "#FCD34D" : "#78350F" }}>{step}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* ── Section 2: Why flagged ── */}
      <section aria-labelledby="why-suspicious" className="mb-7">
        <div className="flex items-center gap-2 mb-3">
          <span className="flex items-center justify-center rounded-full w-6 h-6 text-xs font-bold flex-shrink-0" style={{ background: "#D97706", color: "white" }} aria-hidden>2</span>
          <h2 id="why-suspicious" className="text-base font-bold" style={{ color: textPrimary }}>Why this was flagged</h2>
        </div>
        <p className="text-sm mb-4" style={{ color: textSecondary }}>None of these signals alone confirms a phishing attempt, but together they are worth verifying before you act.</p>
        <div className="flex flex-col gap-2.5">
          {SUSPICIOUS_INDICATORS.map((ind, i) => (
            <ExpandableIndicator key={i} label={ind.label} plain={ind.plain} technical={ind.technical} severity={ind.severity} hc={hc} accentColor="amber" />
          ))}
        </div>
      </section>

      {/* Reported confirmation banner */}
      {reported && (
        <div className="flex items-center gap-3 px-5 py-4 rounded-xl mb-5" style={{ background: hc ? "#052e16" : "#F0FDF4", border: "1.5px solid #BBF7D0" }} role="status" aria-live="polite">
          <span className="flex items-center justify-center rounded-full flex-shrink-0" style={{ width: 28, height: 28, background: "#D1FAE5" }} aria-hidden>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          </span>
          <div>
            <p className="text-sm font-bold" style={{ color: hc ? "#6EE7B7" : "#065F46" }}>Reported to IT Security</p>
            <p className="text-xs" style={{ color: hc ? "#6EE7B7" : "#047857" }}>Ticket <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>#PS-12346</span> has been created. The IT Security team will review this email.</p>
          </div>
        </div>
      )}

      {/* Actions — secondary report button, prominent return */}
      <div className="flex gap-3 flex-wrap">
        <button
          onClick={onBack}
          className="flex-1 flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
          style={{ background: "linear-gradient(135deg,#2563EB 0%,#1D4ED8 100%)", color: "white", boxShadow: "0 4px 12px rgba(37,99,235,0.25)" }}
        >
          <span aria-hidden>{Icon.chevronLeft}</span> Return to Upload
        </button>
        <button
          onClick={handleReport}
          disabled={reported}
          className="flex items-center justify-center gap-2 px-5 py-3.5 rounded-xl text-sm font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500"
          style={{
            background: reported ? (hc ? "#374151" : "#F0FDF4") : (hc ? "#374151" : "white"),
            color: reported ? (hc ? "#9CA3AF" : "#065F46") : (hc ? "#FCD34D" : "#92400E"),
            border: `1.5px solid ${reported ? (hc ? "#4B5563" : "#BBF7D0") : (hc ? "#78350F" : "#FDE68A")}`,
            cursor: reported ? "not-allowed" : "pointer",
          }}
          aria-disabled={reported}
          title="Optional — report if you believe this is a phishing attempt"
        >
          <span aria-hidden style={{ flexShrink: 0 }}>{reported ? <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg> : Icon.phone}</span>
          {reported ? "Reported" : "Report to IT Security"}
        </button>
      </div>
    </div>
  );
}

// ─── Safe / No Threats Detected Screen ────────────────────────────────────────
function SafeScreen({
  onBack, filename, hc,
}: {
  onBack: () => void;
  filename: string;
  hc: boolean;
}) {
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const borderColor = hc ? "#374151" : "#E2E8F0";

  return (
    <div className="max-w-2xl mx-auto px-8 py-10">
      <button onClick={onBack} className="flex items-center gap-1.5 text-sm mb-6 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-md px-1" style={{ color: textSecondary }}>
        <span aria-hidden>{Icon.chevronLeft}</span> Back to Upload
      </button>

      {/* Banner */}
      <div className="rounded-2xl px-6 py-5 mb-7 flex items-start gap-4" style={{ background: hc ? "#052e16" : "#F0FDF4", border: `2px solid ${hc ? "#14532d" : "#86EFAC"}` }} role="status" aria-label="No threats detected">
        <div className="flex items-center justify-center rounded-xl flex-shrink-0" style={{ width: 52, height: 52, background: hc ? "#14532d" : "#D1FAE5" }}>
          <span style={{ color: "#059669" }} aria-hidden>{Icon.shieldCheck}</span>
        </div>
        <div className="flex-1">
          <div className="flex flex-wrap items-center gap-2.5 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide" style={{ background: "#059669", color: "white" }}>No Threats Detected</span>
            <span className="text-xs font-semibold" style={{ color: hc ? "#6EE7B7" : "#065F46" }}>All 8 checks passed</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight" style={{ color: hc ? "#6EE7B7" : "#065F46" }}>This email looks safe.</h1>
        </div>
      </div>

      {/* File row */}
      <div className="flex items-center gap-3 mb-7 px-4 py-3 rounded-xl" style={{ background: hc ? "#1F2937" : "#F8FAFC", border: `1px solid ${borderColor}` }}>
        <span aria-hidden style={{ color: textSecondary }}>{Icon.file}</span>
        <span className="text-xs font-medium flex-1 truncate" style={{ fontFamily: "'JetBrains Mono', monospace", color: textPrimary }}>{filename}</span>
        <span className="text-xs flex-shrink-0" style={{ color: textSecondary }}>Scanned just now</span>
      </div>

      {/* What was checked */}
      <div className="rounded-2xl overflow-hidden mb-6" style={{ border: `1px solid ${hc ? "#14532d" : "#D1FAE5"}` }}>
        {SAFE_CHECKS.map((c, i) => (
          <div key={c.label} className="flex items-center gap-3 px-5 py-3.5" style={{ background: i % 2 === 0 ? (hc ? "#052e16" : "#F0FDF4") : (hc ? "#071f16" : "#F7FFF9"), borderTop: i > 0 ? `1px solid ${hc ? "#14532d" : "#D1FAE5"}` : "none" }}>
            <span className="flex items-center justify-center rounded-full flex-shrink-0" style={{ width: 22, height: 22, background: hc ? "#14532d" : "#D1FAE5" }} aria-hidden>
              <span style={{ color: "#059669" }}>{Icon.check}</span>
            </span>
            <span className="text-sm flex-1" style={{ color: textPrimary }}>{c.label}</span>
            <span className="text-xs font-semibold" style={{ color: hc ? "#6EE7B7" : "#059669" }}>{c.result}</span>
          </div>
        ))}
      </div>

      {/* Stay alert reminder */}
      <div className="rounded-xl px-5 py-4 mb-8 flex items-start gap-3" style={{ background: hc ? "#1F2937" : "#F8FAFC", border: `1px solid ${borderColor}` }}>
        <span className="flex-shrink-0 mt-0.5" style={{ color: "#64748B" }} aria-hidden>{Icon.info}</span>
        <p className="text-sm leading-relaxed" style={{ color: textSecondary }}>
          <strong style={{ color: textPrimary }}>Stay alert.</strong> Even safe emails can contain unexpected requests for sensitive information. If anything feels off about what the email is asking you to do, trust your instincts and contact the sender directly.
        </p>
      </div>

      {/* Single action */}
      <button
        onClick={onBack}
        className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-sm font-bold text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-green-500 focus-visible:ring-offset-2"
        style={{ background: "linear-gradient(135deg,#059669 0%,#047857 100%)", boxShadow: "0 4px 12px rgba(5,150,105,0.3)" }}
      >
        <span aria-hidden>{Icon.chevronLeft}</span> Return to Upload
      </button>
    </div>
  );
}

// ─── Scan History Screen ───────────────────────────────────────────────────────
function HistoryScreen({ hc }: { hc: boolean }) {
  const [filter, setFilter] = useState<"all" | "high-risk" | "safe">("all");
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const cardBg = hc ? "#1F2937" : "white";
  const borderColor = hc ? "#374151" : "#E2E8F0";
  const items = HISTORY_ITEMS.filter((h) => filter === "all" || h.status === filter);

  return (
    <div className="max-w-3xl mx-auto px-8 py-10">
      <div className="mb-8 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight mb-1" style={{ color: textPrimary }}>Scan History</h1>
          <p className="text-sm" style={{ color: textSecondary }}>All previous scans from your account, most recent first.</p>
        </div>
        <div className="flex gap-2">
          {(["all", "high-risk", "safe"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              aria-pressed={filter === f}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 transition-colors duration-150"
              style={{
                background: filter === f ? "#2563EB" : (hc ? "#374151" : "#F1F5F9"),
                color: filter === f ? "white" : textSecondary,
              }}
            >
              {f === "all" ? "All" : f === "high-risk" ? "High Risk" : "Safe"}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-2xl overflow-hidden" style={{ border: `1px solid ${borderColor}` }}>
        <div className="grid px-5 py-3 text-xs font-bold uppercase tracking-wider" style={{ gridTemplateColumns: "1fr auto auto auto", gap: "1rem", background: hc ? "#111827" : "#F8FAFC", color: textSecondary, borderBottom: `1px solid ${borderColor}` }}>
          <span>File</span><span>Result</span><span>Size</span><span>Date</span>
        </div>
        {items.map((item, i) => (
          <div key={item.name} className="grid px-5 py-4 items-center" style={{ gridTemplateColumns: "1fr auto auto auto", gap: "1rem", background: cardBg, borderTop: i > 0 ? `1px solid ${hc ? "#111827" : "#F8FAFC"}` : "none" }}>
            <div className="flex items-center gap-3 min-w-0">
              <span className="flex items-center justify-center rounded-lg flex-shrink-0" style={{ width: 32, height: 32, background: hc ? "#374151" : "#F1F5F9" }} aria-hidden>{Icon.file}</span>
              <div className="min-w-0">
                <p className="text-xs font-semibold truncate" style={{ fontFamily: "'JetBrains Mono', monospace", color: textPrimary }}>{item.name}</p>
                <p className="text-xs" style={{ color: textSecondary }}>{item.user}</p>
              </div>
            </div>
            <StatusBadge status={item.status} />
            <span className="text-xs" style={{ color: textSecondary, fontFamily: "'JetBrains Mono', monospace" }}>{item.size}</span>
            <span className="text-xs whitespace-nowrap" style={{ color: textSecondary }}>{item.date}</span>
          </div>
        ))}
        {items.length === 0 && (
          <div className="px-5 py-12 text-center" style={{ background: cardBg }}>
            <p className="text-sm" style={{ color: textSecondary }}>No scans match this filter.</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Alerts Screen ─────────────────────────────────────────────────────────────
function AlertsScreen({ hc }: { hc: boolean }) {
  const [dismissed, setDismissed] = useState<number[]>([]);
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const visible = ALERT_ITEMS.filter((a) => !dismissed.includes(a.id));

  const severityStyle = (s: string, hc: boolean) => {
    if (s === "critical") return { bg: hc ? "#3B0000" : "#FFF5F5", border: hc ? "#7F1D1D" : "#FECACA", dot: "#DC2626", text: hc ? "#FCA5A5" : "#991B1B", label: "Critical" };
    if (s === "high") return { bg: hc ? "#3B1500" : "#FFFBEB", border: hc ? "#78350F" : "#FDE68A", dot: "#D97706", text: hc ? "#FCD34D" : "#92400E", label: "High" };
    if (s === "medium") return { bg: hc ? "#1e3a5f" : "#EFF6FF", border: hc ? "#1e40af" : "#BFDBFE", dot: "#3B82F6", text: hc ? "#93C5FD" : "#1D4ED8", label: "Medium" };
    return { bg: hc ? "#1F2937" : "#F8FAFC", border: hc ? "#374151" : "#E2E8F0", dot: "#64748B", text: hc ? "#9CA3AF" : "#475569", label: "Info" };
  };

  return (
    <div className="max-w-3xl mx-auto px-8 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight mb-1" style={{ color: textPrimary }}>Alerts</h1>
        <p className="text-sm" style={{ color: textSecondary }}>{visible.filter((a) => !a.read).length} unread alert{visible.filter((a) => !a.read).length !== 1 ? "s" : ""}</p>
      </div>
      <div className="flex flex-col gap-3">
        {visible.map((alert) => {
          const s = severityStyle(alert.severity, hc);
          return (
            <div key={alert.id} className="rounded-2xl px-5 py-4 flex gap-4" style={{ background: s.bg, border: `1px solid ${s.border}`, opacity: alert.read ? 0.75 : 1 }}>
              <span className="w-2 h-2 rounded-full flex-shrink-0 mt-2" style={{ background: s.dot }} aria-hidden />
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-3 mb-1">
                  <p className="text-sm font-bold leading-tight" style={{ color: s.text }}>{alert.title}</p>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-xs" style={{ color: textSecondary }}>{alert.time}</span>
                    <button
                      onClick={() => setDismissed((d) => [...d, alert.id])}
                      aria-label={`Dismiss alert: ${alert.title}`}
                      className="p-1 rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                      style={{ color: textSecondary }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                  </div>
                </div>
                <p className="text-xs leading-relaxed" style={{ color: s.text }}>{alert.detail}</p>
                <div className="flex items-center gap-2 mt-2">
                  <span className="px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide" style={{ background: `${s.dot}22`, color: s.dot }}>{s.label}</span>
                  {!alert.read && <span className="text-xs font-semibold" style={{ color: s.dot }}>New</span>}
                </div>
              </div>
            </div>
          );
        })}
        {visible.length === 0 && (
          <div className="flex flex-col items-center py-16" style={{ color: textSecondary }}>
            <span aria-hidden className="mb-3 opacity-40">{Icon.bell}</span>
            <p className="text-sm font-medium">All alerts dismissed</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Settings Screen ───────────────────────────────────────────────────────────
function SettingsScreen({
  settings, onSettings, hc,
}: {
  settings: AppSettings;
  onSettings: (s: AppSettings) => void;
  hc: boolean;
}) {
  const textPrimary = hc ? "#F9FAFB" : "#111827";
  const textSecondary = hc ? "#9CA3AF" : "#64748B";
  const cardBg = hc ? "#1F2937" : "white";
  const borderColor = hc ? "#374151" : "#E2E8F0";

  const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div className="rounded-2xl overflow-hidden mb-6" style={{ border: `1px solid ${borderColor}`, background: cardBg }}>
      <div className="px-6 py-4" style={{ borderBottom: `1px solid ${borderColor}`, background: hc ? "#111827" : "#F8FAFC" }}>
        <h2 className="text-xs font-bold uppercase tracking-widest" style={{ color: textSecondary }}>{title}</h2>
      </div>
      <div>{children}</div>
    </div>
  );

  const Row = ({ children }: { children: React.ReactNode }) => (
    <div className="px-6 py-5" style={{ borderTop: `1px solid ${borderColor}` }}>{children}</div>
  );

  return (
    <div className="max-w-2xl mx-auto px-8 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight mb-1" style={{ color: textPrimary }}>Settings</h1>
        <p className="text-sm" style={{ color: textSecondary }}>Personalise PhishScan to meet your accessibility and display preferences.</p>
      </div>

      <Section title="Accessibility — Text Size">
        <div className="px-6 py-5">
          <p className="text-sm font-semibold mb-1" style={{ color: textPrimary }}>Text size</p>
          <p className="text-xs mb-4" style={{ color: textSecondary }}>Adjust the base font size across the entire application. Changes apply instantly.</p>
          <div className="flex gap-3">
            {([["standard", "Standard", "14–16px"], ["large", "Large", "17–19px"], ["xl", "Extra Large", "19–22px"]] as [FontSize, string, string][]).map(([val, label, desc]) => (
              <button
                key={val}
                onClick={() => onSettings({ ...settings, fontSize: val })}
                aria-pressed={settings.fontSize === val}
                className="flex-1 flex flex-col items-center py-4 px-3 rounded-xl border-2 transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                style={{
                  border: `2px solid ${settings.fontSize === val ? "#2563EB" : (hc ? "#4B5563" : "#E2E8F0")}`,
                  background: settings.fontSize === val ? (hc ? "rgba(37,99,235,0.15)" : "#EFF6FF") : "transparent",
                }}
              >
                <span className="font-bold mb-1" style={{ fontSize: val === "standard" ? 15 : val === "large" ? 18 : 22, color: settings.fontSize === val ? "#2563EB" : textPrimary }}>Aa</span>
                <span className="text-xs font-semibold" style={{ color: settings.fontSize === val ? "#2563EB" : textPrimary }}>{label}</span>
                <span className="text-xs mt-0.5" style={{ color: textSecondary, fontFamily: "'JetBrains Mono', monospace" }}>{desc}</span>
              </button>
            ))}
          </div>
        </div>
      </Section>

      <Section title="Accessibility — Display">
        <Row>
          <div className="flex items-start justify-between gap-8">
            <div>
              <p className="text-sm font-semibold mb-1" style={{ color: textPrimary }}>High Contrast Mode</p>
              <p className="text-xs leading-relaxed" style={{ color: textSecondary }}>Increases colour contrast throughout the app for improved legibility on low-vision displays. Switches to a dark, high-contrast colour scheme.</p>
            </div>
            <Toggle checked={settings.highContrast} onChange={(v) => onSettings({ ...settings, highContrast: v })} label="High Contrast Mode" />
          </div>
        </Row>
        <Row>
          <div className="flex items-start justify-between gap-8">
            <div>
              <p className="text-sm font-semibold mb-1" style={{ color: textPrimary }}>Reduce Motion</p>
              <p className="text-xs leading-relaxed" style={{ color: textSecondary }}>Disables animations, transitions, and spinning indicators. Recommended for users with vestibular disorders or motion sensitivity.</p>
            </div>
            <Toggle checked={settings.reduceMotion} onChange={(v) => onSettings({ ...settings, reduceMotion: v })} label="Reduce Motion" />
          </div>
        </Row>
      </Section>

      <Section title="Account">
        <Row>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold mb-0.5" style={{ color: textPrimary }}>Sarah Kim</p>
              <p className="text-xs" style={{ color: textSecondary }}>s.kim@acme.com &middot; IT Security Analyst</p>
            </div>
            <button className="px-4 py-2 rounded-lg text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500" style={{ background: hc ? "#374151" : "#F1F5F9", color: textSecondary, border: `1px solid ${borderColor}` }}>
              Edit profile
            </button>
          </div>
        </Row>
        <Row>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold mb-0.5" style={{ color: textPrimary }}>Two-factor authentication</p>
              <p className="text-xs" style={{ color: textSecondary }}>TOTP authenticator app is active. Last used today.</p>
            </div>
            <span className="flex items-center gap-1.5 text-xs font-bold" style={{ color: "#059669" }}>
              <span aria-hidden>{Icon.check}</span> Active
            </span>
          </div>
        </Row>
      </Section>

      <Section title="About">
        <Row>
          <div className="flex items-center justify-between">
            <p className="text-sm" style={{ color: textSecondary }}>PhishScan version</p>
            <span className="text-xs font-semibold" style={{ fontFamily: "'JetBrains Mono', monospace", color: textPrimary }}>3.1.0</span>
          </div>
        </Row>
        <Row>
          <div className="flex items-center justify-between">
            <p className="text-sm" style={{ color: textSecondary }}>Engine definitions</p>
            <span className="text-xs font-semibold" style={{ fontFamily: "'JetBrains Mono', monospace", color: "#059669" }}>Up to date (11 Sep 2026)</span>
          </div>
        </Row>
      </Section>
    </div>
  );
}

// ─── App (root) ───────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView] = useState<View>("login");
  const [activeNav, setActiveNav] = useState("upload");
  const [scanResult, setScanResult] = useState<ScanResult>("high-risk");
  const [scanFilename, setScanFilename] = useState("upload.txt");
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);
  const [settings, setSettings] = useState<AppSettings>({ fontSize: "standard", highContrast: false, reduceMotion: false });

  const { fontSize, highContrast: hc, reduceMotion } = settings;
  const fontSizePx = fontSize === "standard" ? 15 : fontSize === "large" ? 17 : 20;

  useEffect(() => {
    document.documentElement.style.fontSize = `${fontSizePx}px`;
  }, [fontSizePx]);

  const handleNav = (id: string) => {
    setActiveNav(id);
    if (id === "upload") setView("upload");
    else if (id === "history") setView("history");
    else if (id === "alerts") setView("alerts");
    else if (id === "settings") setView("settings");
  };

  const handleScan = (result: ScanResult, filename: string) => {
    setScanResult(result);
    setScanFilename(filename);
    setView("scanning");
  };

  const handleScanDone = () => {
    setView(scanResult);
  };

  const handleLogout = () => {
    setView("login");
    setActiveNav("upload");
  };

  const showToast = useCallback((msg: string, type: "success" | "error" | "info") => {
    setToast({ msg, type });
  }, []);

  const isAuth = !["login", "mfa"].includes(view);

  const crumbMap: Record<View, string> = {
    login: "Sign In", mfa: "Verify Identity", upload: "New Scan",
    scanning: "Scanning…", "high-risk": "Results — High Risk",
    suspicious: "Results — Suspicious", safe: "Results — No Threats",
    history: "Scan History", alerts: "Alerts", settings: "Settings",
  };

  const contentBg = hc ? "#0D1117" : "#F8FAFC";
  const contentText = hc ? "#F9FAFB" : "#0F172A";

  return (
    <div
      style={{
        minHeight: "100vh",
        background: contentBg,
        color: contentText,
        fontFamily: "'Inter', system-ui, sans-serif",
      }}
    >
      {/* Global focus ring */}
      <style>{`
        @keyframes pulse { 0%,100%{box-shadow:0 0 0 0 rgba(37,99,235,0.4)} 50%{box-shadow:0 0 0 12px rgba(37,99,235,0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        .animate-spin { animation: spin 0.7s linear infinite; }
        ${reduceMotion ? "*, *::before, *::after { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }" : ""}
      `}</style>

      {/* Login / MFA — no sidebar */}
      {view === "login" && <LoginScreen onSuccess={() => setView("mfa")} />}
      {view === "mfa" && <MFAScreen onSuccess={() => { setView("upload"); setActiveNav("upload"); }} onBack={() => setView("login")} />}

      {/* Authenticated layout */}
      {isAuth && (
        <div className="flex">
          <Sidebar activeNav={activeNav} onNav={handleNav} onLogout={handleLogout} hc={hc} />
          <main className="flex-1 overflow-y-auto" style={{ marginLeft: 240, minHeight: "100vh", background: contentBg }}>
            <TopBar crumb={crumbMap[view]} hc={hc} />
            {view === "upload" && <UploadScreen onScan={handleScan} hc={hc} reduceMotion={reduceMotion} />}
            {view === "scanning" && <ScanningScreen filename={scanFilename} onDone={handleScanDone} reduceMotion={reduceMotion} hc={hc} />}
            {view === "high-risk" && <HighRiskScreen onBack={() => { setView("upload"); setActiveNav("upload"); }} filename={scanFilename} hc={hc} reduceMotion={reduceMotion} onToast={showToast} />}
            {view === "suspicious" && <SuspiciousScreen onBack={() => { setView("upload"); setActiveNav("upload"); }} filename={scanFilename} hc={hc} onToast={showToast} />}
            {view === "safe" && <SafeScreen onBack={() => { setView("upload"); setActiveNav("upload"); }} filename={scanFilename} hc={hc} />}
            {view === "history" && <HistoryScreen hc={hc} />}
            {view === "alerts" && <AlertsScreen hc={hc} />}
            {view === "settings" && <SettingsScreen settings={settings} onSettings={setSettings} hc={hc} />}
          </main>
        </div>
      )}

      {/* Toast */}
      {toast && <Toast message={toast.msg} type={toast.type} onDismiss={() => setToast(null)} />}
    </div>
  );
}
