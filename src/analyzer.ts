// Real, rule-based phishing analysis. Replaces the old Math.random() result.
// Scores actual file/email/pasted content against known phishing patterns
// instead of picking a result at random.

export type RiskTier = "high-risk" | "suspicious" | "safe";

export type Indicator = {
  label: string;
  severity: "critical" | "moderate";
  explanation: string;
  technical: string;
};

export type AnalysisResult = {
  tier: RiskTier;
  score: number;
  indicators: Indicator[];
  checkedContent: boolean; // false if we only had a filename to go on
};

const URGENCY_PHRASES = [
  "verify your account", "act now", "immediately", "within 24 hours",
  "suspended", "your account has been limited", "confirm your identity",
  "unusual activity", "click here", "final notice", "avoid suspension",
  "urgent action required", "your password will expire",
];

const CREDENTIAL_REQUEST_PHRASES = [
  "enter your password", "confirm your password", "update your payment method",
  "enter your ssn", "social security number", "verify your billing",
  "login to your account", "re-enter your credentials", "confirm your card number",
];

const SUSPICIOUS_LINK_PATTERNS = [
  /bit\.ly/i, /tinyurl/i, /goo\.gl/i, /\d+\.\d+\.\d+\.\d+/, // raw IP addresses
  /-secure\.(net|com|info)/i, /paypa1/i, /amaz0n/i, /micros0ft/i,
];

const KNOWN_BRANDS = ["paypal", "amazon", "microsoft", "apple", "google", "bank of america", "wells fargo", "chase", "netflix", "docusign"];

function extractLinks(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s"'<>]+/gi);
  return matches ?? [];
}

function extractSenderDomain(text: string): string | null {
  const fromMatch = text.match(/from:.*?[<@]([a-z0-9.-]+\.[a-z]{2,})/i);
  return fromMatch ? fromMatch[1].toLowerCase() : null;
}

export function analyzeContent(rawText: string, filename: string): AnalysisResult {
  const text = rawText.toLowerCase();
  const indicators: Indicator[] = [];
  let score = 0;

  // 1. Urgency / pressure language
  const urgencyHits = URGENCY_PHRASES.filter((p) => text.includes(p));
  if (urgencyHits.length > 0) {
    score += urgencyHits.length >= 2 ? 30 : 15;
    indicators.push({
      label: "Uses urgency to pressure you",
      severity: urgencyHits.length >= 2 ? "critical" : "moderate",
      explanation: "This message uses language designed to make you act quickly without thinking it through.",
      technical: `Matched phrases: ${urgencyHits.join(", ")}`,
    });
  }

  // 2. Requests for credentials / sensitive info
  const credHits = CREDENTIAL_REQUEST_PHRASES.filter((p) => text.includes(p));
  if (credHits.length > 0) {
    score += 30;
    indicators.push({
      label: "Asks for login details or sensitive information",
      severity: "critical",
      explanation: "Legitimate companies rarely ask you to re-enter passwords or account numbers through email links.",
      technical: `Matched phrases: ${credHits.join(", ")}`,
    });
  }

  // 3. Suspicious links
  const links = extractLinks(rawText);
  const suspiciousLinks = links.filter((l) => SUSPICIOUS_LINK_PATTERNS.some((p) => p.test(l)));
  if (suspiciousLinks.length > 0) {
    score += 35;
    indicators.push({
      label: "Contains a suspicious link",
      severity: "critical",
      explanation: "One or more links in this message point to an address that mimics a real company or hides its true destination.",
      technical: `Flagged URL(s): ${suspiciousLinks.join(", ")}`,
    });
  } else if (links.length > 0) {
    score += 5;
  }

  // 4. Sender domain vs. mentioned brand mismatch
  const senderDomain = extractSenderDomain(rawText);
  const mentionedBrand = KNOWN_BRANDS.find((b) => text.includes(b));
  if (senderDomain && mentionedBrand) {
    const brandSlug = mentionedBrand.replace(/\s+/g, "");
    if (!senderDomain.includes(brandSlug.slice(0, 5))) {
      score += 30;
      indicators.push({
        label: "Sender domain doesn't match the company mentioned",
        severity: "critical",
        explanation: `This message claims to be from ${mentionedBrand}, but the sending address doesn't match ${mentionedBrand}'s real domain.`,
        technical: `Sender domain: ${senderDomain} — mentioned brand: ${mentionedBrand}`,
      });
    }
  }

  // 5. Suspicious attachment extension in filename
  if (/\.(exe|scr|bat|js|vbs|jar)$/i.test(filename)) {
    score += 40;
    indicators.push({
      label: "Potentially dangerous attachment type",
      severity: "critical",
      explanation: "This file type can run code on your computer and is commonly used to deliver malware.",
      technical: `Filename: ${filename}`,
    });
  }

  const tier: RiskTier = score >= 50 ? "high-risk" : score >= 20 ? "suspicious" : "safe";

  return {
    tier,
    score,
    indicators,
    checkedContent: rawText.trim().length > 0,
  };
}
