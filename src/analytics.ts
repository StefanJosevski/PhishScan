import posthog from "posthog-js";

const KEY = import.meta.env.VITE_POSTHOG_KEY as string | undefined;
const HOST = (import.meta.env.VITE_POSTHOG_HOST as string | undefined) ?? "https://us.i.posthog.com";

let ready = false;

export function initAnalytics() {
  if (!KEY || ready) return;
  posthog.init(KEY, { api_host: HOST });
  ready = true;
}

// Custom events for the scan flow. They send only result summaries, never the email text.
export function trackScanStarted(input_type: "file" | "text") {
  if (!ready) return;
  posthog.capture("scan_started", { input_type });
}

export function trackScanCompleted(props: {
  risk_tier: string;
  score: number;
  indicator_count: number;
  input_type: "file" | "text";
}) {
  if (!ready) return;
  posthog.capture("scan_completed", props);
}