/**
 * PhishGuard — Shared TypeScript type definitions
 * Author: Akshay | https://akshay.fruvvi.com
 */

// ─── Threat Classification ────────────────────────────────────────────────────

export type ThreatLevel = "safe" | "low" | "medium" | "high" | "critical";

export interface ThreatScore {
  level: ThreatLevel;
  probability: number;       // 0–1 raw model output
  confidence: number;        // 0–100 display percentage
  indicators: ThreatIndicator[];
  scanDurationMs: number;
}

export interface ThreatIndicator {
  id: string;
  label: string;
  description: string;
  severity: "info" | "warning" | "danger";
  triggered: boolean;
}

// ─── URL Feature Vector ───────────────────────────────────────────────────────
// Must mirror ml/training/features.py exactly — order matters for ONNX inference

export interface URLFeatures {
  urlLength: number;           // Raw character count
  domainLength: number;
  subdomainCount: number;      // Number of dots in hostname
  hasIPAddress: boolean;       // IP in host (e.g. http://192.168.1.1/login)
  hasHTTPS: boolean;
  specialCharCount: number;    // @, -, _, ~ etc.
  digitRatio: number;          // digits / totalChars
  entropyScore: number;        // Shannon entropy of full URL
  pathDepth: number;           // Number of "/" segments
  hasLoginKeyword: boolean;    // login, signin, account, verify, secure…
  hasBrandKeyword: boolean;    // paypal, apple, google, amazon, microsoft…
  tldSuspicious: boolean;      // .xyz, .tk, .pw, .ml, .gq etc.
  hasRedirectParam: boolean;   // ?redirect=, ?url=, ?next=
  domainAge: number;           // -1 if unknown, 0 = very new
  hasPortInURL: boolean;       // Non-standard port usage
}

// Convert to flat Float32Array for ONNX inference — order must match training
export function featuresToArray(f: URLFeatures): Float32Array {
  return new Float32Array([
    f.urlLength / 300,           // Normalize to ~0-1
    f.domainLength / 100,
    f.subdomainCount / 5,
    f.hasIPAddress ? 1 : 0,
    f.hasHTTPS ? 0 : 1,          // Inverted: no HTTPS = suspicious
    f.specialCharCount / 20,
    f.digitRatio,
    f.entropyScore / 6,
    f.pathDepth / 10,
    f.hasLoginKeyword ? 1 : 0,
    f.hasBrandKeyword ? 1 : 0,
    f.tldSuspicious ? 1 : 0,
    f.hasRedirectParam ? 1 : 0,
    f.domainAge === -1 ? 0.5 : Math.max(0, Math.min(1, f.domainAge / 365)),
    f.hasPortInURL ? 1 : 0,
  ]);
}

// ─── Scan State ───────────────────────────────────────────────────────────────

export type ScanStatus = "idle" | "scanning" | "done" | "error";

export interface ScanState {
  status: ScanStatus;
  url: string | null;
  result: ThreatScore | null;
  error: string | null;
  timestamp: number | null;
}

// ─── Chrome Message Passing ───────────────────────────────────────────────────

export type MessageType =
  | "SCAN_URL"
  | "SCAN_RESULT"
  | "GET_CURRENT_SCAN"
  | "CLEAR_SCAN";

export interface ChromeMessage<T = unknown> {
  type: MessageType;
  payload?: T;
}

export interface ScanURLPayload {
  url: string;
}

export interface ScanResultPayload {
  url: string;
  result: ThreatScore;
}

// ─── Settings ─────────────────────────────────────────────────────────────────

export interface PhishGuardSettings {
  enableAutoScan: boolean;
  enableThreatIntel: boolean;   // Whether to check PhishTank/URLHaus remotely
  enableAnalytics: boolean;     // Opt-in aggregated analytics
  showSafeNotifications: boolean;
  threatThreshold: ThreatLevel; // Minimum level to show popup
}

export const DEFAULT_SETTINGS: PhishGuardSettings = {
  enableAutoScan: true,
  enableThreatIntel: false,     // Off by default — privacy-first
  enableAnalytics: false,
  showSafeNotifications: false,
  threatThreshold: "medium",
};
