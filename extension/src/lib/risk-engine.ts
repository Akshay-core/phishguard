/**
 * PhishGuard — Risk Score Engine
 *
 * Converts raw ONNX probability + feature indicators into a
 * structured ThreatScore with human-readable explanation.
 *
 * Why separate from the model runner?
 * - The model gives probability. Risk assessment is a business logic concern.
 * - Thresholds can be tuned without retraining the model.
 * - Allows blending model output with rule-based indicators.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { ThreatLevel, ThreatScore } from "../types";
import { URLFeatures } from "../types";
import { extractFeatures, getTriggeredIndicators } from "./feature-extractor";
import { getDomainContext } from "./domain-intelligence";
import { runInference, initModel } from "./onnx-runner";

// Thresholds tuned for precision — minimize false positives on legitimate sites
const THREAT_THRESHOLDS: Record<ThreatLevel, number> = {
  safe:     0.0,
  low:      0.25,
  medium:   0.50,
  high:     0.70,
  critical: 0.88,
};

function probabilityToLevel(prob: number): ThreatLevel {
  if (prob >= THREAT_THRESHOLDS.critical) return "critical";
  if (prob >= THREAT_THRESHOLDS.high)     return "high";
  if (prob >= THREAT_THRESHOLDS.medium)   return "medium";
  if (prob >= THREAT_THRESHOLDS.low)      return "low";
  return "safe";
}

/**
 * Full scan pipeline:
 * URL → features → ONNX inference → threat level + indicators
 */
export async function scanURL(url: string): Promise<ThreatScore> {
  await initModel();

  const features: URLFeatures = extractFeatures(url);
  const { probability, durationMs } = await runInference(features);
  const domainContext = getDomainContext(url);

  // Rule-based override: obvious malicious combinations raise risk, trusted
  // ownership context caps weak ML false positives.
  const level = applyContextualRules(features, probabilityToLevel(probability), domainContext);
  const finalProbability = calibrateProbabilityForLevel(probability, level);

  const indicators = getTriggeredIndicators(features);

  return {
    level,
    probability: finalProbability,
    confidence: Math.round(finalProbability * 100),
    indicators,
    scanDurationMs: Math.round(durationMs),
  };
}

/**
 * Hard rules that override the ML model in obvious cases.
 * These are deterministic — not probabilistic.
 *
 * Tradeoff: Slightly increases false positive rate for edge cases,
 * but dramatically improves detection of known-bad patterns.
 */
function applyContextualRules(
  features: URLFeatures,
  modelLevel: ThreatLevel,
  domainContext: ReturnType<typeof getDomainContext>
): ThreatLevel {
  // If the URL has an IP address AND no HTTPS AND a login keyword,
  // it's almost certainly phishing regardless of model confidence.
  if (features.hasIPAddress && !features.hasHTTPS && features.hasLoginKeyword) {
    return "critical";
  }

  // Suspicious TLD + brand impersonation = almost certainly spoofing.
  if (features.tldSuspicious && domainContext?.isBrandImpersonation) {
    return features.hasLoginKeyword ? "critical" : maxLevel(modelLevel, "high");
  }

  if (features.tldSuspicious && features.hasLoginKeyword) {
    return maxLevel(modelLevel, "high");
  }

  if (domainContext?.isTrustedDomain) {
    return capTrustedDomainLevel(features, modelLevel);
  }

  return modelLevel;
}

function capTrustedDomainLevel(features: URLFeatures, modelLevel: ThreatLevel): ThreatLevel {
  const dangerousSignals = [
    features.hasIPAddress,
    !features.hasHTTPS,
    features.tldSuspicious,
    features.hasRedirectParam,
    features.hasPortInURL,
  ].filter(Boolean).length;

  if (dangerousSignals === 0 && features.subdomainCount <= 3) {
    return minLevel(modelLevel, features.hasLoginKeyword ? "low" : "safe");
  }

  if (dangerousSignals <= 1) {
    return minLevel(modelLevel, "medium");
  }

  return modelLevel;
}

function minLevel(current: ThreatLevel, ceiling: ThreatLevel): ThreatLevel {
  const order: ThreatLevel[] = ["safe", "low", "medium", "high", "critical"];
  return order[Math.min(order.indexOf(current), order.indexOf(ceiling))];
}

function maxLevel(current: ThreatLevel, floor: ThreatLevel): ThreatLevel {
  const order: ThreatLevel[] = ["safe", "low", "medium", "high", "critical"];
  return order[Math.max(order.indexOf(current), order.indexOf(floor))];
}

function calibrateProbabilityForLevel(probability: number, level: ThreatLevel): number {
  const ceilings: Record<ThreatLevel, number> = {
    safe: 0.12,
    low: 0.35,
    medium: 0.65,
    high: 0.85,
    critical: 1.0,
  };

  return Math.min(probability, ceilings[level]);
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────

export const THREAT_DISPLAY: Record<ThreatLevel, {
  label: string;
  color: string;        // Tailwind color token
  bgColor: string;
  emoji: string;
  description: string;
}> = {
  safe: {
    label: "Safe",
    color: "text-green-600 dark:text-green-400",
    bgColor: "bg-green-50 dark:bg-green-950",
    emoji: "✓",
    description: "No phishing indicators detected.",
  },
  low: {
    label: "Low Risk",
    color: "text-yellow-600 dark:text-yellow-400",
    bgColor: "bg-yellow-50 dark:bg-yellow-950",
    emoji: "⚠",
    description: "Minor suspicious signals. Proceed with caution.",
  },
  medium: {
    label: "Suspicious",
    color: "text-orange-600 dark:text-orange-400",
    bgColor: "bg-orange-50 dark:bg-orange-950",
    emoji: "⚠",
    description: "Multiple phishing indicators detected.",
  },
  high: {
    label: "High Risk",
    color: "text-red-600 dark:text-red-400",
    bgColor: "bg-red-50 dark:bg-red-950",
    emoji: "✕",
    description: "Strong phishing signals. Do not enter credentials.",
  },
  critical: {
    label: "Phishing Detected",
    color: "text-red-700 dark:text-red-300",
    bgColor: "bg-red-100 dark:bg-red-900",
    emoji: "✕",
    description: "This URL matches known phishing patterns. Do not proceed.",
  },
};
