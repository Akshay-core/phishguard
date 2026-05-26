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

  // Rule-based override: if any hard indicators fire, floor the level
  const level = applyHardRules(features, probabilityToLevel(probability));

  const indicators = getTriggeredIndicators(features);

  return {
    level,
    probability,
    confidence: Math.round(probability * 100),
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
function applyHardRules(features: URLFeatures, modelLevel: ThreatLevel): ThreatLevel {
  // If the URL has an IP address AND no HTTPS AND a login keyword,
  // it's almost certainly phishing regardless of model confidence.
  if (features.hasIPAddress && !features.hasHTTPS && features.hasLoginKeyword) {
    return "critical";
  }

  // Suspicious TLD + brand keyword = almost certainly spoofing
  if (features.tldSuspicious && features.hasBrandKeyword) {
    const elevated = elevateLevel(modelLevel, 1);
    return elevated;
  }

  return modelLevel;
}

/**
 * Elevate a threat level by N steps.
 * "safe" + 1 = "low", "high" + 1 = "critical"
 */
function elevateLevel(current: ThreatLevel, steps: number): ThreatLevel {
  const order: ThreatLevel[] = ["safe", "low", "medium", "high", "critical"];
  const idx = order.indexOf(current);
  return order[Math.min(idx + steps, order.length - 1)];
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
