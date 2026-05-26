/**
 * PhishGuard — Threat Intelligence Client
 *
 * Optional remote checks against public threat feeds.
 * Only activated when the user enables "Threat Intelligence" in settings.
 *
 * Privacy contract:
 * - Only the hostname (not full URL) is sent
 * - Requests are rate-limited to prevent excessive API calls
 * - Completely disabled by default
 * - User must explicitly opt-in in settings
 *
 * Threat sources:
 * - PhishTank: https://www.phishtank.com/api_info.php
 * - URLHaus: https://urlhaus-api.abuse.ch/
 * - Our optional backend aggregator
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { parseURL } from "../utils/url-parser";

export interface ThreatIntelResult {
  isKnownPhish: boolean;
  source: string | null;
  reportedAt: string | null;
  confidence: number;    // 0–1
}

const NEGATIVE_RESULT: ThreatIntelResult = {
  isKnownPhish: false,
  source: null,
  reportedAt: null,
  confidence: 0,
};

// Simple in-memory cache to avoid hammering APIs on every navigation
const cache = new Map<string, { result: ThreatIntelResult; ts: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// Rate limiting: max 1 request per 2 seconds per hostname
const lastRequestTime = new Map<string, number>();
const RATE_LIMIT_MS = 2000;

/**
 * Check a URL against remote threat intelligence feeds.
 * Returns negative result immediately if:
 * - Threat intel is disabled in settings
 * - URL is in cache
 * - Rate limit is active
 */
export async function checkThreatIntel(
  url: string,
  backendURL?: string
): Promise<ThreatIntelResult> {
  const parsed = parseURL(url);
  if (!parsed.isValid) return NEGATIVE_RESULT;

  const hostname = parsed.hostname;

  // Cache check
  const cached = cache.get(hostname);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.result;
  }

  // Rate limit check
  const lastReq = lastRequestTime.get(hostname) ?? 0;
  if (Date.now() - lastReq < RATE_LIMIT_MS) {
    return NEGATIVE_RESULT;
  }
  lastRequestTime.set(hostname, Date.now());

  try {
    // If we have our own backend, use it (aggregates multiple sources)
    if (backendURL) {
      const result = await checkOurBackend(hostname, backendURL);
      cache.set(hostname, { result, ts: Date.now() });
      return result;
    }

    // Fallback: check URLHaus directly (no API key required)
    const result = await checkURLHaus(hostname);
    cache.set(hostname, { result, ts: Date.now() });
    return result;
  } catch (err) {
    console.warn("[PhishGuard] Threat intel check failed:", err);
    return NEGATIVE_RESULT;
  }
}

/**
 * Check against URLHaus API (free, no auth required).
 * https://urlhaus-api.abuse.ch/
 */
async function checkURLHaus(hostname: string): Promise<ThreatIntelResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `host=${encodeURIComponent(hostname)}`,
      signal: controller.signal,
    });

    if (!response.ok) return NEGATIVE_RESULT;

    const data = await response.json() as {
      query_status: string;
      urls?: Array<{ date_added: string }>;
    };

    if (data.query_status === "is_host" && data.urls && data.urls.length > 0) {
      return {
        isKnownPhish: true,
        source: "URLHaus",
        reportedAt: data.urls[0]?.date_added ?? null,
        confidence: 0.95,
      };
    }

    return NEGATIVE_RESULT;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Check against our optional PhishGuard backend.
 * Backend aggregates PhishTank + URLHaus + OpenPhish.
 */
async function checkOurBackend(
  hostname: string,
  backendURL: string
): Promise<ThreatIntelResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch(
      `${backendURL}/api/v1/threat/check?hostname=${encodeURIComponent(hostname)}`,
      { signal: controller.signal }
    );

    if (!response.ok) return NEGATIVE_RESULT;

    return await response.json() as ThreatIntelResult;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Clear the threat intel cache (useful after settings change).
 */
export function clearThreatIntelCache(): void {
  cache.clear();
  lastRequestTime.clear();
}
