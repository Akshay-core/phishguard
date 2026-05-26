/**
 * PhishGuard — URL Feature Extractor
 *
 * Converts a raw URL string into a 15-element feature vector.
 * CRITICAL: This must mirror ml/training/features.py exactly.
 * Any drift between JS and Python features will silently degrade model accuracy.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { URLFeatures } from "../types";

// Brand names commonly spoofed in phishing attacks
const BRAND_KEYWORDS = [
  "paypal", "apple", "google", "amazon", "microsoft", "facebook",
  "netflix", "instagram", "twitter", "whatsapp", "ebay", "chase",
  "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
  "linkedin", "dropbox", "adobe", "steam", "roblox", "coinbase",
];

// High-risk/free TLDs frequently used in phishing
const SUSPICIOUS_TLDS = new Set([
  "xyz", "tk", "pw", "ml", "gq", "cf", "ga", "top", "work",
  "click", "loan", "download", "racing", "date", "win", "review",
  "science", "party", "stream", "gdn", "bid", "trade", "link",
]);

// Keywords suggesting credential harvesting
const LOGIN_KEYWORDS = [
  "login", "signin", "sign-in", "account", "verify", "secure",
  "update", "confirm", "banking", "wallet", "password", "credential",
];

/**
 * Shannon entropy — measures randomness/unpredictability of a string.
 * High entropy (>4.5) suggests algorithmically-generated domains (DGA).
 */
export function computeEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Extract all 15 features from a URL string.
 * Returns a strongly-typed URLFeatures object.
 */
export function extractFeatures(rawURL: string): URLFeatures {
  let parsed: URL;
  try {
    parsed = new URL(rawURL);
  } catch {
    // Unparseable URL — treat as maximally suspicious
    return getDefaultSuspiciousFeatures(rawURL);
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullURL = rawURL.toLowerCase();
  const tld = hostname.split(".").pop() ?? "";

  // Count special characters that don't belong in legitimate URLs
  const specialCharCount = (rawURL.match(/[@\-_~%=]/g) ?? []).length;

  // Digit ratio — phishing domains often have numbers (paypa1, g00gle)
  const digits = (rawURL.match(/\d/g) ?? []).length;
  const digitRatio = rawURL.length > 0 ? digits / rawURL.length : 0;

  // Subdomain depth — legitimate sites rarely have >2 levels
  const subdomainCount = hostname.split(".").length - 2;

  // Path depth — deeply nested paths are suspicious (/account/login/verify/update)
  const pathDepth = parsed.pathname
    .split("/")
    .filter((s) => s.length > 0).length;

  // Redirect parameters — common in open-redirect phishing chains
  const hasRedirectParam =
    parsed.searchParams.has("redirect") ||
    parsed.searchParams.has("url") ||
    parsed.searchParams.has("next") ||
    parsed.searchParams.has("return") ||
    parsed.searchParams.has("returnUrl");

  // IP-based URL detection (bypasses domain filtering)
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hasIPAddress = ipv4Pattern.test(hostname);

  // Brand keyword detection — check both domain and path
  const hasBrandKeyword = BRAND_KEYWORDS.some(
    (brand) => hostname.includes(brand) || parsed.pathname.toLowerCase().includes(brand)
  );

  const hasLoginKeyword = LOGIN_KEYWORDS.some(
    (kw) => fullURL.includes(kw)
  );

  return {
    urlLength: rawURL.length,
    domainLength: hostname.length,
    subdomainCount: Math.max(0, subdomainCount),
    hasIPAddress,
    hasHTTPS: parsed.protocol === "https:",
    specialCharCount,
    digitRatio,
    entropyScore: computeEntropy(rawURL),
    pathDepth,
    hasLoginKeyword,
    hasBrandKeyword,
    tldSuspicious: SUSPICIOUS_TLDS.has(tld),
    hasRedirectParam,
    domainAge: -1,  // Runtime: -1 (unknown). Backend can populate this.
    hasPortInURL: parsed.port !== "" && parsed.port !== "80" && parsed.port !== "443",
  };
}

/**
 * Used when URL parsing fails entirely — return maximally suspicious defaults.
 * A URL that can't be parsed at all is almost certainly malicious.
 */
function getDefaultSuspiciousFeatures(rawURL: string): URLFeatures {
  return {
    urlLength: rawURL.length,
    domainLength: rawURL.length,
    subdomainCount: 5,
    hasIPAddress: false,
    hasHTTPS: false,
    specialCharCount: 10,
    digitRatio: 0.3,
    entropyScore: 5.0,
    pathDepth: 5,
    hasLoginKeyword: true,
    hasBrandKeyword: true,
    tldSuspicious: true,
    hasRedirectParam: true,
    domainAge: 0,
    hasPortInURL: true,
  };
}

/**
 * Human-readable explanation of which indicators fired.
 * Used to generate the "why is this suspicious" explanation in the popup.
 */
export function getTriggeredIndicators(features: URLFeatures) {
  const indicators = [];

  if (features.hasIPAddress) {
    indicators.push({
      id: "ip_url",
      label: "IP address used instead of domain",
      description: "Legitimate sites use domain names. IP-based URLs are often used to evade detection.",
      severity: "danger" as const,
      triggered: true,
    });
  }

  if (!features.hasHTTPS) {
    indicators.push({
      id: "no_https",
      label: "No HTTPS encryption",
      description: "The site uses unencrypted HTTP. Any data you submit can be intercepted.",
      severity: "warning" as const,
      triggered: true,
    });
  }

  if (features.tldSuspicious) {
    indicators.push({
      id: "suspicious_tld",
      label: "Suspicious top-level domain",
      description: "This TLD is commonly used in phishing campaigns due to low registration cost.",
      severity: "danger" as const,
      triggered: true,
    });
  }

  if (features.hasBrandKeyword && features.subdomainCount > 1) {
    indicators.push({
      id: "brand_spoofing",
      label: "Brand name in subdomain",
      description: "Using a well-known brand in a subdomain (e.g. paypal.evil.com) is a classic phishing tactic.",
      severity: "danger" as const,
      triggered: true,
    });
  }

  if (features.entropyScore > 4.5) {
    indicators.push({
      id: "high_entropy",
      label: "High URL randomness (possible DGA)",
      description: "Domain Generation Algorithms create random-looking domains to evade blocklists.",
      severity: "warning" as const,
      triggered: true,
    });
  }

  if (features.hasRedirectParam) {
    indicators.push({
      id: "redirect_param",
      label: "Suspicious redirect parameter",
      description: "Open redirects allow attackers to use trusted domains to forward to malicious ones.",
      severity: "warning" as const,
      triggered: true,
    });
  }

  if (features.subdomainCount > 3) {
    indicators.push({
      id: "excessive_subdomains",
      label: "Excessive subdomain depth",
      description: "Deeply nested subdomains obscure the real domain from casual inspection.",
      severity: "warning" as const,
      triggered: true,
    });
  }

  if (features.hasPortInURL) {
    indicators.push({
      id: "unusual_port",
      label: "Unusual port in URL",
      description: "Non-standard ports can be used to route around network filters.",
      severity: "info" as const,
      triggered: true,
    });
  }

  return indicators;
}
