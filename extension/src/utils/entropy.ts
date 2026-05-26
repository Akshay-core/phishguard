/**
 * PhishGuard — Entropy Utilities
 *
 * Shannon entropy measures the unpredictability/randomness of a string.
 * In phishing detection, it's used to identify:
 *  - DGA (Domain Generation Algorithm) domains: "xk3j9qz.com"
 *  - Algorithmically-generated subdomains
 *  - Base64-encoded data in URLs
 *
 * Typical values:
 *  - Low entropy (< 3.0):  "google", "paypal" — human-readable, memorable
 *  - Medium entropy (3–4): "amazon-login", "secure-bank"
 *  - High entropy (> 4.5): "xk3j9qzm2p", "aHR0cHM6Ly" — likely DGA or encoded
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

/**
 * Compute Shannon entropy of a string.
 * H(X) = -Σ p(x) * log₂(p(x))
 *
 * @returns Entropy value in bits (0 for empty/uniform strings, max ~log2(charsetSize))
 */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = input.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Normalized entropy: entropy / log2(unique chars).
 * Returns 0–1 regardless of character set size.
 * Useful for comparing strings of different character sets.
 */
export function normalizedEntropy(input: string): number {
  if (input.length === 0) return 0;

  const uniqueChars = new Set(input).size;
  if (uniqueChars <= 1) return 0;

  return shannonEntropy(input) / Math.log2(uniqueChars);
}

/**
 * Compute entropy of just the domain part of a URL.
 * More targeted than full-URL entropy.
 */
export function domainEntropy(hostname: string): number {
  // Remove TLD and dots before computing — focus on the meaningful part
  const parts = hostname.split(".");
  const domain = parts.slice(0, -1).join(""); // Drop TLD
  return shannonEntropy(domain);
}

/**
 * Classify entropy level for display/debugging.
 */
export function classifyEntropy(entropy: number): "low" | "medium" | "high" {
  if (entropy < 3.0) return "low";
  if (entropy < 4.5) return "medium";
  return "high";
}
