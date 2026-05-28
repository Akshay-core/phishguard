import { getRegistrableDomain, normalizeURLInput } from "../lib/domain-intelligence";

/**
 * PhishGuard — URL Parser Utility
 *
 * Safe wrappers around the browser URL API.
 * All functions handle malformed URLs gracefully without throwing.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

export interface ParsedURL {
  href: string;
  protocol: string;
  hostname: string;
  host: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  tld: string;
  registrableDomain: string;   // e.g. "google.com" from "mail.google.com"
  subdomain: string;            // e.g. "mail" from "mail.google.com"
  isValid: boolean;
}

const EMPTY_PARSED: ParsedURL = {
  href: "",
  protocol: "",
  hostname: "",
  host: "",
  port: "",
  pathname: "",
  search: "",
  hash: "",
  tld: "",
  registrableDomain: "",
  subdomain: "",
  isValid: false,
};

/**
 * Parse a URL string into a structured object.
 * Returns an invalid stub instead of throwing on malformed input.
 */
export function parseURL(rawURL: string): ParsedURL {
  let url: URL;
  try {
    url = new URL(normalizeURLInput(rawURL));
  } catch {
    return { ...EMPTY_PARSED, href: rawURL };
  }

  const { registrableDomain, subdomain, tld } = getRegistrableDomain(url.hostname);

  return {
    href: url.href,
    protocol: url.protocol,
    hostname: url.hostname,
    host: url.host,
    port: url.port,
    pathname: url.pathname,
    search: url.search,
    hash: url.hash,
    tld,
    registrableDomain,
    subdomain,
    isValid: true,
  };
}

/**
 * Extract the display domain for UI — removes www. prefix.
 * Example: "www.paypal.com" → "paypal.com"
 */
export function getDisplayDomain(url: string): string {
  const parsed = parseURL(url);
  if (!parsed.isValid) return url.slice(0, 50);
  return parsed.hostname.replace(/^www\./, "");
}

/**
 * Truncate a URL for display without breaking its meaning.
 * Shows protocol + domain + start of path.
 */
export function truncateURL(url: string, maxLen = 52): string {
  if (url.length <= maxLen) return url;
  const parsed = parseURL(url);
  if (!parsed.isValid) return url.slice(0, maxLen) + "…";
  const base = `${parsed.protocol}//${parsed.hostname}`;
  const remaining = maxLen - base.length - 1;
  if (remaining <= 3) return base + "…";
  return base + parsed.pathname.slice(0, remaining) + "…";
}

/**
 * Check whether a URL is HTTP or HTTPS — the only types we scan.
 */
export function isWebURL(url: string): boolean {
  return url.startsWith("http://") || url.startsWith("https://");
}

/**
 * Check if a URL is an internal browser page we should skip.
 */
export function isInternalURL(url: string): boolean {
  const internalPrefixes = [
    "chrome://", "chrome-extension://", "moz-extension://",
    "about:", "edge://", "opera://", "brave://",
  ];
  return internalPrefixes.some((prefix) => url.startsWith(prefix));
}
