/**
 * Local domain intelligence helpers.
 *
 * These checks are intentionally offline and deterministic. They provide
 * ownership context around URL features so trusted subdomains are not treated
 * the same as brand names embedded inside attacker-controlled domains.
 */

export interface DomainContext {
  normalizedURL: string;
  hostname: string;
  tld: string;
  registrableDomain: string;
  subdomain: string;
  isTrustedDomain: boolean;
  matchedBrand: string | null;
  isBrandOwnedDomain: boolean;
  isBrandImpersonation: boolean;
}

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk",
  "com.au", "net.au", "org.au",
  "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in",
  "co.jp", "ne.jp", "or.jp",
  "com.br", "com.mx", "com.tr",
]);

export const TRUSTED_REGISTRABLE_DOMAINS = new Set([
  "google.com",
  "youtube.com",
  "gmail.com",
  "github.com",
  "github.io",
  "gitlab.com",
  "microsoft.com",
  "live.com",
  "office.com",
  "office365.com",
  "outlook.com",
  "windows.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "linkedin.com",
  "paypal.com",
  "netflix.com",
  "dropbox.com",
  "adobe.com",
  "cloudflare.com",
]);

const BRAND_KEYWORDS = [
  "paypal", "apple", "google", "amazon", "microsoft", "facebook",
  "netflix", "instagram", "twitter", "whatsapp", "ebay", "chase",
  "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
  "linkedin", "dropbox", "adobe", "steam", "roblox", "coinbase",
  "github", "gitlab", "icloud", "office365", "cloudflare",
];

const BRAND_OWNED_DOMAINS: Record<string, Set<string>> = {
  google: new Set(["google.com", "gmail.com", "youtube.com"]),
  github: new Set(["github.com", "github.io"]),
  gitlab: new Set(["gitlab.com"]),
  microsoft: new Set(["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "windows.com"]),
  office365: new Set(["office365.com", "office.com", "microsoft.com"]),
  apple: new Set(["apple.com", "icloud.com"]),
  icloud: new Set(["icloud.com", "apple.com"]),
  amazon: new Set(["amazon.com"]),
  facebook: new Set(["facebook.com"]),
  instagram: new Set(["instagram.com"]),
  whatsapp: new Set(["whatsapp.com"]),
  paypal: new Set(["paypal.com"]),
  netflix: new Set(["netflix.com"]),
  linkedin: new Set(["linkedin.com"]),
  dropbox: new Set(["dropbox.com"]),
  adobe: new Set(["adobe.com"]),
  cloudflare: new Set(["cloudflare.com"]),
};

export function normalizeURLInput(rawURL: string): string {
  const trimmed = rawURL.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

export function getRegistrableDomain(hostname: string): {
  registrableDomain: string;
  subdomain: string;
  tld: string;
} {
  const parts = hostname.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (parts.length <= 1) {
    return { registrableDomain: hostname.toLowerCase(), subdomain: "", tld: "" };
  }

  const lastTwo = parts.slice(-2).join(".");
  const suffixSize = MULTI_PART_PUBLIC_SUFFIXES.has(lastTwo) && parts.length >= 3 ? 2 : 1;
  const domainParts = parts.slice(-(suffixSize + 1));
  const registrableDomain = domainParts.join(".");
  const subdomain = parts.slice(0, -(suffixSize + 1)).join(".");
  const tld = parts.slice(-suffixSize).join(".");

  return { registrableDomain, subdomain, tld };
}

export function getDomainContext(rawURL: string): DomainContext | null {
  let parsed: URL;
  const normalizedURL = normalizeURLInput(rawURL);

  try {
    parsed = new URL(normalizedURL);
  } catch {
    return null;
  }

  const hostname = parsed.hostname.toLowerCase();
  const { registrableDomain, subdomain, tld } = getRegistrableDomain(hostname);
  const matchedBrand =
    BRAND_KEYWORDS.find((brand) => hostname.includes(brand) || parsed.pathname.toLowerCase().includes(brand)) ?? null;
  const ownedDomains = matchedBrand ? BRAND_OWNED_DOMAINS[matchedBrand] : undefined;
  const isBrandOwnedDomain = Boolean(matchedBrand && ownedDomains?.has(registrableDomain));
  const isTrustedDomain =
    TRUSTED_REGISTRABLE_DOMAINS.has(registrableDomain) ||
    TRUSTED_REGISTRABLE_DOMAINS.has(hostname);
  const isBrandImpersonation = Boolean(matchedBrand && !isBrandOwnedDomain);

  return {
    normalizedURL,
    hostname,
    tld,
    registrableDomain,
    subdomain,
    isTrustedDomain,
    matchedBrand,
    isBrandOwnedDomain,
    isBrandImpersonation,
  };
}
