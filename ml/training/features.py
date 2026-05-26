"""
PhishGuard — Shared Feature Engineering Module
================================================
Single source of truth for all URL features.
Imported by train.py, evaluate.py, and any future scripts.

CRITICAL CONTRACT:
  This module must produce identical numerical output to
  extension/src/lib/feature-extractor.ts for the same input URL.
  Any divergence silently degrades detection accuracy.
  Test parity with: python scripts/test_feature_parity.py

Author: Akshay | https://akshay.fruvvi.com
"""

from __future__ import annotations

import re
import math
from collections import Counter
from dataclasses import dataclass, fields as dataclass_fields, astuple
from typing import List
from urllib.parse import urlparse, parse_qs


# ─── Domain knowledge constants ───────────────────────────────────────────────

BRAND_KEYWORDS: frozenset = frozenset({
    "paypal", "apple", "google", "amazon", "microsoft", "facebook",
    "netflix", "instagram", "twitter", "whatsapp", "ebay", "chase",
    "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
    "linkedin", "dropbox", "adobe", "steam", "roblox", "coinbase",
})

SUSPICIOUS_TLDS: frozenset = frozenset({
    "xyz", "tk", "pw", "ml", "gq", "cf", "ga", "top", "work",
    "click", "loan", "download", "racing", "date", "win", "review",
    "science", "party", "stream", "gdn", "bid", "trade", "link",
})

LOGIN_KEYWORDS = (
    "login", "signin", "sign-in", "account", "verify", "secure",
    "update", "confirm", "banking", "wallet", "password", "credential",
)

REDIRECT_PARAMS: frozenset = frozenset({
    "redirect", "url", "next", "return", "returnurl",
})

_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_SPECIAL_CHARS_PATTERN = re.compile(r"[@\-_~%=]")


# ─── Feature dataclass ────────────────────────────────────────────────────────

@dataclass
class URLFeatureVector:
    """
    15-element feature vector. Field order MUST match TypeScript featuresToArray().
    Adding or reordering fields requires re-training AND updating TypeScript.
    """
    url_length:      float   # 1.  Normalized URL length
    domain_length:   float   # 2.  Normalized domain length
    subdomain_count: float   # 3.  Normalized subdomain depth
    has_ip:          float   # 4.  IP-based hostname (0/1)
    no_https:        float   # 5.  Missing HTTPS (0/1, inverted)
    special_chars:   float   # 6.  Normalized special char count
    digit_ratio:     float   # 7.  Fraction of digits in URL
    entropy:         float   # 8.  Normalized Shannon entropy
    path_depth:      float   # 9.  Normalized path depth
    has_login_kw:    float   # 10. Login keyword present (0/1)
    has_brand_kw:    float   # 11. Brand keyword present (0/1)
    suspicious_tld:  float   # 12. Suspicious TLD (0/1)
    has_redirect:    float   # 13. Redirect parameter (0/1)
    domain_age:      float   # 14. Normalized domain age (0.5 = unknown)
    has_port:        float   # 15. Non-standard port (0/1)

    def to_list(self) -> List[float]:
        return list(astuple(self))


# ─── Module-level constants (fixed) ──────────────────────────────────────────

# Extract field names from the dataclass properly
FEATURE_NAMES: List[str] = [f.name for f in dataclass_fields(URLFeatureVector)]
NUM_FEATURES: int = len(FEATURE_NAMES)  # 15


# ─── Core functions ───────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string in bits."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract(url: str, domain_age_days: int = -1) -> URLFeatureVector:
    """
    Extract the 15-element feature vector from a URL string.

    Args:
        url: Raw URL string
        domain_age_days: Age in days (-1 = unknown)

    Returns:
        URLFeatureVector with all 15 features normalized to [0, 1]
    """
    # Ensure URL has a scheme for urlparse to work correctly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return _suspicious_defaults(url)

    hostname  = (parsed.netloc or "").lower().split(":")[0]
    url_lower = url.lower()
    tld       = hostname.split(".")[-1] if "." in hostname else ""

    # 1. URL length
    url_length = min(len(url) / 300.0, 1.0)

    # 2. Domain length
    domain_length = min(len(hostname) / 100.0, 1.0)

    # 3. Subdomain count
    parts = hostname.split(".")
    raw_subdomain = max(0, len(parts) - 2)
    subdomain_count = min(raw_subdomain / 5.0, 1.0)

    # 4. IP address in hostname
    has_ip = 1.0 if _IP_PATTERN.match(hostname) else 0.0

    # 5. Missing HTTPS (INVERTED)
    no_https = 0.0 if parsed.scheme == "https" else 1.0

    # 6. Special characters
    special_count = len(_SPECIAL_CHARS_PATTERN.findall(url))
    special_chars = min(special_count / 20.0, 1.0)

    # 7. Digit ratio
    digit_count = sum(1 for c in url if c.isdigit())
    digit_ratio = digit_count / len(url) if url else 0.0

    # 8. Shannon entropy
    entropy = min(shannon_entropy(url) / 6.0, 1.0)

    # 9. Path depth
    path_parts = [p for p in parsed.path.split("/") if p]
    path_depth = min(len(path_parts) / 10.0, 1.0)

    # 10. Login keyword
    has_login_kw = 1.0 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0.0

    # 11. Brand keyword
    path_lower = parsed.path.lower()
    has_brand_kw = 1.0 if any(b in hostname or b in path_lower for b in BRAND_KEYWORDS) else 0.0

    # 12. Suspicious TLD
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 13. Redirect parameter
    try:
        query_keys = {k.lower() for k in parse_qs(parsed.query, keep_blank_values=True).keys()}
    except Exception:
        query_keys = set()
    has_redirect = 1.0 if query_keys & REDIRECT_PARAMS else 0.0

    # 14. Domain age
    if domain_age_days == -1:
        domain_age = 0.5
    else:
        domain_age = max(0.0, min(1.0, domain_age_days / 365.0))

    # 15. Non-standard port
    port = parsed.port
    has_port = 1.0 if (port and port not in (80, 443)) else 0.0

    return URLFeatureVector(
        url_length=url_length,
        domain_length=domain_length,
        subdomain_count=subdomain_count,
        has_ip=has_ip,
        no_https=no_https,
        special_chars=special_chars,
        digit_ratio=digit_ratio,
        entropy=entropy,
        path_depth=path_depth,
        has_login_kw=has_login_kw,
        has_brand_kw=has_brand_kw,
        suspicious_tld=suspicious_tld,
        has_redirect=has_redirect,
        domain_age=domain_age,
        has_port=has_port,
    )


def batch_extract(urls: List[str]) -> List[List[float]]:
    """Extract features for a list of URLs."""
    return [extract(url).to_list() for url in urls]


def _suspicious_defaults(url: str) -> URLFeatureVector:
    """Maximally suspicious defaults for unparseable URLs."""
    return URLFeatureVector(
        url_length=min(len(url) / 300, 1.0),
        domain_length=1.0,
        subdomain_count=1.0,
        has_ip=0.0,
        no_https=1.0,
        special_chars=0.5,
        digit_ratio=0.3,
        entropy=0.85,
        path_depth=0.5,
        has_login_kw=1.0,
        has_brand_kw=1.0,
        suspicious_tld=1.0,
        has_redirect=1.0,
        domain_age=0.0,
        has_port=1.0,
    )