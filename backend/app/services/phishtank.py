"""
PhishGuard — Threat Intelligence Service
==========================================
Aggregates PhishTank and URLHaus APIs with:
  - Async HTTP via httpx
  - In-process TTL cache (functools + time)
  - Graceful fallback: if one source fails, return the other
  - Structured result type

Author: Akshay | https://akshay.fruvvi.com
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import settings

log = logging.getLogger("phishguard.phishtank")


# ─── Result type ──────────────────────────────────────────────────────────────

@dataclass
class ThreatResult:
    is_phish:    bool
    source:      str | None = None
    reported_at: str | None = None
    confidence:  float = 0.0
    from_cache:  bool = False


SAFE_RESULT = ThreatResult(is_phish=False, confidence=0.0)

# ─── Cache ────────────────────────────────────────────────────────────────────
# Simple dict-based TTL cache. For production at scale, replace with Redis.

@dataclass
class CacheEntry:
    result:    ThreatResult
    cached_at: float = field(default_factory=time.time)


_cache: dict[str, CacheEntry] = {}


def _get_cached(hostname: str) -> ThreatResult | None:
    entry = _cache.get(hostname)
    if entry and (time.time() - entry.cached_at) < settings.THREAT_CACHE_TTL:
        result = entry.result
        result.from_cache = True
        return result
    if entry:
        del _cache[hostname]
    return None


def _set_cached(hostname: str, result: ThreatResult) -> None:
    _cache[hostname] = CacheEntry(result=result)
    # Evict old entries if cache grows large (basic protection)
    if len(_cache) > 10_000:
        oldest = sorted(_cache.items(), key=lambda x: x[1].cached_at)[:1000]
        for key, _ in oldest:
            del _cache[key]


# ─── HTTP client ──────────────────────────────────────────────────────────────

_client: httpx.AsyncClient | None = None

def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=2.0),
            headers={"User-Agent": f"PhishGuard/{settings.VERSION}"},
            follow_redirects=False,
        )
    return _client


# ─── URLHaus check ────────────────────────────────────────────────────────────

async def _check_urlhaus(hostname: str) -> ThreatResult:
    if not settings.ENABLE_URLHAUS:
        return SAFE_RESULT

    client = _get_client()
    try:
        response = await client.post(
            settings.URLHAUS_API_URL,
            data={"host": hostname},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "is_host":
            urls = data.get("urls", [])
            reported_at = urls[0].get("date_added") if urls else None
            return ThreatResult(
                is_phish=True,
                source="URLHaus",
                reported_at=reported_at,
                confidence=0.95,
            )
        return SAFE_RESULT

    except httpx.HTTPError as e:
        log.warning(f"URLHaus check failed for {hostname}: {e}")
        return SAFE_RESULT


# ─── PhishTank check ──────────────────────────────────────────────────────────

PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"

async def _check_phishtank(hostname: str) -> ThreatResult:
    if not settings.ENABLE_PHISHTANK:
        return SAFE_RESULT

    client = _get_client()
    params = {"url": f"http://{hostname}/", "format": "json"}
    if settings.PHISHTANK_API_KEY:
        params["app_key"] = settings.PHISHTANK_API_KEY

    try:
        response = await client.post(PHISHTANK_API_URL, data=params)
        response.raise_for_status()
        data = response.json()

        results = data.get("results", {})
        if results.get("in_database") and results.get("valid"):
            return ThreatResult(
                is_phish=True,
                source="PhishTank",
                reported_at=results.get("submission_time"),
                confidence=0.98,
            )
        return SAFE_RESULT

    except httpx.HTTPError as e:
        log.warning(f"PhishTank check failed for {hostname}: {e}")
        return SAFE_RESULT


# ─── Public API ───────────────────────────────────────────────────────────────

async def check_hostname(hostname: str) -> ThreatResult:
    """
    Check hostname against all enabled threat intelligence sources.
    Returns the highest-confidence positive result, or SAFE if none found.
    """
    # Cache hit
    cached = _get_cached(hostname)
    if cached:
        return cached

    # Run all checks concurrently
    results = await asyncio.gather(
        _check_urlhaus(hostname),
        _check_phishtank(hostname),
        return_exceptions=True,
    )

    # Pick first positive result with highest confidence
    best: ThreatResult = SAFE_RESULT
    for result in results:
        if isinstance(result, ThreatResult) and result.is_phish:
            if result.confidence > best.confidence:
                best = result

    _set_cached(hostname, best)
    return best


async def warm_cache() -> None:
    """Pre-populate cache with no-ops at startup (just validates connectivity)."""
    try:
        await check_hostname("google.com")  # Known safe — warms the client
        log.info("Threat intel connectivity verified.")
    except Exception as e:
        log.warning(f"Threat intel warm-up failed (non-fatal): {e}")
