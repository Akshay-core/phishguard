"""
PhishGuard — Threat Intelligence API Router
============================================
Aggregates PhishTank + URLHaus results and returns a unified
threat assessment for a given hostname.

Privacy:
  - Only accepts hostnames (not full URLs) — callers strip path+query before sending
  - No IP addresses or query strings are stored in logs
  - Results are cached server-side to minimize outbound API calls

Author: Akshay | https://akshay.fruvvi.com
"""

import re
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app.services.phishtank import check_hostname
from app.core.config import settings
from app.utils.rate_limiter import check_rate_limit

log = logging.getLogger("phishguard.threat")
router = APIRouter()

# ─── Input validation ─────────────────────────────────────────────────────────

# Very strict hostname validation — only letters, digits, hyphens, dots
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")

def validate_hostname(hostname: str) -> str:
    hostname = hostname.strip().lower()
    if not hostname or len(hostname) > 253:
        raise HTTPException(status_code=422, detail="Invalid hostname")
    if not _HOSTNAME_RE.match(hostname):
        raise HTTPException(status_code=422, detail="Invalid hostname format")
    # Block obvious internal/loopback addresses
    blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if hostname in blocked:
        raise HTTPException(status_code=422, detail="Invalid hostname")
    return hostname


# ─── Response models ──────────────────────────────────────────────────────────

class ThreatCheckResponse(BaseModel):
    hostname:       str
    isKnownPhish:   bool
    source:         str | None = None
    reportedAt:     str | None = None
    confidence:     float      # 0–1
    fromCache:      bool = False


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get(
    "/check",
    response_model=ThreatCheckResponse,
    summary="Check a hostname against threat intelligence feeds",
    description=(
        "Returns whether a hostname is known to be associated with phishing. "
        "Only accepts hostnames — full URLs must be stripped by the client. "
        "Results are cached for efficiency."
    ),
    dependencies=[Depends(check_rate_limit)],
)
async def check_threat(
    hostname: Annotated[str, Query(description="Hostname to check (e.g. 'evil.xyz')")],
    request: Request,
):
    clean_hostname = validate_hostname(hostname)

    log.info(f"Threat check: {clean_hostname}")

    result = await check_hostname(clean_hostname)

    return ThreatCheckResponse(
        hostname=clean_hostname,
        isKnownPhish=result.is_phish,
        source=result.source,
        reportedAt=result.reported_at,
        confidence=result.confidence,
        fromCache=result.from_cache,
    )
