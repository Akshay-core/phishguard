"""
PhishGuard — Rate Limiter
==========================
Simple sliding-window rate limiter using in-process memory.
For production at scale, replace backing store with Redis.

Why not use a library like slowapi?
- Fewer dependencies = smaller image
- Full control over the eviction and key strategy
- Simpler to understand and audit

Author: Akshay | https://akshay.fruvvi.com
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.core.config import settings


# ─── Sliding window store ─────────────────────────────────────────────────────
# Each key maps to a deque of timestamps for requests in the current window

_windows: dict[str, deque[float]] = defaultdict(deque)
_WINDOW_SECONDS = 60


def _get_client_ip(request: Request) -> str:
    """
    Extract client IP from request.
    Handles X-Forwarded-For for reverse-proxy deployments.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (client), not the proxy's IP
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(request: Request) -> None:
    """
    Enforce rate limiting for a request.
    Raises HTTP 429 if the client has exceeded the limit.

    Call this as a FastAPI dependency:
        @router.get("/check", dependencies=[Depends(check_rate_limit)])
    """
    client_ip = _get_client_ip(request)
    now = time.monotonic()
    window = _windows[client_ip]

    # Remove requests outside the sliding window
    while window and window[0] < now - _WINDOW_SECONDS:
        window.popleft()

    if len(window) >= settings.RATE_LIMIT_RPM:
        # How long until the oldest request falls out of the window
        retry_after = int(_WINDOW_SECONDS - (now - window[0])) + 1
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "limit": settings.RATE_LIMIT_RPM,
                "window_seconds": _WINDOW_SECONDS,
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    window.append(now)


def get_rate_limit_headers(request: Request) -> dict[str, str]:
    """
    Return rate limit headers to include in responses.
    Follows the RateLimit header draft spec.
    """
    client_ip = _get_client_ip(request)
    now = time.monotonic()
    window = _windows.get(client_ip, deque())

    # Count active requests in window
    active = sum(1 for ts in window if ts >= now - _WINDOW_SECONDS)
    remaining = max(0, settings.RATE_LIMIT_RPM - active)

    return {
        "RateLimit-Limit":     str(settings.RATE_LIMIT_RPM),
        "RateLimit-Remaining": str(remaining),
        "RateLimit-Reset":     str(_WINDOW_SECONDS),
    }
