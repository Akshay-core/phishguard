"""
PhishGuard — FastAPI Backend
=============================
Optional lightweight API for:
  - Threat intelligence aggregation (PhishTank + URLHaus + OpenPhish)
  - Model update distribution
  - Aggregated analytics (opt-in, hostname-only)

This is NOT required for core detection — the extension works fully offline.
Deploy this only if you want remote threat intelligence feeds.

Author: Akshay | https://akshay.fruvvi.com
GitHub: https://github.com/Akshay-core
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import threat, health
from app.core.config import settings

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("phishguard.api")


# ─── Lifespan (startup/shutdown) ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("PhishGuard API starting up...")
    log.info(f"Environment: {settings.ENVIRONMENT}")
    log.info(f"Version: {settings.VERSION}")

    # Warm up threat intel caches on startup
    from app.services.phishtank import warm_cache
    await warm_cache()
    log.info("Threat intel cache warmed.")

    yield

    log.info("PhishGuard API shutting down.")


# ─── App factory ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="Threat intelligence backend for PhishGuard browser extension.",
    version=settings.VERSION,
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT == "development" else None,
    lifespan=lifespan,
)

# ─── Middleware ────────────────────────────────────────────────────────────────

# CORS — only allow extension origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Trusted hosts — prevent host header injection
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )


@app.middleware("http")
async def add_request_timing(request: Request, call_next):
    """Add X-Response-Time header for observability."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Response-Time"] = f"{duration_ms}ms"
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Minimal security headers."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Tell the extension what we are
    response.headers["X-PhishGuard-API"] = settings.VERSION
    return response


# ─── Exception handlers ───────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"error": "Not found"})


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    log.exception("Unhandled server error")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ─── Routes ───────────────────────────────────────────────────────────────────

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(threat.router, prefix="/api/v1/threat", tags=["threat"])
