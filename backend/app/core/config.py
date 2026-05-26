"""
PhishGuard — Backend Configuration
=====================================
All configuration loaded from environment variables.
Never hardcode secrets — always use .env or actual env vars in production.

Author: Akshay | https://akshay.fruvvi.com
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ───────────────────────────────────────────────────────────────────
    VERSION:     str = "1.0.0"
    ENVIRONMENT: Literal["development", "production", "test"] = "development"
    LOG_LEVEL:   str = "INFO"

    # ── Server ────────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ── Security ──────────────────────────────────────────────────────────────
    # Extension IDs that are allowed to call this API
    # Format: "chrome-extension://abc123,chrome-extension://xyz456"
    CORS_ORIGINS: list[str] = Field(
        default=["chrome-extension://", "moz-extension://"],
        description="Allowed CORS origins",
    )
    ALLOWED_HOSTS: list[str] = Field(
        default=["*"],
        description="Allowed hosts (set to your domain in production)",
    )

    # API rate limiting (requests per minute per IP)
    RATE_LIMIT_RPM: int = 60

    # ── External APIs ─────────────────────────────────────────────────────────
    # PhishTank API key (optional — increases rate limits)
    # Get free key at: https://www.phishtank.com/api_info.php
    PHISHTANK_API_KEY: str = ""

    # URLHaus (no key required)
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1/host/"

    # ── Cache ─────────────────────────────────────────────────────────────────
    # How long to cache threat intel results (seconds)
    THREAT_CACHE_TTL: int = 3600   # 1 hour

    # ── Feature flags ─────────────────────────────────────────────────────────
    ENABLE_URLHAUS:   bool = True
    ENABLE_PHISHTANK: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_hosts(cls, v) -> list[str]:
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
