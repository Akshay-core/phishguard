"""
PhishGuard — Health Check Router
Author: Akshay | https://akshay.fruvvi.com
"""

import time
from fastapi import APIRouter
from pydantic import BaseModel
from app.core.config import settings

router = APIRouter()
_START_TIME = time.time()


class HealthResponse(BaseModel):
    status:      str
    version:     str
    environment: str
    uptime_s:    float


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    include_in_schema=True,
)
async def health_check():
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        uptime_s=round(time.time() - _START_TIME, 2),
    )
