"""
Local investigation API.

The endpoint returns a full multi-engine report for one URL. It does not require
paid services and stores only local history in SQLite.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.investigation import InvestigationReport, investigate_url
from app.utils.rate_limiter import check_rate_limit


router = APIRouter()


class InvestigationRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    deep: bool = False


@router.post(
    "/url",
    response_model=InvestigationReport,
    summary="Run a local multi-engine URL investigation",
    dependencies=[Depends(check_rate_limit)],
)
async def investigate_post(payload: InvestigationRequest):
    try:
        return await investigate_url(payload.url, deep=payload.deep)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}") from exc


@router.get(
    "/url",
    response_model=InvestigationReport,
    summary="Run a local multi-engine URL investigation",
    dependencies=[Depends(check_rate_limit)],
)
async def investigate_get(
    url: Annotated[str, Query(min_length=3, max_length=2048)],
    deep: bool = False,
):
    try:
        return await investigate_url(url, deep=deep)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}") from exc
