"""Scope parsing endpoint — lets clients preview parsed scope before scanning."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from sentinel.core.finding import BountyScope
from sentinel.scope.scope_parser import ScopeParser, ScopeSourceError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scope", tags=["scope"])


class ScopeParseRequest(BaseModel):
    mode: Literal["url", "file", "text"]
    value: str = Field(..., min_length=1, max_length=500_000)


class ScopeParseResponse(BaseModel):
    source_mode: str
    scope: BountyScope


@router.post("/parse", response_model=ScopeParseResponse)
def parse_scope_endpoint(req: ScopeParseRequest) -> ScopeParseResponse:
    """Parse scope from URL, file path, or pasted text. Returns structured BountyScope."""
    parser = ScopeParser()
    try:
        if req.mode == "url":
            scope = parser.from_url(req.value)
        elif req.mode == "file":
            scope = parser.from_file(Path(req.value))
        else:
            scope = parser.from_text(req.value)
    except ScopeSourceError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope parse failed: {e}",
        ) from e
    return ScopeParseResponse(source_mode=req.mode, scope=scope)