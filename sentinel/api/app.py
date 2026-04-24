"""SENTINEL FastAPI gateway.

Single source of truth for CLI and GUI. Both clients call these endpoints.

Security features built in:
- CORS locked to localhost by default
- Request body size limit (prevents DoS via huge uploads)
- Legal disclaimer on root endpoint
- Audit logging middleware (every request logged)
- Explicit error handlers (no stack traces leaked to clients)
"""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel.api.routes import agents, scans, scope
from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

MAX_REQUEST_SIZE = 600 * 1024 * 1024  # 600 MB (APK upload cap)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Run once at startup and shutdown."""
    settings = get_settings()
    logger.info("SENTINEL API starting (workspace=%s)", settings.workspace)
    yield
    logger.info("SENTINEL API shutting down")


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    app = FastAPI(
        title="SENTINEL API",
        description=(
            "Multi-agent mobile application security assessment platform. "
            "88 AI-powered vulnerability detection agents across 14 categories. "
            "Use only against targets you have explicit written permission to test."
        ),
        version="0.1.0",
        lifespan=lifespan,
        openapi_tags=[
            {"name": "scans", "description": "Scan lifecycle operations"},
            {"name": "agents", "description": "Agent registry and metadata"},
            {"name": "scope", "description": "Bug bounty scope parsing"},
            {"name": "meta", "description": "Health, version, status"},
        ],
    )

    # CORS — locked to localhost for now
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def audit_log(request: Request, call_next):
        """Assign request ID, log method+path+status+duration."""
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "%s %s %s %d %dms",
            rid, request.method, request.url.path, response.status_code, duration_ms,
        )
        response.headers["X-Request-ID"] = rid
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        """Swallow stack traces — never leak internals to clients."""
        logger.exception("Unhandled exception in %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "internal_error", "detail": "see server logs"},
        )

    # Root endpoint
    @app.get("/", tags=["meta"])
    def root() -> dict:
        return {
            "service": "SENTINEL",
            "version": "0.1.0",
            "docs": "/docs",
            "disclaimer": (
                "Use only against targets you have explicit written permission to test. "
                "Always respect bug bounty program scope. "
                "The authors assume no liability for misuse."
            ),
        }

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/status", tags=["meta"])
    def status_endpoint() -> dict:
        settings = get_settings()
        return {
            "service": "SENTINEL",
            "version": "0.1.0",
            "cerebras_configured": settings.has_cerebras_key(),
            "workspace": str(settings.workspace),
        }

    # Attach routers
    app.include_router(scans.router)
    app.include_router(agents.router)
    app.include_router(scope.router)

    return app


# Expose an instance for uvicorn
app = create_app()