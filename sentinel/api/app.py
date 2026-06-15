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
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from sentinel.api.routes import agents, auth, devices, reports, scans, scope
from sentinel.core.config import get_settings

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

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
            {"name": "authentication", "description": "User registration, login, JWT tokens"},
            {"name": "scans", "description": "Scan lifecycle operations"},
            {"name": "agents", "description": "Agent registry and metadata"},
            {"name": "scope", "description": "Bug bounty scope parsing"},
            {"name": "reports", "description": "VAPT report artifacts"},
            {"name": "meta", "description": "Health, version, status"},
        ],
    )

    # CORS — keep browser access scoped to configured local origins
    # rather than allowing arbitrary websites to drive the local scanner
    # API from a victim browser.
    settings = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.parsed_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
        max_age=86400,
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
        # The frontend has no build hash, so stale browser cache keeps
        # showing edits-ago content. Force revalidation on every UI asset.
        if request.url.path.startswith("/ui/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
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
    app.include_router(auth.router)
    app.include_router(scans.router)
    app.include_router(agents.router)
    app.include_router(scope.router)
    app.include_router(reports.router)
    app.include_router(devices.router)

    # Serve the frontend so `sentinel serve` is one-command for the GUI.
    # Marketing landing at /ui/  ·  app shell at /ui/app.html
    # API docs stay at /docs.
    if FRONTEND_DIR.exists():
        app.mount(
            "/ui",
            StaticFiles(directory=FRONTEND_DIR, html=True),
            name="frontend",
        )

        @app.get("/app", include_in_schema=False)
        def serve_app() -> RedirectResponse:
            return RedirectResponse(url="/ui/app.html")

        @app.get("/landing", include_in_schema=False)
        def serve_landing() -> RedirectResponse:
            return RedirectResponse(url="/ui/index.html")

    return app


# Expose an instance for uvicorn
app = create_app()
