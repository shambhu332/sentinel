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
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from sentinel.api.routes import agents, auth, devices, reports, scans, scope
from sentinel.core.config import get_settings

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

logger = logging.getLogger(__name__)

MAX_REQUEST_SIZE = 600 * 1024 * 1024  # 600 MB (APK upload cap)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Run once at startup and shutdown."""
    import asyncio
    from sentinel.core.janitor import start_janitor

    settings = get_settings()
    logger.info("SENTINEL API starting (workspace=%s)", settings.workspace)

    janitor_task = start_janitor(
        workspace_root=settings.workspace,
        retention_days=settings.scan_retention_days,
        interval_seconds=settings.janitor_interval_seconds,
    )

    yield

    logger.info("SENTINEL API shutting down")
    janitor_task.cancel()
    try:
        await asyncio.wait_for(asyncio.shield(janitor_task), timeout=5.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


class _AuditLogMiddleware:
    """Pure ASGI audit-log middleware.

    Using BaseHTTPMiddleware/call_next causes anyio.WouldBlock → CancelledError
    tracebacks on graceful shutdown because its internal stream bridge races
    with task cancellation. A raw ASGI class avoids that entirely.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        rid = (
            dict(scope.get("headers") or [])
            .get(b"x-request-id", b"")
            .decode()
            or uuid.uuid4().hex[:12]
        )
        method = scope.get("method", "")
        path = scope.get("path", "")
        start = time.monotonic()
        status_code = 500

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = rid
                if path.startswith("/ui/"):
                    headers["Cache-Control"] = "no-store, max-age=0"
            await send(message)

        try:
            await self._app(scope, receive, send_wrapper)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.info("%s %s %s %d %dms", rid, method, path, status_code, duration_ms)


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

    app.add_middleware(_AuditLogMiddleware)

    # Phase 1.3 — RBAC middleware sits *outside* audit log so audit
    # records the deny/allow decision for every request. Middlewares
    # run outer-first for both request and response, so ordering here
    # (add RBAC after audit) means audit wraps RBAC — desired.
    from sentinel.auth.rbac import RBACMiddleware  # local import — avoids cycle at module load
    app.add_middleware(RBACMiddleware)

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
            "description": "Autonomous Android security scanner for AppSec teams and bug bounty hunters.",
            "docs": "/docs",
            "legal": (
                "Use only against targets you have explicit written permission to test. "
                "Always respect bug bounty program scope and rules of engagement. "
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
