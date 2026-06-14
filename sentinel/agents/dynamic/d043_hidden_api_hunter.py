"""D_043 — Hidden / internal API endpoint hunter.

Two-stage:

  1. **SAST** — walks decompiled Java for HTTP client invocations
     (`OkHttpClient.newCall`, `Retrofit.create`, `HttpURLConnection`,
     `Volley.newRequestQueue`) and extracts every string-literal URL
     that flows in. Filters to URLs whose path looks "internal":
     `/internal/`, `/debug/`, `/admin/`, `/api/v0/`, trailing
     `?test=`, `?staging=`, or hostnames matching `*.staging.*`,
     `*.dev.*`, `*.internal.*`.

  2. **DAST** — emits a `frida_payload` containing the list of
     suspicious URLs and a recipe for the Frida hook to probe each
     one with the *currently active user token* (captured from the
     same OkHttp/Retrofit hook). Bound by SafetyBudget — max 30
     probes, 3/s, 30s wall-clock.

Why this beats a plain N_015 internal-endpoint scan: we capture not
just the URL but the call site, so the DAST hook knows *which
client/auth context* to reuse when probing. Without that context a
probe gets a generic 401 and the bug stays hidden.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# HTTP client construction signals — presence means we should harvest URLs.
_HTTP_CLIENT_MARKERS = (
    "OkHttpClient", "Retrofit", "HttpURLConnection",
    "Volley.newRequestQueue", "okhttp3.Request",
)

# URL literal extractor — covers http(s) + ws(s)
_URL_RE = re.compile(
    r'"(https?://[^"\s<>]+|wss?://[^"\s<>]+)"',
)

# Internal-ness signals — path or host substring
_INTERNAL_PATH_RE = re.compile(
    r"/(internal|debug|admin|test|staging|sandbox|preview|"
    r"dev|local|private|backdoor|legacy|v0)/",
    re.IGNORECASE,
)
_INTERNAL_HOST_RE = re.compile(
    r"\b(staging|dev|internal|backend|admin|test|qa|sandbox|preview)"
    r"\.[a-z0-9.-]+",
    re.IGNORECASE,
)
_INTERNAL_QUERY_RE = re.compile(
    r"\?(debug|test|staging|internal|admin|preview)=",
    re.IGNORECASE,
)

_MAX_FILES = 2500
_MAX_URLS = 50


class HiddenApiHunterAgent(BaseAgent):
    """D_043: capture suspicious internal URLs + emit DAST probe plan."""

    AGENT_ID = "D_043"
    VULN_CLASS = "Hidden Internal Endpoint (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        # url -> set of source files referencing it
        by_url: dict[str, set[str]] = {}
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not any(marker in text for marker in _HTTP_CLIENT_MARKERS):
                continue
            rel = str(path.relative_to(root))
            for m in _URL_RE.finditer(text):
                url = m.group(1)
                if self._is_internal(url):
                    by_url.setdefault(url, set()).add(rel)
                    if len(by_url) >= _MAX_URLS:
                        break
            if len(by_url) >= _MAX_URLS:
                break

        if not by_url:
            return []

        findings: list[Finding] = []
        # Single finding holding the full surface; details per URL.
        urls_payload = [
            {
                "url": u,
                "sources": sorted(srcs)[:5],
                "internal_reason": self._reason(u),
            }
            for u, srcs in by_url.items()
        ]
        findings.append(self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.65,
            recommendation=(
                f"{len(urls_payload)} URL(s) with internal-looking shape "
                "were extracted from HTTP-client construction sites. The "
                "DAST phase will probe each with the live user token "
                "captured from the same OkHttp/Retrofit hook (no "
                "unauthenticated 401s). Remove debug/staging endpoints "
                "from release builds; if they must ship, require server-"
                "side allow-listed accounts."
            ),
            evidence={
                "urls": urls_payload,
                "url_count": len(urls_payload),
                "dynamic_target": True,
                "frida_payload": self._build_payload(urls_payload),
            },
        ))
        return findings

    # ---------- internal-ness ----------

    @staticmethod
    def _is_internal(url: str) -> bool:
        return bool(
            _INTERNAL_PATH_RE.search(url)
            or _INTERNAL_HOST_RE.search(url)
            or _INTERNAL_QUERY_RE.search(url)
        )

    @staticmethod
    def _reason(url: str) -> str:
        for label, pat in (
            ("internal_path", _INTERNAL_PATH_RE),
            ("internal_host", _INTERNAL_HOST_RE),
            ("internal_query", _INTERNAL_QUERY_RE),
        ):
            if pat.search(url):
                return label
        return "unknown"

    @staticmethod
    def _build_payload(urls: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "urls": [u["url"] for u in urls][:_MAX_URLS],
            "safety_budget": {
                "max_actions_total": 30,
                "max_actions_per_sec": 3,
                "wall_clock_budget_s": 30,
                "max_consecutive_crashes": 3,
            },
            "frida_script_hint":
                "// D_043 — fire URLs via the live OkHttp client with the\n"
                "// currently active auth token; capture response status + body\n"
                "// preview.\n"
                "// rpc.exports.hiddenapiprobe(payload) is the entry\n",
        }


__all__ = ["HiddenApiHunterAgent"]
