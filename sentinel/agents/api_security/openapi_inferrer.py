"""API_001 — Mobile-backend OpenAPI inferrer.

Takes the mitmproxy capture stored in ``ctx.sources['mitmproxy']`` and
walks every flow to **infer the live API surface** the app talks to.
Each endpoint that ships findings carries:

* the templated path (``/users/{id}/orders`` rather than the literal
  ``/users/42/orders`` and ``/users/9001/orders``),
* the observed HTTP methods,
* the observed auth shape — header names + whether **every** call
  carried one,
* a short, mechanical security verdict (e.g. *"no Authorization header
  on any of 5 observed calls; expected for a mutating verb"*).

This is the bookkeeping half of djini.ai's "Mobile Backend API
Security" feature. The interesting half — fuzzing + auth manipulation
— is a follow-up; doing the inventory honestly is the first step
because there's no point fuzzing an endpoint you can't model.

We deliberately keep this **pattern-based**, no LLM. The output is
deterministic and re-running the agent on the same capture is
reproducible byte-for-byte.

Out of scope (this agent):
* GraphQL operations beyond the touchpoint flag — that's D_054.
* WebSocket frames — that's D_058.
* Authentication-bypass probes — needs runtime; that's a follow-up.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Path segments that look like ID-shaped values get templated.
_ID_SEGMENT_RE = re.compile(
    r"^("
    r"\d{1,}"                                          # all digits
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"  # UUID
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,}"                               # long hex
    r"|[A-Za-z0-9_-]{20,}"                             # opaque token
    r")$"
)
_TOKEN_HEADERS = (
    "authorization", "x-auth-token", "x-api-key", "x-access-token",
    "cookie", "x-csrf-token", "x-amz-security-token",
)
_INTERNAL_HOST_SHAPES = re.compile(
    r"(?:^|\.)(internal|local|corp|dev|staging|test|qa)\b", re.IGNORECASE,
)


def _templatize_path(path: str) -> str:
    """Replace ID-shaped segments with ``{id}`` placeholders."""
    if not path or path == "/":
        return path
    parts = path.split("/")
    out: list[str] = []
    for p in parts:
        if _ID_SEGMENT_RE.match(p):
            out.append("{id}")
        else:
            out.append(p)
    return "/".join(out)


def _flow_has_token(flow: Any) -> tuple[bool, list[str]]:
    """True if any of the flow's request headers looks like an auth token.

    Returns ``(has_token, present_header_names)``.
    """
    headers = getattr(flow, "request_headers", None) or {}
    lowered = {k.lower(): v for k, v in headers.items()}
    found: list[str] = [h for h in _TOKEN_HEADERS if h in lowered]
    return bool(found), found


class OpenAPIInferrerAgent(BaseAgent):
    """API_001: infer the live backend API surface from mitmproxy capture."""

    AGENT_ID = "API_001"
    VULN_CLASS = "Mobile Backend API Security"
    PHASE = "Phase 4"

    async def is_applicable(self) -> bool:
        capture = (self._context.sources or {}).get("mitmproxy")
        return capture is not None and bool(getattr(capture, "flows", None))

    async def analyze(self) -> list[Finding]:
        capture = (self._context.sources or {}).get("mitmproxy")
        flows = list(getattr(capture, "flows", []))
        if not flows:
            return []

        # Group flows by (host, method, templated_path). Each group is
        # one endpoint observation; findings are emitted per group, not
        # per individual flow.
        groups: dict[tuple[str, str, str], list[Any]] = defaultdict(list)
        for f in flows:
            host = getattr(f, "host", "") or ""
            if not host:
                continue
            method = (getattr(f, "method", "") or "GET").upper()
            tmpl = _templatize_path(getattr(f, "path", "") or "/")
            groups[(host, method, tmpl)].append(f)

        findings: list[Finding] = []
        for (host, method, tmpl), grp in groups.items():
            findings.extend(self._emit_for_group(host, method, tmpl, grp))

        # Emit one inventory finding (informational) so the report has a
        # crisp "API surface" pane the user can audit at a glance.
        inventory = sorted(
            {
                f"{m} {h}{p}"
                for (h, m, p) in groups.keys()
            }
        )
        findings.append(self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=1.0,
            recommendation=(
                "Inferred API inventory captured during the dynamic "
                "session. Verify every mutating endpoint is exercised "
                "with an authenticated test account during VAPT; "
                "endpoints surfaced by this agent are the seed list "
                "for downstream fuzzing / IDOR / auth-bypass probes."
            ),
            evidence={
                "kind": "api_inventory",
                "endpoint_count": len(groups),
                "flow_count": len(flows),
                "endpoints": inventory[:200],   # cap to keep evidence dict sane
            },
        ))
        return findings

    # ---------- per-group analysis ----------

    def _emit_for_group(
        self, host: str, method: str, tmpl: str, group: list[Any],
    ) -> list[Finding]:
        out: list[Finding] = []
        token_results = [_flow_has_token(f) for f in group]
        any_authed = any(t for t, _ in token_results)
        all_authed = all(t for t, _ in token_results)
        token_names = sorted({n for _, hs in token_results for n in hs})
        mutating = method in ("POST", "PUT", "PATCH", "DELETE")
        internal = bool(_INTERNAL_HOST_SHAPES.search(host))

        # Severity ladder: a mutating endpoint with zero observed auth
        # is HIGH; a read-only endpoint without auth is MEDIUM; a
        # partially-authed surface (token sometimes present, sometimes
        # not) is HIGH regardless of method because it suggests an
        # attacker-reachable code path.
        sev: Severity | None = None
        verdict: str = ""

        if not any_authed:
            if mutating:
                sev = Severity.HIGH
                verdict = (
                    f"{method} {tmpl} called {len(group)}x with no "
                    "Authorization-shaped header in any observation. "
                    "Mutating verb on an unauthenticated endpoint is "
                    "a strong IDOR / mass-assignment indicator."
                )
            else:
                sev = Severity.MEDIUM
                verdict = (
                    f"{method} {tmpl} returned data on {len(group)} "
                    "observations with no Authorization header. If the "
                    "response contains user-scoped data, this is an "
                    "unauthenticated read primitive."
                )
        elif any_authed and not all_authed:
            sev = Severity.HIGH
            verdict = (
                f"{method} {tmpl} was sometimes called with a token "
                f"({sum(1 for t, _ in token_results if t)}/"
                f"{len(group)} observations) and sometimes without. "
                "Inconsistent auth strongly suggests a code path the "
                "user reached without logging in."
            )
        elif internal and method in ("GET", "POST"):
            sev = Severity.MEDIUM
            verdict = (
                f"Internal-shaped host {host!r} reached from the "
                "mobile app. Confirm this is intended for production "
                "users and not a debug staging surface that leaked."
            )

        if sev is None:
            return out  # nothing to say about this endpoint

        # Pick a representative flow for the evidence URL/headers — the
        # first one in the group is fine; they all share method+path.
        sample = group[0]
        out.append(self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=sev,
            confidence=0.80 if sev != Severity.HIGH else 0.85,
            recommendation=(
                verdict + " Add an Authorization gate on the server "
                "side and reject the request before any business logic "
                "runs. The mobile client should never be the sole "
                "enforcer of authentication."
            ),
            evidence={
                "kind": "endpoint",
                "host": host,
                "method": method,
                "path_template": tmpl,
                "endpoint": f"{method} https://{host}{tmpl}",
                "url": getattr(sample, "url", ""),
                "auth_headers_observed": token_names,
                "auth_consistency": (
                    "always" if all_authed else
                    "never" if not any_authed else
                    "partial"
                ),
                "observation_count": len(group),
                "is_mutating": mutating,
                "internal_host_shape": internal,
                "owasp_masvs": "MASVS-NETWORK-1",
            },
        ))
        return out


__all__ = ["OpenAPIInferrerAgent"]
