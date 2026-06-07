"""D_007 — Race-Condition / TOCTOU Candidate Identifier.

The classic TOCTOU bug on a mobile-backed app is the
"send two identical requests in parallel and both succeed" race —
double-redeem a coupon, double-claim a referral bonus, double-withdraw
the same balance. The window between the server checking eligibility
and committing the side-effect is usually milliseconds, but
attacker-controlled parallelism beats it routinely.

A *true* race confirmation requires actively re-firing N parallel
copies of an authenticated request through mitmproxy and observing
the response delta. That is the job of the exploit engine and is
gated behind a separate user opt-in. This agent does the upstream
work: it scans the mitmproxy capture, identifies the subset of flows
that look value-affecting (i.e., race-prone), and emits one finding
per distinct endpoint so a reviewer or the exploit engine knows where
to aim.

Detection
---------

A flow is a race candidate when:

1. Method is POST / PUT / PATCH / DELETE (state-mutating), AND
2. URL path contains a value-affecting verb keyword
   (claim / redeem / withdraw / transfer / cashout / vote / purchase /
   coupon / refund / apply / submit / activate / enroll / accept /
   reserve / book), AND
3. The 2xx response body suggests the server confirmed the action
   (contains success / ok / true / accepted / created — case
   insensitive), OR the status code is 201/202/204.

We emit MEDIUM by default. The severity bumps to HIGH when the
endpoint name carries one of the high-impact verbs
(transfer / withdraw / cashout / refund) because the cost of one
extra successful execution there is direct financial damage.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_VALUE_VERBS = (
    "claim", "redeem", "withdraw", "transfer", "cashout", "vote",
    "purchase", "coupon", "refund", "apply", "submit", "activate",
    "enroll", "accept", "reserve", "book",
)
_HIGH_IMPACT_VERBS = (
    "transfer", "withdraw", "cashout", "refund",
)
_MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_SUCCESS_HINT = re.compile(
    r"\b(success|ok|true|accepted|created|approved|granted)\b",
    re.IGNORECASE,
)


class RaceConditionCandidateAgent(BaseAgent):
    """D_007: flag flows that are race-condition replay candidates."""

    AGENT_ID = "D_007"
    VULN_CLASS = "Race-Condition / TOCTOU Candidate"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("mitmproxy")
        if not capture or not getattr(capture, "flows", None):
            logger.info("[D_007] No mitmproxy flows — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("mitmproxy")
        if capture is None or not getattr(capture, "flows", None):
            return []

        # Group candidates by (host, path-template, method) so we
        # emit one finding per endpoint even if observed many times.
        seen: dict[tuple[str, str, str], dict[str, Any]] = {}
        for flow in capture.flows:
            method = (getattr(flow, "method", "") or "").upper()
            if method not in _MUTATING_METHODS:
                continue
            path = getattr(flow, "path", "") or ""
            verbs = [v for v in _VALUE_VERBS if v in path.lower()]
            if not verbs:
                continue
            status = int(getattr(flow, "response_status", 0) or 0)
            body = getattr(flow, "response_body", "") or ""
            if not (200 <= status < 300):
                continue
            if status not in (201, 202, 204) and not _SUCCESS_HINT.search(body):
                continue

            host = getattr(flow, "host", "") or ""
            key = (host, _normalise_path(path), method)
            entry = seen.setdefault(key, {
                "host": host,
                "method": method,
                "path": path,
                "verbs": verbs,
                "sample_status": status,
                "occurrence_count": 0,
            })
            entry["occurrence_count"] += 1

        findings: list[Finding] = []
        for entry in seen.values():
            findings.append(self._finding(entry))
        return findings

    def _finding(self, entry: dict[str, Any]) -> Finding:
        verbs = entry["verbs"]
        severity = (
            Severity.HIGH
            if any(v in _HIGH_IMPACT_VERBS for v in verbs)
            else Severity.MEDIUM
        )
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.75,
            evidence={
                "issue": (
                    "The application makes an authenticated state-"
                    "mutating request whose path contains a value-"
                    f"affecting verb ({verbs}). Endpoints in this "
                    "shape are the canonical targets for "
                    "race-condition / TOCTOU exploits: send N "
                    "parallel copies of the same request and observe "
                    "whether the server commits more than one side-"
                    "effect. The traffic capture by itself cannot "
                    "confirm the bug — the exploit engine's replayer "
                    "must run an active test against the endpoint."
                ),
                "host": entry["host"],
                "method": entry["method"],
                "path": entry["path"],
                "verbs": verbs,
                "observed_success_status": entry["sample_status"],
                "occurrence_count": entry["occurrence_count"],
                "vector": (
                    "mitmproxy capture filtered for "
                    f"{_MUTATING_METHODS} methods whose path matches "
                    "the value-verb keyword list."
                ),
                "sources": ["mitmproxy"],
            },
            recommendation=(
                "Enforce server-side idempotency on every value-"
                "affecting endpoint: require an Idempotency-Key header "
                "(RFC draft idempotency-header-01) and reject duplicates "
                "for at least 24h. Wrap the eligibility check and the "
                "side-effect commit in a single database transaction "
                "with row-level locking on the user/account/coupon "
                "row, or use a conditional update "
                "(UPDATE ... WHERE balance >= amount). Never rely on "
                "an application-layer 'is this allowed?' read followed "
                "by a later 'commit' write — that is the TOCTOU "
                "window the attacker hits."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-3",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        )


def _normalise_path(path: str) -> str:
    """Collapse numeric path segments to ``{id}`` so two flows hitting
    ``/redeem/123`` and ``/redeem/456`` group as one endpoint."""
    parts = path.split("?", 1)[0].split("/")
    return "/".join(
        "{id}" if (p.isdigit() and len(p) >= 1) else p for p in parts
    )
