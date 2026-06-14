"""mitmproxy-capture-based verifiers."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from sentinel.core.finding import Finding
from sentinel.verify.models import VerificationResult, VerifierContext

# ---------- N_002 — cleartext traffic ----------


class CleartextTrafficVerifier:
    """Confirm the cleartext URL the agent flagged was actually requested."""

    AGENT_IDS = ("N_002",)

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        capture = ctx.mitm_capture
        if capture is None:
            return VerificationResult.unsupported(
                method="mitm-flow-match",
                reason="no mitmproxy capture in scope (run scan with --dynamic)",
            )
        flows = list(getattr(capture, "flows", None) or [])
        if not flows:
            return VerificationResult.unsupported(
                method="mitm-flow-match",
                reason="mitm capture present but empty",
            )

        flagged_host = _extract_host_hint(finding.evidence or {})
        cleartext_flows: list[dict[str, Any]] = []
        for flow in flows:
            scheme = (getattr(flow, "scheme", "") or "").lower()
            host = (getattr(flow, "host", "") or "").lower()
            url = getattr(flow, "url", "")
            if scheme == "http" and (not flagged_host or flagged_host == host):
                cleartext_flows.append({
                    "url": url,
                    "method": getattr(flow, "method", ""),
                    "host": host,
                })

        if cleartext_flows:
            return VerificationResult.verified(
                method="mitm-flow-match",
                evidence={
                    "cleartext_flow_count": len(cleartext_flows),
                    "samples": cleartext_flows[:5],
                },
            )
        return VerificationResult.refuted(
            method="mitm-flow-match",
            evidence={"flagged_host": flagged_host or "<any>"},
            notes="no http:// flows captured for the flagged host",
        )


def _extract_host_hint(evidence: dict[str, Any]) -> str:
    """Pull a hostname out of an N_002 finding's evidence, best-effort."""
    for key in ("url", "endpoint", "host"):
        val = evidence.get(key)
        if isinstance(val, str) and val:
            if "://" in val:
                try:
                    return urlparse(val).hostname or ""
                except ValueError:
                    pass
            if "/" in val and val.startswith("http"):
                continue
            return val.lower()
    return ""
