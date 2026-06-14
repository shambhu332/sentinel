"""Frida-event-based verifiers."""
from __future__ import annotations

from typing import Any

from sentinel.core.finding import Finding
from sentinel.verify.models import VerificationResult, VerifierContext

# ---------- A_003 — runtime crypto ----------


class RuntimeCryptoVerifier:
    """Cross-check the agent's claimed algorithm against Frida events."""

    AGENT_IDS = ("A_003",)

    _CIPHER_EVENT_KINDS = ("crypto.cipher", "crypto.digest", "crypto.keygen")

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        capture = ctx.frida_capture
        if capture is None:
            return VerificationResult.unsupported(
                method="frida-event-match",
                reason="no Frida capture in scope (run scan with --frida)",
            )
        events = list(getattr(capture, "events", None) or [])
        if not events:
            return VerificationResult.unsupported(
                method="frida-event-match",
                reason="Frida capture present but no events recorded",
            )

        flagged = self._flagged_algorithm(finding.evidence or {})
        if not flagged:
            return VerificationResult.unsupported(
                method="frida-event-match",
                reason="finding evidence does not name an algorithm",
            )
        matches: list[dict[str, Any]] = []
        for event in events:
            kind = getattr(event, "kind", "")
            if kind not in self._CIPHER_EVENT_KINDS:
                continue
            payload = getattr(event, "payload", {}) or {}
            algo = str(payload.get("algorithm", "") or "").lower()
            if flagged in algo:
                matches.append({"kind": kind, "algorithm": algo})
        if matches:
            return VerificationResult.verified(
                method="frida-event-match",
                evidence={
                    "algorithm": flagged,
                    "match_count": len(matches),
                    "samples": matches[:5],
                },
            )
        return VerificationResult.refuted(
            method="frida-event-match",
            evidence={"algorithm": flagged},
            notes="no runtime event observed for the flagged algorithm",
        )

    @staticmethod
    def _flagged_algorithm(evidence: dict[str, Any]) -> str:
        for key in ("algorithm", "primitive", "vuln_class"):
            val = evidence.get(key)
            if isinstance(val, str) and val:
                return val.lower()
        return ""


# ---------- N_005 — cert pinning bypass ----------


class TlsPinningBypassVerifier:
    """Confirm a Frida bypass event surfaced during the scan."""

    AGENT_IDS = ("N_005",)

    _BYPASS_EVENT_KINDS = ("tls.bypass", "tls.pin_check")

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        capture = ctx.frida_capture
        if capture is None:
            return VerificationResult.unsupported(
                method="frida-event-match",
                reason="no Frida capture in scope (run scan with --frida)",
            )
        events = list(getattr(capture, "events", None) or [])
        if not events:
            return VerificationResult.unsupported(
                method="frida-event-match",
                reason="Frida capture present but no events recorded",
            )

        bypass_events: list[dict[str, Any]] = []
        pin_check_events: list[dict[str, Any]] = []
        for event in events:
            kind = getattr(event, "kind", "")
            payload = getattr(event, "payload", {}) or {}
            if kind == "tls.bypass":
                bypass_events.append({"library": payload.get("library", "")})
            elif kind == "tls.pin_check":
                pin_check_events.append({"library": payload.get("library", "")})

        if bypass_events:
            return VerificationResult.verified(
                method="frida-event-match",
                evidence={
                    "bypass_event_count": len(bypass_events),
                    "samples": bypass_events[:5],
                },
                notes="Frida observed pin-check bypass at runtime",
            )
        if pin_check_events:
            return VerificationResult.inconclusive(
                method="frida-event-match",
                reason=(
                    f"{len(pin_check_events)} pin check(s) observed but "
                    "no bypass — pinning library is present and "
                    "executing as intended"
                ),
            )
        return VerificationResult.refuted(
            method="frida-event-match",
            evidence={},
            notes="no TLS pin-check events observed",
        )
