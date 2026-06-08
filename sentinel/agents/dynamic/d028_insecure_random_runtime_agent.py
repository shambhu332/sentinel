"""D_028 — Insecure RNG Consumed in a Security Context.

``java.util.Random``, ``Math.random()``, and ``SecureRandom`` with a
caller-controlled seed are not cryptographically secure. When their
output ends up in a session token, CSRF nonce, OTP, key derivation,
or any other security-sensitive surface the app's threat model is
broken. Static scanners catch obvious cases; this agent picks up the
ones obfuscation hides.

Detection
---------

We consume one Frida event kind:

* ``random.observation`` — emitted from every consumption call on a
  non-CSPRNG source (``Random.nextInt`` / ``nextLong`` / ``nextBytes``
  / ``nextDouble``, ``Math.random``, and any ``SecureRandom.setSeed``
  with a caller-supplied byte[] that arrived in the same stack
  frame). Payload:
  ``{api, byte_count, caller_class, security_context_hint, stack}``.

``security_context_hint`` is a best-effort label produced by the
Frida side when the calling class name or method name contains a
security-keyword (``token`` / ``otp`` / ``nonce`` / ``session`` /
``csrf`` / ``key`` / ``iv`` / ``salt``).

Severity matrix:

* **HIGH** — ``security_context_hint`` is non-empty (the calling
  surface looks security-relevant).
* **MEDIUM** — at least one ``random.observation`` whose ``byte_count``
  is >= 8 (suggesting a key/nonce-sized read) but no security
  keyword hit. Could be benign UI randomness; flagged for review.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class InsecureRandomRuntimeAgent(BaseAgent):
    """D_028: catch insecure-RNG consumption in security contexts."""

    AGENT_ID = "D_028"
    VULN_CLASS = "Insecure RNG in Security Context"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_028] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        security_hits: list[dict[str, Any]] = []
        large_read_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "random.observation":
                continue
            payload = ev.payload or {}
            hint = str(payload.get("security_context_hint") or "")
            byte_count = _coerce_int(payload.get("byte_count")) or 0
            sample = {
                "api": str(payload.get("api") or ""),
                "byte_count": byte_count,
                "caller_class": str(payload.get("caller_class") or "")[:200],
                "security_context_hint": hint,
                "stack": payload.get("stack"),
            }
            if hint:
                security_hits.append(sample)
            elif byte_count >= 8:
                large_read_hits.append(sample)

        findings: list[Finding] = []
        if security_hits:
            findings.append(self._security_finding(security_hits))
        if large_read_hits:
            findings.append(self._large_read_finding(large_read_hits))
        return findings

    def _security_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "Output from java.util.Random / Math.random / a "
                    "seeded SecureRandom was consumed on a code path "
                    "whose class- or method-name advertised a security "
                    "purpose (token, OTP, nonce, session, key, IV, "
                    "salt, CSRF). None of these sources are "
                    "cryptographically secure — predicting future "
                    "values from a captured prefix is trivial."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Random / Math RNG consumption "
                    "checked the calling class + method names for "
                    "security keywords."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Switch to ``java.security.SecureRandom`` constructed "
                "with the no-arg constructor — let the OS seed it. "
                "Never call setSeed() with a caller-supplied value. "
                "For keys, prefer KeyGenerator over hand-rolled byte "
                "buffers."
            ),
            owasp="M5: Insufficient Cryptography",
            masvs="MSTG-CRYPTO-6",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _large_read_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Insecure RNG Large Read (Caller Unclear)",
            severity=Severity.MEDIUM,
            confidence=0.55,
            evidence={
                "issue": (
                    "Output from java.util.Random or Math.random was "
                    "consumed in chunks of 8 bytes or more (the size "
                    "of a key / IV / nonce). No security keyword was "
                    "matched on the calling class — could be benign "
                    "UI shuffling, but the size warrants review."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Random / Math RNG consumption "
                    "captured byte counts >= 8."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Audit the call sites and switch to SecureRandom if "
                "any path can influence a security-relevant surface."
            ),
            owasp="M5: Insufficient Cryptography",
            masvs="MSTG-CRYPTO-6",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
