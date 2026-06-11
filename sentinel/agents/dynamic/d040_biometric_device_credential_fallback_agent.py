"""D_040 — BiometricPrompt Accepts Device-Credential Fallback.

``BiometricPrompt`` is the modern API for binding sensitive
operations to a user-presence check. The Authenticators enum
controls which credential classes satisfy the prompt:

* ``BIOMETRIC_STRONG`` (0x0F)
* ``BIOMETRIC_WEAK``   (0xFF)
* ``DEVICE_CREDENTIAL`` (0x8000) — falls back to the device PIN /
  pattern / password.

When the prompt is launched with ``BIOMETRIC_STRONG |
DEVICE_CREDENTIAL`` *and* a ``CryptoObject`` is bound, the OS
accepts a PIN unlock as a valid biometric — the supposed biometric
binding becomes a *knowledge-factor* binding. Any code path that
sees the user enter a PIN once unlocks the bound Keystore key.

Static SAST (D_003 ``BiometricWeakAgent``) catches the configuration
at construction time. This runtime agent picks up the
``BiometricPrompt.Builder.setAllowedAuthenticators`` calls obscured
by builder chains, reflection, or DI factories.

Detection
---------

We consume one Frida event kind:

* ``biometric.authenticate_called`` — emitted when
  ``BiometricPrompt.authenticate`` is invoked (both
  ``CryptoObject``-bearing overloads and the credential-only ones).
  Payload: ``{allowed_authenticators, has_crypto,
  negative_button_set, caller_class, stack}``.

Severity matrix:

* **HIGH** — ``has_crypto=True`` AND
  ``allowed_authenticators & DEVICE_CREDENTIAL != 0``. PIN/pattern
  fallback unlocks a CryptoObject-bound Keystore key.
* **HIGH** — ``has_crypto=False`` AND ``allowed_authenticators``
  includes only ``BIOMETRIC_WEAK`` (0xFF without 0x0F). Convenience
  flows that authorise sensitive actions on Class 2 biometrics.
* **MEDIUM** — ``has_crypto=False`` AND
  ``allowed_authenticators & DEVICE_CREDENTIAL != 0``. PIN as the
  sole authenticator on a sensitive flow — knowledge-factor
  binding.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


BIOMETRIC_STRONG = 0x0F
BIOMETRIC_WEAK = 0xFF
DEVICE_CREDENTIAL = 0x8000


class BiometricDeviceCredentialFallbackAgent(BaseAgent):
    """D_040: classify BiometricPrompt authenticator masks at runtime."""

    AGENT_ID = "D_040"
    VULN_CLASS = "Biometric Crypto Bypassable via PIN Fallback"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_040] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        crypto_fallback_hits: list[dict[str, Any]] = []
        weak_only_hits: list[dict[str, Any]] = []
        no_crypto_fallback_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "biometric.authenticate_called":
                continue
            payload = ev.payload or {}
            mask = _coerce_int(payload.get("allowed_authenticators")) or 0
            has_crypto = bool(payload.get("has_crypto"))
            sample = {
                "allowed_authenticators": mask,
                "decoded": _decode_authenticators(mask),
                "has_crypto": has_crypto,
                "negative_button_set": payload.get("negative_button_set"),
                "caller_class": str(payload.get("caller_class") or "")[:200],
                "stack": payload.get("stack"),
            }
            has_credential = bool(mask & DEVICE_CREDENTIAL)
            only_weak = (
                (mask & BIOMETRIC_WEAK) == BIOMETRIC_WEAK
                and (mask & BIOMETRIC_STRONG) != BIOMETRIC_STRONG
            )

            if has_crypto and has_credential:
                crypto_fallback_hits.append(sample)
            elif not has_crypto and only_weak:
                weak_only_hits.append(sample)
            elif not has_crypto and has_credential:
                no_crypto_fallback_hits.append(sample)

        findings: list[Finding] = []
        if crypto_fallback_hits:
            findings.append(self._crypto_fallback_finding(crypto_fallback_hits))
        if weak_only_hits:
            findings.append(self._weak_only_finding(weak_only_hits))
        if no_crypto_fallback_hits:
            findings.append(
                self._no_crypto_fallback_finding(no_crypto_fallback_hits),
            )
        return findings

    def _crypto_fallback_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "BiometricPrompt.authenticate was launched with a "
                    "CryptoObject bound AND an authenticator mask "
                    "that includes DEVICE_CREDENTIAL. The OS will "
                    "accept a PIN / pattern / password unlock as a "
                    "valid biometric — anyone who watches the user "
                    "enter their device PIN once can unlock the "
                    "bound Keystore key. The biometric link becomes "
                    "a knowledge-factor link."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on BiometricPrompt.authenticate read "
                    "the authenticator mask off the Builder and the "
                    "CryptoObject pointer off the call."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop DEVICE_CREDENTIAL from the mask whenever a "
                "CryptoObject is bound. Use BIOMETRIC_STRONG alone "
                "and handle the BIOMETRIC_ERROR_NO_BIOMETRICS / "
                "BIOMETRIC_ERROR_NONE_ENROLLED errors by re-"
                "bootstrapping the secret server-side instead of "
                "weakening the prompt."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-AUTH-8",
            cvss_vector="CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N",
        )

    def _weak_only_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="BiometricPrompt Accepts Class-2 Biometrics Only",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "BiometricPrompt.authenticate was launched with "
                    "BIOMETRIC_WEAK in the authenticator mask but "
                    "without BIOMETRIC_STRONG. Class-2 biometrics "
                    "(face / iris on many OEMs, older fingerprint "
                    "sensors) fall outside the BIOMETRIC_STRONG "
                    "threshold and accept materially higher false-"
                    "accept rates."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook compared the authenticator mask "
                    "against the BIOMETRIC_STRONG / BIOMETRIC_WEAK "
                    "constants."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Use BIOMETRIC_STRONG. If the device has no Class-3 "
                "biometric the prompt will surface "
                "BIOMETRIC_ERROR_NONE_ENROLLED — handle that "
                "explicitly rather than weakening the mask."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-AUTH-8",
            cvss_vector="CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N",
        )

    def _no_crypto_fallback_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Biometric Flow Accepts PIN Fallback",
            severity=Severity.MEDIUM,
            confidence=0.65,
            evidence={
                "issue": (
                    "BiometricPrompt.authenticate was launched "
                    "without a CryptoObject but with DEVICE_CREDENTIAL "
                    "in the authenticator mask. The flow gates a "
                    "sensitive action on knowledge of the device PIN "
                    "alone — a weaker contract than the biometric "
                    "promise implies."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook saw DEVICE_CREDENTIAL in the mask "
                    "without a bound CryptoObject."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Confirm the use-case actually needs a PIN fallback. "
                "If the prompt is gating money movement or sensitive "
                "PII access, drop DEVICE_CREDENTIAL."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-AUTH-8",
            cvss_vector="CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
        )


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _decode_authenticators(mask: int) -> list[str]:
    decoded: list[str] = []
    if mask & BIOMETRIC_STRONG == BIOMETRIC_STRONG:
        decoded.append("BIOMETRIC_STRONG")
    elif mask & BIOMETRIC_WEAK == BIOMETRIC_WEAK:
        decoded.append("BIOMETRIC_WEAK")
    if mask & DEVICE_CREDENTIAL:
        decoded.append("DEVICE_CREDENTIAL")
    return decoded
