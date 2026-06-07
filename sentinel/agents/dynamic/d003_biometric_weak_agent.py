"""D_003 — Insecure Biometric Prompt.

``BiometricPrompt.Builder`` on Android lets the developer pick which
authenticator classes are acceptable:

* ``BIOMETRIC_STRONG`` (Class 3) — current fingerprint / face that
  meet the CDD's spoof / impostor acceptance bounds.
* ``BIOMETRIC_WEAK``   (Class 2) — older biometrics that fail the
  Strong bar (cheaper face unlock, low-resolution fingerprint).
* ``DEVICE_CREDENTIAL`` — the device PIN / pattern / password.

When a sensitive flow (unlock vault, sign transaction, decrypt
secrets) calls
``setAllowedAuthenticators(BIOMETRIC_WEAK | DEVICE_CREDENTIAL)``
or worse, ``setDeviceCredentialAllowed(true)`` on the older API, the
biometric guarantee silently degrades into "anyone who knows the
device PIN can authenticate" — which is the threat model the user
explicitly opted out of by enabling biometrics in the first place.

Detection
---------

We consume Frida events of kind ``biometric.prompt``. Each event
payload describes a single ``BiometricPrompt`` build at runtime:

* ``authenticators`` — int bitmask of the
  ``setAllowedAuthenticators`` flags
* ``device_credential_allowed`` — bool, true if the deprecated
  ``setDeviceCredentialAllowed(true)`` was called instead
* ``negative_button`` — str title of the negative button (some apps
  drop it when DEVICE_CREDENTIAL is allowed)
* ``crypto_object`` — bool, true if a CryptoObject was bound
* ``activity`` — caller activity FQCN if known
* ``stack`` — optional caller class/method

Bitmask values per Android docs:

* ``BIOMETRIC_STRONG``   = 0x0F
* ``BIOMETRIC_WEAK``     = 0xFF
* ``DEVICE_CREDENTIAL``  = 0x8000

We raise:

* HIGH if the bitmask includes ``DEVICE_CREDENTIAL`` (0x8000) OR
  ``device_credential_allowed`` is true — biometric is silently
  reducible to device PIN.
* MEDIUM if the bitmask includes ``BIOMETRIC_WEAK`` but not
  ``BIOMETRIC_STRONG`` — accepts older / cheaper biometrics.
* MEDIUM if ``crypto_object`` is false on a build that allowed
  device credential — the auth is not bound to a Keystore key, so
  the result is a yes/no signal an attacker can fake.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_BIOMETRIC_STRONG = 0x0F
_BIOMETRIC_WEAK = 0xFF
_DEVICE_CREDENTIAL = 0x8000


class BiometricWeakAgent(BaseAgent):
    """D_003: detects insecure BiometricPrompt configurations."""

    AGENT_ID = "D_003"
    VULN_CLASS = "Insecure Biometric Prompt"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_003] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        prompts = [
            ev for ev in capture.events if ev.kind == "biometric.prompt"
        ]
        if not prompts:
            return []

        findings: list[Finding] = []
        for ev in prompts:
            payload = ev.payload or {}
            verdict = self._classify(payload)
            if verdict is None:
                continue
            severity, reason = verdict
            findings.append(self._finding(payload, severity, reason))
        return findings

    @staticmethod
    def _classify(
        payload: dict[str, Any],
    ) -> tuple[Severity, str] | None:
        authenticators = payload.get("authenticators")
        legacy_device_cred = bool(payload.get("device_credential_allowed"))
        crypto_object = bool(payload.get("crypto_object"))

        # The legacy setDeviceCredentialAllowed(true) is a HIGH on
        # its own — it predates setAllowedAuthenticators and bypasses
        # the strength tiers entirely.
        if legacy_device_cred:
            return (
                Severity.HIGH,
                "BiometricPrompt.Builder.setDeviceCredentialAllowed(true) "
                "downgrades the prompt to accept the device PIN/pattern. "
                "Sensitive flows must not accept device credential.",
            )

        if isinstance(authenticators, int) and authenticators:
            # BIOMETRIC_STRONG = 0x0F, BIOMETRIC_WEAK = 0xFF, and
            # DEVICE_CREDENTIAL = 0x8000. Weak's bitmask is a superset
            # of Strong's, so we identify Weak by the upper four bits
            # in the low byte (0xF0) — those are only present when
            # BIOMETRIC_WEAK was passed.
            has_device_cred = bool(authenticators & _DEVICE_CREDENTIAL)
            biometric_bits = authenticators & ~_DEVICE_CREDENTIAL & 0xFFFF
            has_weak = bool(biometric_bits & 0xF0)
            strong_only = biometric_bits == _BIOMETRIC_STRONG

            if has_device_cred:
                return (
                    Severity.HIGH,
                    "setAllowedAuthenticators includes DEVICE_CREDENTIAL "
                    "(0x8000) — biometric is silently reducible to the "
                    "device PIN.",
                )
            if has_weak:
                return (
                    Severity.MEDIUM,
                    "setAllowedAuthenticators allows BIOMETRIC_WEAK "
                    "(Class 2). Class-2 face unlock on some OEMs is "
                    "spoofable from a photograph.",
                )
            if strong_only and not crypto_object:
                return (
                    Severity.MEDIUM,
                    "BIOMETRIC_STRONG selected but the prompt was not "
                    "bound to a CryptoObject. A spoofed Java-level "
                    "callback can satisfy the prompt without unlocking "
                    "a Keystore-bound key.",
                )

        return None

    def _finding(
        self,
        payload: dict[str, Any],
        severity: Severity,
        reason: str,
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.90,
            evidence={
                "issue": reason,
                "activity": payload.get("activity") or "?",
                "authenticators": payload.get("authenticators"),
                "device_credential_allowed": bool(
                    payload.get("device_credential_allowed"),
                ),
                "crypto_object_bound": bool(payload.get("crypto_object")),
                "negative_button": payload.get("negative_button"),
                "vector": (
                    "Frida hook on BiometricPrompt.Builder."
                    "setAllowedAuthenticators / "
                    "setDeviceCredentialAllowed / build() captured the "
                    "downgraded configuration at runtime."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Use setAllowedAuthenticators(BIOMETRIC_STRONG) for "
                "any flow guarding a secret. Bind the prompt to a "
                "CryptoObject backed by a "
                "KeyGenParameterSpec.Builder.setUserAuthenticationRequired("
                "true) Keystore key so a successful prompt actually "
                "unlocks the key rather than just returning a yes/no "
                "callback. Never call setDeviceCredentialAllowed(true) "
                "or include DEVICE_CREDENTIAL in the bitmask for "
                "sensitive operations."
            ),
            owasp="M4: Insufficient Cryptography",
            masvs="MSTG-AUTH-8",
            cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        )
