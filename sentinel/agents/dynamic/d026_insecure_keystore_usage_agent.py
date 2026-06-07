"""D_026 — Insecure Android-Keystore Key Generation.

``KeyGenParameterSpec`` is the modern API for binding a key to the
Android Keystore. The defaults are *not* secure:

* ``setUserAuthenticationRequired(false)`` (the default) — the key
  can be used by any code with the alias, including malware running
  while the screen is locked.
* ``setInvalidatedByBiometricEnrollment(false)`` — when the user
  enrolls a new fingerprint the key remains valid. An attacker who
  briefly seizes an unlocked device can enroll their own biometric
  and use the key forever.
* ``setUserAuthenticationValidityDurationSeconds(N>30)`` — once the
  user authenticates, the key stays usable for N seconds *for any
  caller in the process*. Long windows defeat the point of binding.
* ``setIsStrongBoxBacked(false)`` on devices with StrongBox — the key
  lives in TEE software rather than the dedicated security chip,
  losing tamper-evident hardware isolation.

Detection
---------

We consume one Frida event kind:

* ``keystore.key_spec_built`` — emitted from
  ``KeyGenParameterSpec$Builder.build()``. Payload:
  ``{alias, purposes, user_auth_required,
    invalidated_by_biometric_enrollment,
    strong_box_backed, validity_duration_seconds,
    user_confirmation_required, stack}``.

``purposes`` is the bitmask of ``KeyProperties.PURPOSE_*`` flags:
  - 0x1 ENCRYPT
  - 0x2 DECRYPT
  - 0x4 SIGN
  - 0x8 VERIFY
  - 0x20 WRAP_KEY
  - 0x40 AGREE_KEY

Severity matrix:

* **HIGH** — purposes include SIGN or DECRYPT **and**
  ``user_auth_required`` is false. The key authenticates the user or
  decrypts a credential without any liveness gate.
* **HIGH** — ``user_auth_required`` is true but
  ``invalidated_by_biometric_enrollment`` is false. Bio-enrollment
  hijack pattern.
* **MEDIUM** — ``user_auth_required`` is true and the validity-
  duration window is > 30 seconds (post-auth re-use window is wider
  than a single transaction).
* **MEDIUM** — purposes include SIGN/DECRYPT and
  ``strong_box_backed`` is false (key is TEE-software, not StrongBox
  hardware). Lower confidence — depends on device support.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


PURPOSE_ENCRYPT = 0x1
PURPOSE_DECRYPT = 0x2
PURPOSE_SIGN = 0x4
PURPOSE_VERIFY = 0x8
PURPOSE_WRAP_KEY = 0x20
PURPOSE_AGREE_KEY = 0x40

SENSITIVE_PURPOSES = PURPOSE_SIGN | PURPOSE_DECRYPT

_MAX_REASONABLE_VALIDITY_S = 30


class InsecureKeystoreUsageAgent(BaseAgent):
    """D_026: classify Android-Keystore key-generation choices."""

    AGENT_ID = "D_026"
    VULN_CLASS = "Insecure Android-Keystore Key Generation"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_026] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        no_auth_hits: list[dict[str, Any]] = []
        enroll_hijack_hits: list[dict[str, Any]] = []
        long_window_hits: list[dict[str, Any]] = []
        no_strongbox_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "keystore.key_spec_built":
                continue
            payload = ev.payload or {}
            purposes = _coerce_int(payload.get("purposes")) or 0
            user_auth = bool(payload.get("user_auth_required"))
            invalidated = payload.get("invalidated_by_biometric_enrollment")
            strongbox = payload.get("strong_box_backed")
            validity = _coerce_int(payload.get("validity_duration_seconds"))
            sensitive = bool(purposes & SENSITIVE_PURPOSES)

            sample = {
                "alias": str(payload.get("alias") or "")[:200],
                "purposes": purposes,
                "purposes_decoded": _decode_purposes(purposes),
                "user_auth_required": user_auth,
                "invalidated_by_biometric_enrollment": invalidated,
                "strong_box_backed": strongbox,
                "validity_duration_seconds": validity,
                "stack": payload.get("stack"),
            }

            if sensitive and not user_auth:
                no_auth_hits.append(sample)
                continue

            if user_auth and invalidated is False:
                enroll_hijack_hits.append(sample)

            if (user_auth and validity is not None
                    and validity > _MAX_REASONABLE_VALIDITY_S):
                long_window_hits.append(sample)

            if sensitive and strongbox is False:
                no_strongbox_hits.append(sample)

        findings: list[Finding] = []
        if no_auth_hits:
            findings.append(self._no_auth_finding(no_auth_hits))
        if enroll_hijack_hits:
            findings.append(self._enroll_hijack_finding(enroll_hijack_hits))
        if long_window_hits:
            findings.append(self._long_window_finding(long_window_hits))
        if no_strongbox_hits:
            findings.append(self._no_strongbox_finding(no_strongbox_hits))
        return findings

    def _no_auth_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "A Keystore key intended for signing or decryption "
                    "was generated without setUserAuthenticationRequired"
                    "(true). Any code path that can name the alias — "
                    "in-process malware, accessibility-service abuse, "
                    "or a callback the dev forgot about — can issue "
                    "the operation without prompting the user. The "
                    "Keystore stops being an authenticator and becomes "
                    "an obfuscated opaque token."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on KeyGenParameterSpec$Builder.build() "
                    "inspected isUserAuthenticationRequired() and "
                    "getPurposes() on the returned spec."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Call setUserAuthenticationRequired(true) on the "
                "builder and either bind to a Cipher / Signature "
                "object passed to BiometricPrompt (no validity "
                "duration) or set a tight validity window (1–5s). For "
                "decrypt-of-token flows prefer the BiometricPrompt + "
                "CryptoObject API so the OS itself gates the use."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-AUTH-8",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        )

    def _enroll_hijack_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Keystore Key Survives Biometric Re-Enrollment",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "A user-auth-bound Keystore key was generated "
                    "without setInvalidatedByBiometricEnrollment(true). "
                    "An attacker who briefly seizes an unlocked device "
                    "can enroll their own fingerprint and the key "
                    "remains usable — the supposed biometric binding "
                    "is permanent across the enrollment set, not "
                    "scoped to the legitimate user's original "
                    "enrollment."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on KeyGenParameterSpec$Builder.build() "
                    "read isInvalidatedByBiometricEnrollment() on the "
                    "returned spec."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Call setInvalidatedByBiometricEnrollment(true) on "
                "every user-auth-bound key. The key will be deleted "
                "by the system when the user adds a new fingerprint, "
                "forcing the app to re-bootstrap secrets through the "
                "server with the new authenticator. That is the only "
                "way to preserve the integrity of the biometric link."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-AUTH-9",
            cvss_vector="CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N",
        )

    def _long_window_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Keystore Key Validity Window Too Wide",
            severity=Severity.MEDIUM,
            confidence=0.70,
            evidence={
                "issue": (
                    "A user-auth-bound Keystore key was generated "
                    "with setUserAuthenticationValidityDurationSeconds"
                    " > 30. After the user authenticates once, the "
                    "key is usable for the entire window by *any* "
                    "caller running in the process, including code "
                    "paths the auth gate was never meant to cover."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook read getUserAuthenticationValidity"
                    "DurationSeconds() on the returned spec."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop the validity duration entirely and pass the "
                "Cipher / Signature to BiometricPrompt instead — the "
                "OS will gate each individual operation. If a window "
                "is unavoidable, cap it at 5 seconds and have the dev "
                "justify it in code comments."
            ),
            owasp="M3: Insecure Authentication/Authorization",
            masvs="MSTG-AUTH-8",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        )

    def _no_strongbox_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Keystore Key Not Bound to StrongBox",
            severity=Severity.MEDIUM,
            confidence=0.55,
            evidence={
                "issue": (
                    "A signing / decryption Keystore key was generated "
                    "with setIsStrongBoxBacked(false) (or never called). "
                    "On devices with a StrongBox hardware module the "
                    "key still lives in TEE software, losing the "
                    "tamper-evident isolation StrongBox provides. "
                    "Whether this matters depends on the target's "
                    "device fleet — flagged for review."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook read isStrongBoxBacked() on the "
                    "returned spec."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Wrap key generation in a try / catch that first "
                "attempts setIsStrongBoxBacked(true) and falls back "
                "to setIsStrongBoxBacked(false) on "
                "StrongBoxUnavailableException. Cheap, additive, and "
                "lifts the floor on devices that support it (Pixel 3+, "
                "most flagships since 2019)."
            ),
            owasp="M5: Insufficient Cryptography",
            masvs="MSTG-CRYPTO-1",
            cvss_vector="CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _decode_purposes(purposes: int) -> list[str]:
    if not purposes:
        return []
    decoded: list[str] = []
    if purposes & PURPOSE_ENCRYPT:
        decoded.append("ENCRYPT")
    if purposes & PURPOSE_DECRYPT:
        decoded.append("DECRYPT")
    if purposes & PURPOSE_SIGN:
        decoded.append("SIGN")
    if purposes & PURPOSE_VERIFY:
        decoded.append("VERIFY")
    if purposes & PURPOSE_WRAP_KEY:
        decoded.append("WRAP_KEY")
    if purposes & PURPOSE_AGREE_KEY:
        decoded.append("AGREE_KEY")
    return decoded
