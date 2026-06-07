"""D_006 — Runtime Static-IV / Hardcoded-Key Reuse.

AES-GCM, AES-CBC, AES-CTR and ChaCha20 all require a *unique*
nonce / IV per encryption under the same key. AES-GCM in particular
fails catastrophically on nonce reuse: two ciphertexts under the same
(key, nonce) leak the XOR of their plaintexts and reveal the auth
key, letting an attacker forge tags for arbitrary new messages.

Static analysis can flag obviously hardcoded ``IvParameterSpec(new
byte[16])`` calls, but the common pattern is to derive the IV from a
constant string at runtime, or to store one IV in a static field and
reuse it. Runtime observation catches every variant uniformly.

Detection
---------

We consume Frida events of kind:

* ``crypto.iv_constructed``  — payload ``{algorithm, iv_hex, len}``
* ``crypto.secret_key_created`` — payload ``{algorithm, key_hex, len}``

Both ``iv_hex`` and ``key_hex`` are the SHA-256 prefix of the raw
bytes (the TS hook never sends raw material). We hash on-device to
preserve "is this the same value as before?" semantics without
exfiltrating secret bytes — even from the developer's own scan.

Logic per ``iv_constructed``:

* HIGH (0.95) — same ``iv_hex`` observed ≥ 2 times for the same
  ``algorithm``. Confirmed runtime IV reuse.
* MEDIUM (0.80) — same ``iv_hex`` observed exactly once but the IV
  is all-zero / all-one (constant byte pattern). Strong signal of a
  hardcoded placeholder that just hasn't reused yet on this trace.
* No finding — single observation of a random-looking IV.

Logic per ``secret_key_created``:

* HIGH (0.90) — same ``key_hex`` observed ≥ 2 times across different
  ``algorithm`` constructors, OR observed at a single call site that
  also fires ``iv_constructed`` with a constant IV. Indicates a
  global static key.

The agent emits one consolidated finding per (algorithm, iv_hex) pair.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class StaticIvReuseAgent(BaseAgent):
    """D_006: detect runtime IV reuse and hardcoded-key reuse."""

    AGENT_ID = "D_006"
    VULN_CLASS = "Runtime IV / Key Reuse"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_006] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        # (algorithm, iv_hex) → list of occurrences
        iv_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        # key_hex → list of (algorithm, occurrence) tuples
        key_groups: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "crypto.iv_constructed":
                algo = str(payload.get("algorithm") or "?")
                iv_hex = str(payload.get("iv_hex") or "")
                if not iv_hex:
                    continue
                iv_groups[(algo, iv_hex)].append({
                    "iv_len": payload.get("iv_len"),
                    "stack": payload.get("stack"),
                    "constant_pattern": payload.get("constant_pattern"),
                    "timestamp": ev.timestamp,
                })
            elif ev.kind == "crypto.secret_key_created":
                algo = str(payload.get("algorithm") or "?")
                key_hex = str(payload.get("key_hex") or "")
                if not key_hex:
                    continue
                key_groups[key_hex].append((algo, {
                    "key_len": payload.get("key_len"),
                    "stack": payload.get("stack"),
                    "timestamp": ev.timestamp,
                }))

        findings: list[Finding] = []
        # ---- IV reuse / constant IV ----
        for (algo, iv_hex), occs in iv_groups.items():
            verdict = self._classify_iv(occs)
            if verdict is None:
                continue
            severity, confidence, reason = verdict
            findings.append(self._iv_finding(
                algo, iv_hex, occs, severity, confidence, reason,
            ))

        # ---- Key reuse across constructors ----
        for key_hex, observations in key_groups.items():
            algos = sorted({a for a, _ in observations})
            if len(observations) >= 2 and len(algos) >= 2:
                findings.append(self._key_finding(
                    key_hex, algos, observations,
                ))

        return findings

    @staticmethod
    def _classify_iv(
        occurrences: list[dict[str, Any]],
    ) -> tuple[Severity, float, str] | None:
        if len(occurrences) >= 2:
            return (
                Severity.HIGH, 0.95,
                "The same IV byte sequence was passed to "
                "IvParameterSpec / GCMParameterSpec on more than one "
                "encryption call. AES-GCM nonce reuse leaks the auth "
                "key; CBC / CTR nonce reuse leaks plaintext patterns.",
            )
        pattern = occurrences[0].get("constant_pattern")
        if pattern in ("zero", "ff", "ascii_const"):
            return (
                Severity.MEDIUM, 0.80,
                "A single IV was observed but its bytes form a "
                f"constant pattern ({pattern}). Hardcoded placeholder "
                "IVs become reuse the moment a second encryption fires.",
            )
        return None

    def _iv_finding(
        self,
        algorithm: str,
        iv_hex: str,
        occurrences: list[dict[str, Any]],
        severity: Severity,
        confidence: float,
        reason: str,
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            evidence={
                "issue": reason,
                "algorithm": algorithm,
                "iv_hash_prefix": iv_hex,
                "occurrence_count": len(occurrences),
                "samples": occurrences[:5],
                "vector": (
                    "Frida hook on IvParameterSpec / GCMParameterSpec "
                    "constructors recorded the SHA-256 prefix of the IV "
                    "bytes on every encryption call. Reuse is detected "
                    "by hash-collision across calls of the same "
                    "algorithm."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Generate a fresh IV per encryption with "
                "SecureRandom.nextBytes(new byte[12]) for AES-GCM "
                "(12-byte nonce) or new byte[16] for AES-CBC / CTR. "
                "Prepend the IV to the ciphertext so the receiver can "
                "reconstruct it. Never persist or hardcode IV bytes "
                "in the application package, and never derive the IV "
                "from a counter that resets — under AES-GCM the very "
                "first reuse is fatal."
            ),
            owasp="M5: Insufficient Cryptography",
            masvs="MSTG-CRYPTO-3",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _key_finding(
        self,
        key_hex: str,
        algorithms: list[str],
        observations: list[tuple[str, dict[str, Any]]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Runtime Hardcoded Key Reuse",
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The same SecretKey byte sequence was instantiated "
                    f"under multiple algorithms ({algorithms}). This is "
                    "the signature of a single hardcoded master key "
                    "reused across encryption / MAC primitives, which "
                    "violates key-separation and lets an attacker who "
                    "recovers the key once compromise every flow."
                ),
                "key_hash_prefix": key_hex,
                "algorithms": algorithms,
                "occurrence_count": len(observations),
                "samples": [
                    {"algorithm": a, **occ} for a, occ in observations[:5]
                ],
                "vector": (
                    "Frida hook on javax.crypto.spec.SecretKeySpec "
                    "constructor recorded the SHA-256 prefix of the key "
                    "bytes on every instantiation. Hash collision under "
                    "different algorithms reveals reuse."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Derive a per-purpose key with HKDF from the master "
                "secret: separate keys for encryption, MAC, and any "
                "key wrapping. Hold the master key in the Android "
                "Keystore with setUserAuthenticationRequired(true) so "
                "the raw bytes are never material the JVM can read."
            ),
            owasp="M5: Insufficient Cryptography",
            masvs="MSTG-CRYPTO-1",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        )
