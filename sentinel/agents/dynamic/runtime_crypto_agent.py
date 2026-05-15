"""A_003 — Runtime Crypto Agent.

Analyzes Frida-captured crypto calls to detect weak algorithms in
ACTUAL runtime use, not just declared in code.

Why this is better than SAST for crypto:
- Static analysis flags Cipher.getInstance("DES") even if it's in dead
  code or a test path.
- Runtime hooking only flags algorithms that actually execute during
  the app's normal operation, eliminating dead-code false positives.

Detection logic:
- Group events by algorithm
- For each weak algorithm observed, produce one finding with all
  call sites/contexts as evidence

Bug bounty value:
- Weak crypto in transit protection: $1,000-$5,000
- Weak password hashing: $500-$2,500
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Algorithms classified as weak. Maps lowercase substring → human description.
# Severity is determined later by _severity_for_description.
_WEAK_ALGORITHMS: dict[str, str] = {
    # Symmetric ciphers
    "des": "DES (broken since 1999, 56-bit key)",
    "3des": "3DES (deprecated by NIST in 2023)",
    "desede": "3DES (deprecated by NIST in 2023)",
    "rc4": "RC4 (broken — BEAR/LEFT attacks)",
    "blowfish": "Blowfish (weak 64-bit block; use AES)",
    # Hash functions
    "md5": "MD5 (collisions trivial)",
    "md2": "MD2 (broken)",
    "md4": "MD4 (broken)",
    "sha1": "SHA-1 (collisions practical)",
    "sha-1": "SHA-1 (collisions practical)",
    # Modes
    "/ecb/": "ECB mode (leaks plaintext patterns)",
    # PRNG
    "random": "java.util.Random for crypto (predictable)",
}


class RuntimeCryptoAgent(BaseAgent):
    """A_003: detects weak crypto algorithms in actual runtime use."""

    AGENT_ID = "A_003"
    VULN_CLASS = "Runtime Weak Cryptography"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[A_003] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        # Pull crypto events
        crypto_events = [
            e for e in capture.events
            if e.kind in ("crypto.cipher", "crypto.digest", "crypto.keygen")
        ]
        if not crypto_events:
            logger.info("[A_003] No crypto events captured")
            return []

        # Group by weak-algorithm description
        findings_by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for event in crypto_events:
            algo = (event.payload.get("algorithm") or "").lower()
            if not algo:
                continue

            for weak_key, description in _WEAK_ALGORITHMS.items():
                if weak_key in algo:
                    findings_by_label[description].append({
                        "algorithm": event.payload.get("algorithm"),
                        "kind": event.kind,
                        "provider": event.payload.get("provider"),
                        "timestamp": event.timestamp,
                    })
                    break  # one match per event is enough

        if not findings_by_label:
            return []

        # Produce one finding per weak-algorithm category
        findings: list[Finding] = []
        for description, occurrences in findings_by_label.items():
            severity = self._severity_for_description(description)
            confidence = 0.95  # runtime observation is high-confidence

            example_algo = occurrences[0].get("algorithm", "?")
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=confidence,
                recommendation=self._build_recommendation(description),
                evidence={
                    "title": (
                        f"Weak crypto algorithm in runtime use: "
                        f"{example_algo} ({description})"
                    ),
                    "package": (
                        (self._context.manifest or {}).get("package", "?")
                    ),
                    "weak_algorithm_description": description,
                    "occurrence_count": len(occurrences),
                    "samples": occurrences[:10],
                    "all_algorithms_observed": sorted(set(
                        e.payload.get("algorithm", "")
                        for e in crypto_events
                    )),
                    "vector": (
                        "Frida hooks captured Cipher/MessageDigest/KeyGenerator "
                        "calls at runtime. Unlike static analysis, this proves "
                        "the algorithm is actually invoked during normal app "
                        "use, not just present in dead code. Steps to "
                        "reproduce: 1) Install Frida and zygiskfrida on test "
                        "device, 2) Launch the app, 3) Use normal app "
                        "functionality, 4) Observe the captured algorithm "
                        "names in the Frida session output."
                    ),
                    "sources": ["frida"],
                },
            ))

        return findings

    @staticmethod
    def _severity_for_description(description: str) -> Severity:
        """Map a weak-algo description to a Severity enum."""
        desc_l = description.lower()
        if "broken" in desc_l or "trivial" in desc_l:
            return Severity.CRITICAL
        if "deprecated" in desc_l or "practical" in desc_l:
            return Severity.HIGH
        if "leaks plaintext" in desc_l:
            return Severity.HIGH
        if "predictable" in desc_l:
            return Severity.HIGH
        if "weak" in desc_l:
            return Severity.MEDIUM
        return Severity.MEDIUM

    @staticmethod
    def _build_recommendation(description: str) -> str:
        if "DES" in description or "3DES" in description or "RC4" in description:
            return (
                "Replace with AES-256-GCM. DES/3DES/RC4 are all known-broken and "
                "should never be used in new code. AES-GCM provides both "
                "confidentiality and authentication. Use BouncyCastle or the "
                "platform JCE provider."
            )
        if "ECB" in description:
            return (
                "Switch to a mode that uses an IV: GCM (authenticated), CBC with "
                "an HMAC, or CTR. Never use ECB for anything longer than one "
                "block. The 'ECB penguin' problem demonstrates why."
            )
        if "MD5" in description or "MD2" in description or "MD4" in description:
            return (
                "Replace with SHA-256 (or SHA-3 for new code). MD5 is "
                "cryptographically broken; only acceptable use is non-security "
                "hashing (caching, change detection)."
            )
        if "SHA-1" in description:
            return (
                "Replace SHA-1 with SHA-256 or SHA-3. Practical collision "
                "attacks exist against SHA-1 (Google 2017)."
            )
        if "Random" in description:
            return (
                "Replace java.util.Random with java.security.SecureRandom for "
                "any security-sensitive value (tokens, IVs, salts, session IDs). "
                "Random is fully predictable from observed output."
            )
        return (
            "Replace with a cryptographically-strong algorithm. See OWASP MASVS "
            "(Mobile Application Security Verification Standard) for current "
            "recommendations: https://mas.owasp.org/MASVS/"
        )
