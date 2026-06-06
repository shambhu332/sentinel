"""C_015: Weak PRNG Seed Detection.

``SecureRandom`` (and its more permissive sibling ``Random``) only
produces unpredictable output when the seed is itself unpredictable.
Two common mistakes make the stream guessable:

1. ``new SecureRandom(seedBytes)`` where ``seedBytes`` comes from
   ``System.currentTimeMillis()`` / ``System.nanoTime()`` — an
   attacker who can guess the boot time (a few minutes' window for
   most malware) can replay the stream.
2. ``new Random(literal)`` or ``Random(System.currentTimeMillis())``
   for token generation. ``Random`` is not cryptographic at all, and
   seeding it with a literal makes the output a fixed pseudo-random
   sequence.

Mobile bug-bounty hits over the years: predictable account-recovery
tokens, predictable OTP codes, predictable nonces feeding into
otherwise-secure ciphers.

Detection
=========

For every ``new SecureRandom(`` / ``new Random(`` / ``new
SecureRandom().setSeed(`` / ``new Random().setSeed(`` call, inspect
the seed argument:

* ``System.currentTimeMillis`` / ``System.nanoTime`` /
  ``new Date().getTime`` → predictable clock seed.
* Numeric literal → fixed seed.
* String literal ``.getBytes()`` → fixed seed.
* ``.hashCode()`` on a static-looking value → fixed seed.

Severity:

* CRITICAL — ``new Random(`` with any of the above (Random itself is
  not cryptographic; any seed is the wrong tool).
* HIGH — ``new SecureRandom(`` / ``setSeed(`` with a clock /
  literal / hashCode seed (defeats the entropy SecureRandom would
  otherwise inherit from the platform).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_PRNG_INIT = re.compile(
    # Form 1: ``new SecureRandom(seed)`` / ``new Random(seed)``
    r"\bnew\s+(SecureRandom|Random)\s*\(\s*([^)]+?)\s*\)|"
    # Form 2: ``<var>.setSeed(...)`` — variable-form chains the seed
    # onto a pre-existing PRNG. We can't always tell the class from
    # the receiver here, so we infer it from a nearby ``new
    # SecureRandom`` / ``new Random`` in the same file by defaulting to
    # SecureRandom (the safer-by-name option). The Random literal case
    # is already covered by Form 1 with an explicit seed.
    r"\.\s*setSeed\s*\(\s*([^)]+?)\s*\)",
)
_CLOCK_SEED = re.compile(
    r"System\s*\.\s*(currentTimeMillis|nanoTime)\s*\(|"
    r"new\s+Date\s*\(\s*\)\s*\.\s*getTime\s*\(",
)
_NUMERIC_LITERAL = re.compile(r"^-?\d+[lL]?$")
_STRING_BYTES = re.compile(
    r'^\s*"[^"]*"\s*\.\s*getBytes\s*\(',
)
_HASHCODE = re.compile(r"\.\s*hashCode\s*\(\s*\)")


class WeakPrngSeedAgent(BaseAgent):
    """Detect Random / SecureRandom seeded with predictable values."""

    AGENT_ID = "C_015"
    VULN_CLASS = "Weak PRNG Seed"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            rel = str(java_file.relative_to(decompiled))

            for m in _PRNG_INIT.finditer(source):
                if m.group(1):
                    cls = m.group(1)
                    seed = (m.group(2) or "").strip()
                else:
                    seed = (m.group(3) or "").strip()
                    # setSeed() variant — infer class from a nearby
                    # ``new Random`` (worst case, downgrade SecureRandom).
                    cls = (
                        "Random"
                        if re.search(r"\bnew\s+Random\b", source)
                        and not re.search(r"\bnew\s+SecureRandom\b", source)
                        else "SecureRandom"
                    )
                if not seed:
                    continue
                severity, confidence, reason = self._classify(
                    cls=cls,
                    seed=seed,
                )
                if severity is None:
                    continue

                findings.append(self._make_finding(
                    vuln_class="Weak PRNG Seed",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "class": cls,
                        "seed_expression": seed[:120],
                        "reason": reason,
                    },
                    recommendation=(
                        "Use a no-argument SecureRandom() and let it "
                        "draw entropy from the platform (/dev/urandom "
                        "on Android). Never seed with a clock value, a "
                        "literal, or a hashCode — these collapse the "
                        "stream to a fixed or near-fixed sequence. "
                        "java.util.Random is not cryptographic; do not "
                        "use it for tokens, OTPs, or nonces under any "
                        "construction."
                    ),
                    owasp="M4: Insufficient Cryptography",
                    masvs="MSTG-CRYPTO-6",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _classify(*, cls: str, seed: str) -> tuple[Severity | None, float, str]:
        is_random = cls == "Random"
        seed_clean = seed.strip()
        if _CLOCK_SEED.search(seed_clean):
            reason = "clock-based seed (currentTimeMillis / nanoTime)"
            return (
                Severity.CRITICAL if is_random else Severity.HIGH,
                0.90 if is_random else 0.85,
                reason,
            )
        if _NUMERIC_LITERAL.match(seed_clean):
            return (
                Severity.CRITICAL if is_random else Severity.HIGH,
                0.95 if is_random else 0.90,
                "numeric literal seed",
            )
        if _STRING_BYTES.match(seed_clean):
            return (
                Severity.CRITICAL if is_random else Severity.HIGH,
                0.90,
                "string-literal getBytes() seed",
            )
        if _HASHCODE.search(seed_clean):
            return (
                Severity.CRITICAL if is_random else Severity.HIGH,
                0.75,
                "hashCode() seed",
            )
        # java.util.Random with any explicit seed argument is still
        # insufficient for cryptographic use even if the seed is
        # plausibly random — surface as HIGH so the reviewer can
        # decide.
        if is_random:
            return Severity.HIGH, 0.70, "java.util.Random with explicit seed"
        return None, 0.0, "unclassified"
