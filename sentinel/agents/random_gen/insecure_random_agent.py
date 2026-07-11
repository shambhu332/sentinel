"""B_002 — Insecure Random Agent.

Detects use of java.util.Random (or Math.random()) in places where
SecureRandom should be used: token generation, password salts, IVs, nonces,
session IDs, password reset tokens, etc.

Why this matters: java.util.Random is a Linear Congruential Generator with
a 48-bit seed. Given a few outputs, an attacker can reconstruct the seed and
predict all future outputs — and all past outputs. If your app uses Random
for security tokens, sessions, or password resets, an attacker can hijack
accounts deterministically. Bug bounty programs pay $300-$1000 for
predictable random number generation, more if account takeover is
demonstrated.

Detection pipeline:
1. Walk decompiled .java files
2. Find usages of java.util.Random and Math.random()
3. Check if those usages are in proximity to security keywords
   (token, secret, salt, iv, nonce, session, password, key, otp)
4. Severity: High if used near security keyword, Medium otherwise
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Detect java.util.Random instantiation or Math.random() call
_RANDOM_USAGE_RE = re.compile(
    r"\b(?:new\s+java\.util\.Random|new\s+Random|Math\.random)\s*\(",
)

# Security context keywords. We look for these within ~200 chars of
# the random call to determine if it's a security-sensitive usage.
_SECURITY_KEYWORDS = (
    "token", "secret", "salt", "iv", "nonce", "session", "password",
    "key", "otp", "verification", "csrf", "auth", "credential",
    "cookie", "captcha", "challenge",
)

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_FINDING = 20

# How many characters around a Random call to inspect for security context
_CONTEXT_WINDOW = 200


class InsecureRandomAgent(BaseAgent):
    """B_002: detects predictable random number generation in security contexts."""

    AGENT_ID = "RNG_001"
    VULN_CLASS = "Insecure Random"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[B_002] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context

        # Two buckets: security-context hits (severity High) and bare hits (Medium)
        security_hits: list[dict[str, Any]] = []
        bare_hits: list[dict[str, Any]] = []

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[B_002] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            for match in _RANDOM_USAGE_RE.finditer(text):
                # Inspect surrounding context for security keywords
                start = max(0, match.start() - _CONTEXT_WINDOW)
                end = min(len(text), match.end() + _CONTEXT_WINDOW)
                context = text[start:end].lower()

                matched_keyword = next(
                    (kw for kw in _SECURITY_KEYWORDS if kw in context),
                    None,
                )

                # Capture line for evidence
                line_start = max(0, text.rfind("\n", 0, match.start()) + 1)
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end].strip()

                hit = {
                    "file": rel,
                    "context": line[:200],
                    "matched": match.group(0)[:80],
                    "security_keyword": matched_keyword,
                }

                if matched_keyword:
                    security_hits.append(hit)
                else:
                    bare_hits.append(hit)

        if not security_hits and not bare_hits:
            logger.info("[B_002] No insecure Random usage detected")
            return []

        package = (ctx.manifest or {}).get("package", "?")
        findings: list[Finding] = []

        if security_hits:
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.80,
                recommendation=self._build_recommendation(security_context=True),
                evidence={
                    "title": "java.util.Random used in security context",
                    "summary": (
                        f"{len(security_hits)} usage(s) of java.util.Random or "
                        f"Math.random() found within proximity of security-sensitive "
                        f"keywords (token, secret, salt, etc.)"
                    ),
                    "package": package,
                    "match_count": len(security_hits),
                    "hits": security_hits[:_MAX_HITS_PER_FINDING],
                    "vector": (
                        "java.util.Random is a 48-bit Linear Congruential Generator. "
                        "Given a small number of consecutive outputs, an attacker "
                        "can recover the seed and predict all future outputs — and "
                        "all past outputs. If Random is used to generate session "
                        "tokens or password reset codes, this enables full session "
                        "prediction and account takeover."
                    ),
                },
            ))

        if bare_hits:
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.MEDIUM,
                confidence=0.65,
                recommendation=self._build_recommendation(security_context=False),
                evidence={
                    "title": "java.util.Random used (security context unclear)",
                    "summary": (
                        f"{len(bare_hits)} usage(s) of java.util.Random or "
                        f"Math.random() found without obvious security keywords nearby. "
                        f"Manual review required to determine if these are security-relevant."
                    ),
                    "package": package,
                    "match_count": len(bare_hits),
                    "hits": bare_hits[:_MAX_HITS_PER_FINDING],
                },
            ))

        return findings

    @staticmethod
    def _build_recommendation(security_context: bool) -> str:
        if security_context:
            return (
                "Replace java.util.Random and Math.random() with "
                "java.security.SecureRandom for any cryptographic or security "
                "purpose (tokens, salts, IVs, nonces, session IDs, password "
                "reset codes, OTPs, CSRF tokens). SecureRandom is seeded from "
                "the operating system's entropy source and is cryptographically "
                "unpredictable. Example:\n"
                "  SecureRandom rng = new SecureRandom();\n"
                "  byte[] token = new byte[32];\n"
                "  rng.nextBytes(token);"
            )
        return (
            "Audit each usage of java.util.Random — if it is used to generate "
            "security-sensitive values, replace with java.security.SecureRandom. "
            "java.util.Random is acceptable only for non-security purposes "
            "(game randomness, statistical sampling, UI animation timing)."
        )

