"""C_007 — Weak Cryptography Agent.

Detects use of cryptographic primitives that are broken, deprecated, or
inappropriate for the security context they're used in.

Why this matters: cryptographic mistakes are the #1 source of confirmed-exploit
bug bounty findings on Android. DES is brute-forceable in hours. MD5 has
practical collision attacks. AES-ECB leaks structure of plaintext. SHA-1 is
deprecated. Apps that ship these primitives get bounty payouts in the
$500-$3000 range, with $5000+ for confirmed exploitation.

Detection pipeline:
1. Walk decompiled .java files
2. Run regexes for each broken primitive
3. Group results by primitive — one finding per primitive type
4. Severity scales: DES/RC4 = Critical, MD5 in security context = High,
   SHA-1 = Medium, AES-ECB = High
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Each detector: (display_name, regex, severity, confidence)
_DETECTORS: list[tuple[str, re.Pattern, Severity, float]] = [
    # DES / 3DES — broken / deprecated
    ("DES", re.compile(
        r'(?:Cipher\.getInstance\s*\(\s*"DES(?:/[A-Z]+/[A-Za-z0-9]+)?"|'
        r'\bSecretKeyFactory\.getInstance\s*\(\s*"DES")',
    ), Severity.CRITICAL, 0.90),

    ("Triple DES (3DES)", re.compile(
        r'Cipher\.getInstance\s*\(\s*"(?:DESede|TripleDES)(?:/[A-Z]+/[A-Za-z0-9]+)?"',
    ), Severity.HIGH, 0.85),

    # RC4 — broken
    ("RC4", re.compile(
        r'Cipher\.getInstance\s*\(\s*"(?:RC4|ARCFOUR)(?:/[A-Z]+/[A-Za-z0-9]+)?"',
    ), Severity.CRITICAL, 0.90),

    # AES-ECB — broken mode (leaks plaintext patterns)
    ("AES-ECB", re.compile(
        r'Cipher\.getInstance\s*\(\s*"AES/ECB(?:/[A-Za-z0-9]+)?"',
    ), Severity.HIGH, 0.85),

    # MD5 — broken hash
    ("MD5", re.compile(
        r'MessageDigest\.getInstance\s*\(\s*"MD5"',
    ), Severity.HIGH, 0.80),

    # SHA-1 — deprecated
    ("SHA-1", re.compile(
        r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"',
    ), Severity.MEDIUM, 0.75),

    # Hardcoded IV (frequent crypto bug)
    ("Hardcoded Initialization Vector", re.compile(
        r'new\s+IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{\s*(?:0x[0-9a-fA-F]+\s*,?\s*)+\}|"[^"]*"\s*\.\s*getBytes)',
    ), Severity.MEDIUM, 0.70),
]

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_PRIMITIVE = 10


class WeakCryptoAgent(BaseAgent):
    """C_007: detects broken/deprecated cryptographic primitives."""

    AGENT_ID = "C_007"
    VULN_CLASS = "Weak Cryptography"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[C_007] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        # Group hits by primitive name
        hits_by_primitive: dict[str, list[dict[str, Any]]] = {}
        primitive_metadata: dict[str, tuple[Severity, float]] = {}

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[C_007] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            for primitive, pattern, severity, confidence in _DETECTORS:
                for match in pattern.finditer(text):
                    # Capture context line + 1-based line number + columns
                    line_start = max(0, text.rfind("\n", 0, match.start()) + 1)
                    line_end = text.find("\n", match.end())
                    if line_end == -1:
                        line_end = len(text)
                    line_text = text[line_start:line_end]
                    # Line number = 1 + number of newlines up to the match
                    line_no = text.count("\n", 0, match.start()) + 1
                    start_col = match.start() - line_start
                    end_col = start_col + (match.end() - match.start())

                    hits_by_primitive.setdefault(primitive, []).append({
                        "file": rel,
                        "line": line_no,
                        "start_col": start_col,
                        "end_col": end_col,
                        "context": line_text.strip()[:200],
                        "matched": match.group(0)[:80],
                    })
                    primitive_metadata[primitive] = (severity, confidence)

        if not hits_by_primitive:
            logger.info("[C_007] No weak crypto primitives detected")
            return []

        package = (ctx.manifest or {}).get("package", "?")

        # One finding per primitive
        findings: list[Finding] = []
        for primitive, instances in hits_by_primitive.items():
            severity, confidence = primitive_metadata[primitive]
            # First hit drives code_snippet; the rest live in evidence["hits"].
            first = instances[0]
            code_snippet = {
                "file": first["file"],
                "line": first["line"],
                "start_col": first["start_col"],
                "end_col": first["end_col"],
                "content": first["context"],
            }
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=confidence,
                recommendation=self._build_recommendation(primitive),
                code_snippet=code_snippet,
                evidence={
                    "title": f"Weak Crypto Primitive: {primitive}",
                    "primitive": primitive,
                    "package": package,
                    "match_count": len(instances),
                    "hits": instances[:_MAX_HITS_PER_PRIMITIVE],
                    "vector": (
                        f"The application uses {primitive} for cryptographic "
                        f"operations. An attacker who can intercept ciphertext or "
                        f"hashed values can recover plaintext or forge data, "
                        f"depending on the use case."
                    ),
                },
            ))

        return findings

    @staticmethod
    def _build_recommendation(primitive: str) -> str:
        recommendations = {
            "DES": (
                "Replace DES with AES-256 in GCM mode. DES has a 56-bit key space "
                "and is brute-forceable in hours on modern hardware. Generate keys "
                "via SecretKeyFactory with PBKDF2 if deriving from passwords."
            ),
            "Triple DES (3DES)": (
                "Replace 3DES with AES-256 in GCM mode. 3DES is deprecated by NIST "
                "for new applications and has been disallowed for new federal "
                "implementations since 2023."
            ),
            "RC4": (
                "Replace RC4 with AES-256 in GCM mode immediately. RC4 has known "
                "biases that allow plaintext recovery, especially in TLS contexts. "
                "RC4 was banned from TLS by RFC 7465 in 2015."
            ),
            "AES-ECB": (
                "Switch from AES/ECB to AES/GCM/NoPadding (preferred) or "
                "AES/CBC/PKCS5Padding with a random IV per encryption. ECB mode "
                "leaks structure of plaintext — identical input blocks produce "
                "identical ciphertext blocks."
            ),
            "MD5": (
                "If used for security (passwords, integrity verification, signatures): "
                "replace with SHA-256 or SHA-3. MD5 has practical collision attacks "
                "since 2008. If used purely for non-security purposes (cache keys, "
                "deduplication), consider whether this should be flagged."
            ),
            "SHA-1": (
                "Replace SHA-1 with SHA-256 or SHA-3. SHA-1 collision attacks are "
                "practical (Google's SHAttered, 2017) and SHA-1 is deprecated by "
                "NIST since 2011 for digital signatures."
            ),
            "Hardcoded Initialization Vector": (
                "Generate a fresh, random IV for every encryption operation using "
                "SecureRandom. The IV must be stored or transmitted alongside the "
                "ciphertext (it doesn't need to be secret, just unique). A static "
                "IV with a stream cipher catastrophically breaks confidentiality."
            ),
        }
        return recommendations.get(
            primitive,
            f"Replace {primitive} with a modern, secure equivalent. "
            f"Consult OWASP's Mobile Application Security Verification Standard.",
        )
