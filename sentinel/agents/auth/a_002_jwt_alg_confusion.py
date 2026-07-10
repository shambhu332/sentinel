"""A_002 — JWT Algorithm Confusion Agent.

Detects JWT algorithm confusion vulnerabilities in decompiled Android source:
  1. alg: "none" — signature bypass (always CRITICAL)
  2. alg: "HS256" with RSA public key — key confusion attack (CRITICAL/HIGH)
  3. Missing algorithm whitelist in jwt.decode() call (HIGH/MEDIUM)
  4. JWK kty/alg mismatch (RSA key with HMAC algorithm) (HIGH)

Detection:
  Regex patterns covering Auth0 java-jwt, JJWT, Nimbus JOSE+JWT, and manual
  JWT parsing in Java/Kotlin. Taint analysis detects attacker-controlled alg
  headers from request parameters.

CWE: CWE-287 (Improper Authentication), CWE-347 (Improper Signature Verification)
MASVS: MASVS-AUTH-2
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext
from sentinel.memory.interface import MemoryInterface

logger = logging.getLogger(__name__)


@dataclass
class _Match:
    vuln_type: str           # "alg_none" | "alg_hs256_rsa" | "missing_verify" | "jwk_mismatch"
    file_path: Path
    line_number: int
    matched_text: str
    context_window: str
    algorithm_value: str | None
    key_type: str | None
    confidence: float


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# 1. alg: "none"
_ALG_NONE: list[re.Pattern[str]] = [
    re.compile(r'Algorithm\.none\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'(?:\\?["\'])alg(?:\\?["\'])\s*:\s*(?:\\?["\'])none(?:\\?["\'])', re.IGNORECASE),
    re.compile(r'algorithms?\s*=\s*\[?\s*["\']none["\']', re.IGNORECASE),
    re.compile(r'Jwts\.parser\s*\(\s*\)\s*[^;]*\.parseClaimsJwt\b', re.IGNORECASE),
]

# 2. HS256 with RSA public key
_ALG_HS256_RSA: list[re.Pattern[str]] = [
    # Algorithm.HMAC256(<anything referencing RSA/public key names directly>)
    re.compile(
        r'Algorithm\.HMAC256\s*\([^)]*(?:RSAPublicKey|publicKey|rsa|PublicKey)[^)]*\)',
        re.IGNORECASE,
    ),
    # algorithms=["HS256"] near RSA public key header
    re.compile(
        r'(?:HS256|HMAC256).*(?:RSAPublicKey|-----BEGIN PUBLIC KEY)',
        re.IGNORECASE | re.DOTALL,
    ),
    # RSAPublicKey-typed variable used as HMAC256 argument (cross-scope, e.g. method param)
    re.compile(
        r'RSAPublicKey\s+(\w+)\b.{0,300}Algorithm\.HMAC256\s*\(\s*\1\b',
        re.IGNORECASE | re.DOTALL,
    ),
]

# 3. Missing algorithm whitelist (JWT.decode with ≤2 args, no algorithms param nearby)
_MISSING_VERIFY: list[re.Pattern[str]] = [
    re.compile(r'\bJWT\.decode\s*\(\s*[^)]+\)', re.IGNORECASE),
    re.compile(r'Jwts\.parser\s*\(\s*\)\s*\.setSigningKey\s*\([^)]+\)\s*\.parseClaimsJws\b', re.IGNORECASE),
]

# 4. JWK kty/alg mismatch
_JWK_MISMATCH: list[re.Pattern[str]] = [
    re.compile(r'["\']kty["\']\s*:\s*["\']RSA["\'][^}]{0,200}["\']alg["\']\s*:\s*["\']HS', re.IGNORECASE | re.DOTALL),
    re.compile(r'["\']alg["\']\s*:\s*["\']HS[^}]{0,200}["\']kty["\']\s*:\s*["\']RSA', re.IGNORECASE | re.DOTALL),
]

_TEST_PATH_RE = re.compile(r'[Tt]est|[Mm]ock|[Ff]ake|[Ss]tub')

# Comments / log lines that look like code but aren't
_COMMENT_LINE_RE = re.compile(r'^\s*(?://|\*|/\*|System\.out|Log\.|logger\.)', re.MULTILINE)


class A002JWTAlgConfusionAgent(BaseAgent):
    """A_002: JWT algorithm confusion detection."""

    AGENT_ID = "A_016"
    VULN_CLASS = "JWT Algorithm Confusion"

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(context, memory, config)

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            return True
        logger.info("[A_002] No decompiled source — skipping")
        return False

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        findings: list[Finding] = []

        source_root = ctx.decompiled_dir
        if not source_root or not source_root.exists():
            return findings

        java_files = list(source_root.rglob("*.java")) + list(source_root.rglob("*.kt"))

        for source_file in java_files:
            if _TEST_PATH_RE.search(str(source_file.relative_to(source_root))):
                continue
            try:
                content = source_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            matches: list[_Match] = []
            matches.extend(self._find_alg_none(source_file, content))
            matches.extend(self._find_hs256_rsa(source_file, content))
            matches.extend(self._find_missing_verify(source_file, content))
            matches.extend(self._find_jwk_mismatch(source_file, content))

            for match in matches:
                if self._is_fp(match, content):
                    continue
                attacker_ctrl = self._check_attacker_controlled(content, match)
                severity = self._severity(match, attacker_ctrl)
                findings.append(self._make_finding(match, attacker_ctrl, severity))

        return findings

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _find_alg_none(self, fp: Path, content: str) -> list[_Match]:
        return self._collect(fp, content, _ALG_NONE, "alg_none", "none", None, 0.95)

    def _find_hs256_rsa(self, fp: Path, content: str) -> list[_Match]:
        return self._collect(fp, content, _ALG_HS256_RSA, "alg_hs256_rsa", "HS256", "RSA public key", 0.90)

    def _find_missing_verify(self, fp: Path, content: str) -> list[_Match]:
        raw = self._collect(fp, content, _MISSING_VERIFY, "missing_verify", None, None, 0.80)
        # Remove hits that already have an algorithms param nearby
        return [m for m in raw if not self._has_algorithms_param(content, m.line_number)]

    def _find_jwk_mismatch(self, fp: Path, content: str) -> list[_Match]:
        return self._collect(fp, content, _JWK_MISMATCH, "jwk_mismatch", "HS*/RSA mismatch", "RSA", 0.85)

    def _collect(
        self,
        fp: Path,
        content: str,
        patterns: list[re.Pattern[str]],
        vuln_type: str,
        alg_value: str | None,
        key_type: str | None,
        confidence: float,
    ) -> list[_Match]:
        seen: set[int] = set()
        results: list[_Match] = []
        for pat in patterns:
            for m in pat.finditer(content):
                line_num = content[: m.start()].count("\n") + 1
                if line_num in seen:
                    continue
                seen.add(line_num)
                results.append(_Match(
                    vuln_type=vuln_type,
                    file_path=fp,
                    line_number=line_num,
                    matched_text=m.group(0)[:200],
                    context_window=self._ctx_window(content, line_num),
                    algorithm_value=alg_value,
                    key_type=key_type,
                    confidence=confidence,
                ))
        return results

    @staticmethod
    def _ctx_window(content: str, line_num: int, window: int = 5) -> str:
        lines = content.split("\n")
        start = max(0, line_num - window - 1)
        end = min(len(lines), line_num + window)
        return "\n".join(lines[start:end])

    @staticmethod
    def _has_algorithms_param(content: str, line_num: int) -> bool:
        lines = content.split("\n")
        snippet = "\n".join(lines[max(0, line_num - 2): min(len(lines), line_num + 5)])
        return bool(re.search(r'algorithms?\s*=|\.verify\s*\(|acceptLeeway', snippet, re.IGNORECASE))

    # ------------------------------------------------------------------
    # False-positive filtering
    # ------------------------------------------------------------------

    def _is_fp(self, match: _Match, content: str) -> bool:
        # Inline comment / log line
        line = content.split("\n")[match.line_number - 1] if match.line_number <= len(content.split("\n")) else ""
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            return True
        if re.search(r'(?:logger|log|System\.out)\s*\.', line, re.IGNORECASE):
            return True
        # Context has explicit validation guard
        ctx_lower = match.context_window.lower()
        if any(kw in ctx_lower for kw in ("validate alg", "verify algorithm", "algorithm whitelist", "reject.*none")):
            return True
        return False

    # ------------------------------------------------------------------
    # Taint
    # ------------------------------------------------------------------

    @staticmethod
    def _check_attacker_controlled(content: str, match: _Match) -> bool:
        if match.vuln_type == "alg_none":
            return True  # Supporting alg:none at all is the vulnerability
        attacker_src = [
            r'getHeader\s*\(\s*["\']alg["\']',
            r'getParameter\s*\(\s*["\']alg["\']',
            r'request\.get.*alg',
            r'JSONObject.*getString\s*\(\s*["\']alg["\']',
        ]
        lines = content.split("\n")
        snippet = "\n".join(lines[max(0, match.line_number - 10): match.line_number + 10])
        return any(re.search(src, snippet, re.IGNORECASE) for src in attacker_src)

    # ------------------------------------------------------------------
    # Severity
    # ------------------------------------------------------------------

    @staticmethod
    def _severity(match: _Match, attacker_ctrl: bool) -> Severity:
        if match.vuln_type == "alg_none":
            return Severity.CRITICAL
        if match.vuln_type == "alg_hs256_rsa":
            return Severity.CRITICAL if attacker_ctrl else Severity.HIGH
        if match.vuln_type == "jwk_mismatch":
            return Severity.HIGH
        # missing_verify
        return Severity.HIGH if attacker_ctrl else Severity.MEDIUM

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    _DESCRIPTIONS: dict[str, str] = {
        "alg_none": (
            "JWT algorithm 'none' is supported. An attacker can craft an unsigned "
            "token by setting alg:none in the header, bypassing signature verification entirely."
        ),
        "alg_hs256_rsa": (
            "JWT is verified with HMAC-SHA256 (HS256) using an RSA public key as the secret. "
            "Since the public key is public, an attacker can forge valid tokens signed with it."
        ),
        "missing_verify": (
            "JWT decode call does not explicitly whitelist allowed algorithms. "
            "This may permit algorithm substitution: an attacker could switch to a weaker "
            "algorithm or 'none' to bypass verification."
        ),
        "jwk_mismatch": (
            "JWK specifies RSA key type (kty:RSA) but is used with an HMAC algorithm "
            "(HS256/384/512). The RSA public key can be used directly as the HMAC secret "
            "to forge tokens."
        ),
    }

    _REMEDIATION: dict[str, str] = {
        "alg_none": (
            "1. Never allow 'none' as an accepted algorithm in production.\n"
            "2. Explicitly whitelist algorithms: algorithms=['RS256'] or ['HS256'].\n"
            "3. Reject any token whose header contains alg:none before verification.\n"
            "4. Use a hardened JWT library (Auth0 java-jwt ≥4, JJWT ≥0.12) with secure defaults."
        ),
        "alg_hs256_rsa": (
            "1. Use asymmetric algorithms (RS256, ES256) with separate private/public key pairs.\n"
            "2. Never pass an RSA public key to HMAC signing/verification functions.\n"
            "3. Validate that algorithm type matches key type before verification.\n"
            "4. Store keys in Android Keystore; never embed them in source code."
        ),
        "missing_verify": (
            "1. Always specify the exact allowed algorithm(s) in decode/verify calls.\n"
            "2. Whitelist exactly one algorithm per key and reject any mismatch.\n"
            "3. Add integration tests that assert tokens with wrong algorithms are rejected.\n"
            "4. Enable strict mode in your JWT library if available."
        ),
        "jwk_mismatch": (
            "1. Validate JWK 'kty' matches the algorithm family before use.\n"
            "   RSA keys → RS256/RS384/RS512 or PS256/PS384/PS512.\n"
            "   Symmetric keys → HS256/HS384/HS512.\n"
            "2. Reject JWKs whose kty/alg pair does not match.\n"
            "3. Use a JWK library that enforces this automatically (Nimbus JOSE+JWT ≥9)."
        ),
    }

    def _make_finding(
        self,
        match: _Match,
        attacker_ctrl: bool,
        severity: Severity,
    ) -> Finding:
        ctx = self._context
        rel_path = (
            match.file_path.relative_to(ctx.workspace)
            if ctx.workspace in match.file_path.parents
            else match.file_path
        )
        desc = self._DESCRIPTIONS.get(match.vuln_type, "JWT algorithm confusion vulnerability.")
        if attacker_ctrl and match.vuln_type != "alg_none":
            desc += " The algorithm header appears to be attacker-controlled, making this immediately exploitable."

        title = match.vuln_type.replace("_", " ").title()
        return Finding(
            agent_id=self.AGENT_ID,
            session_id=ctx.session_id,
            vuln_class=f"JWT Algorithm Confusion — {title}",
            severity=severity,
            confidence=match.confidence,
            evidence={
                "file": str(rel_path),
                "line": match.line_number,
                "vulnerability_type": match.vuln_type,
                "matched_text": match.matched_text,
                "algorithm_value": match.algorithm_value,
                "key_type": match.key_type,
                "attacker_controlled": attacker_ctrl,
                "context": match.context_window[:500],
            },
            owasp="M5",
            masvs="MASVS-AUTH-2",
            compliance_tags=["CWE-287", "CWE-347"],
            recommendation=self._REMEDIATION.get(match.vuln_type, "Validate JWT algorithms strictly."),
            severity_rationale=desc,
            code_snippet={
                "file": str(rel_path),
                "line": match.line_number,
                "content": match.context_window[:1000],
            },
        )
