"""A_002 JWT Algorithm Confusion — AI-Autonomous Version.

Rules identify JWT-related code patterns. LLM verifies whether each hit
is actually exploitable vs a test, comment, or already-mitigated path.
"""
from __future__ import annotations

import re
from typing import Any

from sentinel.agents.base.ai_autonomous_agent import AIAutonomousAgent, Candidate
from sentinel.core.scan_context import ScanContext
from sentinel.llm.vulnerability_analyzer import LLMVulnerabilityAnalyzer
from sentinel.memory.interface import MemoryInterface

_TEST_PATH_RE = re.compile(r"[Tt]est|[Mm]ock|[Ff]ake|[Ss]tub")

_FAST_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"Algorithm\.none\s*\(\s*\)", re.IGNORECASE),
        "A_002",
        0.95,
    ),
    (
        re.compile(r'(?:\\?["\'])alg(?:\\?["\'])\s*:\s*(?:\\?["\'])none(?:\\?["\'])', re.IGNORECASE),
        "A_002",
        0.90,
    ),
    (
        re.compile(r"algorithms?\s*=\s*\[?\s*['\"]none['\"]", re.IGNORECASE),
        "A_002",
        0.92,
    ),
    (
        re.compile(r"Jwts\.parser\s*\(\s*\)\s*[^;]*\.parseClaimsJwt\b", re.IGNORECASE),
        "A_002",
        0.90,
    ),
    (
        re.compile(
            r"Algorithm\.HMAC256\s*\([^)]*(?:RSAPublicKey|publicKey|rsa|PublicKey)[^)]*\)",
            re.IGNORECASE,
        ),
        "A_002",
        0.88,
    ),
    (
        re.compile(
            r"RSAPublicKey\s+(\w+)\b.{0,300}Algorithm\.HMAC256\s*\(\s*\1\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "A_002",
        0.85,
    ),
    (
        re.compile(r"\bJWT\.decode\s*\(\s*[^)]+\)", re.IGNORECASE),
        "A_002",
        0.70,
    ),
    (
        re.compile(
            r'["\']kty["\']\s*:\s*["\']RSA["\'][^}]{0,200}["\']alg["\']\s*:\s*["\']HS',
            re.IGNORECASE | re.DOTALL,
        ),
        "A_002",
        0.85,
    ),
]

_CTX_LINES = 15


class A002AIJWTAlgConfusionAgent(AIAutonomousAgent):
    """A_002 rebuilt as AI-autonomous: rules suggest, LLM decides."""

    AGENT_ID = "A_002"
    VULN_CLASS = "JWT Algorithm Confusion"

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
        *,
        llm_analyzer: LLMVulnerabilityAnalyzer | None = None,
    ) -> None:
        super().__init__(context, memory, config, llm_analyzer=llm_analyzer)

    async def fast_pre_filter(self, ctx: ScanContext) -> list[Candidate]:
        source_root = ctx.decompiled_dir
        if not source_root or not source_root.exists():
            return []

        candidates: list[Candidate] = []
        seen: set[str] = set()

        for source_file in list(source_root.rglob("*.java")) + list(source_root.rglob("*.kt")):
            rel = source_file.relative_to(source_root)
            if _TEST_PATH_RE.search(str(rel)):
                continue
            try:
                content = source_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for pat, rule, confidence in _FAST_PATTERNS:
                for m in pat.finditer(content):
                    line_num = content[: m.start()].count("\n") + 1
                    dedup_key = f"{source_file}:{line_num}:{rule}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    lines = content.split("\n")
                    start = max(0, line_num - _CTX_LINES)
                    end = min(len(lines), line_num + _CTX_LINES)
                    ctx_window = "\n".join(lines[start:end])

                    candidates.append(Candidate(
                        code_snippet=m.group(0)[:300],
                        file_path=str(source_file.relative_to(ctx.workspace)),
                        line_number=line_num,
                        column=m.start() - content.rfind("\n", 0, m.start()),
                        rule_triggered=rule,
                        rule_confidence=confidence,
                        context_window=ctx_window,
                    ))

        return candidates
