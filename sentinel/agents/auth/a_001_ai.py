"""A_001 Hardcoded Credentials — AI-Autonomous Version.

Rules cast a wide net (high recall). LLM decides if each hit is a real
secret vs a placeholder, test constant, or commented-out example.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.ai_autonomous_agent import AIAutonomousAgent, Candidate
from sentinel.core.scan_context import ScanContext
from sentinel.llm.vulnerability_analyzer import LLMVulnerabilityAnalyzer
from sentinel.memory.interface import MemoryInterface

_TEST_PATH_RE = re.compile(r"[Tt]est|[Mm]ock|[Ff]ake|[Ss]tub")

# Broad patterns — intentionally high-recall; FP elimination is the LLM's job
_FAST_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    # (pattern, rule_name, rule_confidence)
    (
        re.compile(r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}", re.MULTILINE),
        "A_001",
        0.98,
    ),
    (
        re.compile(r"AIza[0-9A-Za-z_\-]{35}", re.MULTILINE),
        "A_001",
        0.98,
    ),
    (
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b", re.MULTILINE),
        "A_001",
        0.97,
    ),
    (
        re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{36,}\b", re.MULTILINE),
        "A_001",
        0.97,
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", re.MULTILINE),
        "A_001",
        0.99,
    ),
    (
        re.compile(
            r'(?i)(?:api[_-]?key|apikey|x-api-key|secret|password|token)'
            r'\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',
            re.MULTILINE,
        ),
        "A_001",
        0.65,
    ),
    (
        re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})", re.MULTILINE),
        "A_001",
        0.70,
    ),
]

_CTX_LINES = 15


class A001AIHardcodedCredsAgent(AIAutonomousAgent):
    """A_001 rebuilt as AI-autonomous: rules suggest, LLM decides."""

    AGENT_ID = "A_015"
    VULN_CLASS = "Hardcoded Credentials"

    def __init__(
        self,
        context: ScanContext,
        memory: MemoryInterface,
        config: dict[str, Any] | None = None,
        *,
        llm_analyzer: LLMVulnerabilityAnalyzer | None = None,
    ) -> None:
        super().__init__(context, memory, config, llm_analyzer=llm_analyzer)

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            (ctx.decompiled_dir and ctx.decompiled_dir.exists())
            or (ctx.resources_dir and ctx.resources_dir.exists())
        )

    async def fast_pre_filter(self, ctx: ScanContext) -> list[Candidate]:
        source_root = ctx.decompiled_dir
        if not source_root or not source_root.exists():
            return []

        candidates: list[Candidate] = []
        seen: set[str] = set()

        for source_file in source_root.rglob("*.java"):
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
