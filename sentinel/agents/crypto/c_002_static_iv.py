"""C_002 Static IV Detection — AI-Autonomous Version.

Detects use of static or predictable IVs in AES-CBC and similar modes,
which breaks semantic security guarantees.
"""
from __future__ import annotations

import re
from typing import Any

from sentinel.agents.base.ai_autonomous_agent import AIAutonomousAgent, Candidate
from sentinel.core.scan_context import ScanContext
from sentinel.llm.vulnerability_analyzer import LLMVulnerabilityAnalyzer
from sentinel.memory.interface import MemoryInterface

_TEST_PATH_RE = re.compile(r"[Tt]est|[Mm]ock|[Ff]ake|[Ss]tub")

# (pattern, rule_confidence)
_IV_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r'static\s+(?:final\s+)?byte\s*\[\]\s+\w*[Ii][Vv]\w*\s*='), 0.90),
    (re.compile(r'new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\['), 0.88),  # all-zero IV
    (re.compile(r'IvParameterSpec\s*\(\s*["\'][0-9a-fA-F]{16,}["\']'), 0.75),  # hex literal
]

_CTX_LINES = 10


class C002StaticIVAgent(AIAutonomousAgent):
    """C_002: Detects static/predictable IVs — rules flag, LLM confirms."""

    AGENT_ID = "C_002"
    VULN_CLASS = "Static or Predictable IV"

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

        for source_file in source_root.rglob("*.java"):
            rel = str(source_file.relative_to(source_root))
            if _TEST_PATH_RE.search(rel):
                continue

            try:
                content = source_file.read_text(errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for pattern, confidence in _IV_PATTERNS:
                for match in pattern.finditer(content):
                    line_no = content[: match.start()].count("\n") + 1
                    start = max(0, line_no - 6)
                    end = min(len(lines), line_no + 5)
                    context_window = "\n".join(lines[start:end])

                    candidates.append(Candidate(
                        code_snippet=match.group(0),
                        file_path=str(source_file),
                        line_number=line_no,
                        column=match.start() - content.rfind("\n", 0, match.start()) - 1,
                        rule_triggered=self.AGENT_ID,
                        rule_confidence=confidence,
                        context_window=context_window,
                    ))

        candidates.sort(key=lambda c: c.rule_confidence, reverse=True)
        return candidates[:50]
