"""N_001 Cleartext HTTP Detection — AI-Autonomous Version.

Detects cleartext HTTP transmission in Android apps by scanning both
Java source files and AndroidManifest.xml.
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
_HTTP_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r'usesCleartextTraffic\s*=\s*["\']true["\']'), 0.95),
    (re.compile(r'new\s+URL\s*\(\s*["\']http://(?!localhost)'), 0.85),
    (re.compile(r'baseUrl\s*\(\s*["\']http://'), 0.85),
    (re.compile(r'ConnectionSpec\.CLEARTEXT'), 0.85),
]

_CTX_LINES = 10


class N001CleartextHTTPAgent(AIAutonomousAgent):
    """N_001: Detects cleartext HTTP usage — rules flag, LLM confirms."""

    AGENT_ID = "N_016"
    VULN_CLASS = "Cleartext HTTP Transmission"

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

        # Scan .java files
        for source_file in source_root.rglob("*.java"):
            rel = str(source_file.relative_to(source_root))
            if _TEST_PATH_RE.search(rel):
                continue

            try:
                content = source_file.read_text(errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for pattern, confidence in _HTTP_PATTERNS:
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

        # Scan AndroidManifest.xml in workspace
        manifest_path = ctx.workspace / "AndroidManifest.xml"
        if not manifest_path.exists():
            # Try common decompilation paths
            for candidate_path in ctx.workspace.rglob("AndroidManifest.xml"):
                manifest_path = candidate_path
                break

        if manifest_path.exists():
            try:
                content = manifest_path.read_text(errors="replace")
                lines = content.splitlines()
                for pattern, confidence in _HTTP_PATTERNS:
                    for match in pattern.finditer(content):
                        line_no = content[: match.start()].count("\n") + 1
                        start = max(0, line_no - 6)
                        end = min(len(lines), line_no + 5)
                        context_window = "\n".join(lines[start:end])

                        candidates.append(Candidate(
                            code_snippet=match.group(0),
                            file_path=str(manifest_path),
                            line_number=line_no,
                            column=match.start() - content.rfind("\n", 0, match.start()) - 1,
                            rule_triggered=self.AGENT_ID,
                            rule_confidence=confidence,
                            context_window=context_window,
                        ))
            except OSError:
                pass

        candidates.sort(key=lambda c: c.rule_confidence, reverse=True)
        return candidates[:50]
