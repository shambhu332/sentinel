"""P_001 Deep Link Hijack Detection — AI-Autonomous Version.

Detects exported deep link handlers that may be vulnerable to hijacking
by scanning AndroidManifest.xml and Java source files.
"""
from __future__ import annotations

import re
from typing import Any

from sentinel.agents.base.ai_autonomous_agent import AIAutonomousAgent, Candidate
from sentinel.core.scan_context import ScanContext
from sentinel.llm.vulnerability_analyzer import LLMVerdict, LLMVulnerabilityAnalyzer
from sentinel.memory.interface import MemoryInterface

_TEST_PATH_RE = re.compile(r"[Tt]est|[Mm]ock|[Ff]ake|[Ss]tub")

_DEEPLINK_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r'android:exported\s*=\s*["\']true["\']'), 0.85),
    (re.compile(r'android\.intent\.action\.VIEW'), 0.85),
    (re.compile(r'android\.intent\.category\.BROWSABLE'), 0.85),
    (re.compile(r'android:scheme\s*=\s*["\']https?["\']'), 0.85),
]

_JAVA_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r'getIntent\(\).*getData\(\)', re.DOTALL), 0.85),
    (re.compile(r'getIntent\(\)\.getData\(\)'), 0.85),
]

_CTX_LINES = 10


class P001DeepLinkHijackAgent(AIAutonomousAgent):
    """P_001: Detects exported deep link handlers — rules flag, LLM confirms."""

    AGENT_ID = "P_001"
    VULN_CLASS = "Exported Deep Link Handler"

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

        # Scan .java files for getIntent().getData() patterns
        for source_file in source_root.rglob("*.java"):
            rel = str(source_file.relative_to(source_root))
            if _TEST_PATH_RE.search(rel):
                continue

            try:
                content = source_file.read_text(errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for pattern, confidence in _JAVA_PATTERNS:
                for match in pattern.finditer(content):
                    line_no = content[: match.start()].count("\n") + 1
                    start = max(0, line_no - 6)
                    end = min(len(lines), line_no + 5)
                    context_window = "\n".join(lines[start:end])

                    candidates.append(Candidate(
                        code_snippet=match.group(0)[:300],
                        file_path=str(source_file),
                        line_number=line_no,
                        column=match.start() - content.rfind("\n", 0, match.start()) - 1,
                        rule_triggered=self.AGENT_ID,
                        rule_confidence=confidence,
                        context_window=context_window,
                    ))

        # Scan AndroidManifest.xml
        manifest_path = ctx.workspace / "AndroidManifest.xml"
        if not manifest_path.exists():
            for candidate_path in ctx.workspace.rglob("AndroidManifest.xml"):
                manifest_path = candidate_path
                break

        if manifest_path.exists():
            try:
                content = manifest_path.read_text(errors="replace")
                lines = content.splitlines()
                for pattern, confidence in _DEEPLINK_PATTERNS:
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

    def _dynamic_target_for_candidate(
        self,
        candidate: Candidate,
        verdict: LLMVerdict,
    ) -> dict[str, str] | None:
        """Emit machine-readable runtime target data; never proof commands."""
        del candidate, verdict
        manifest = self._context.manifest or {}
        for entry in manifest.get("deep_links") or []:
            activity = str(entry.get("activity") or "")
            for data in entry.get("data_elements") or []:
                scheme = str(data.get("scheme") or "").strip()
                if not scheme:
                    continue
                host = str(data.get("host") or "showPage").strip().lstrip("/")
                return {
                    "type": "deep_link",
                    "scheme": scheme,
                    "host": host or "showPage",
                    "params": "url=https%3A%2F%2F10.11.3.1%2F",
                    "target_component": activity,
                }
        return None
