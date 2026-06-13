"""D_055 — Native heap monitor (Dynamic Testing Target)."""
from __future__ import annotations
import logging
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class NativeHeapAgent(BaseAgent):
    AGENT_ID = "D_055"
    VULN_CLASS = "Native Heap Memory-Safety Probe (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.app_profile.get("native_libs_info", {}).get("count", 0))

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        native_info = ctx.app_profile.get("native_libs_info") or {}
        libs = native_info.get("libs") or []
        if not libs:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=0.70,
            recommendation=(
                f"{native_info.get('count', 0)} native .so libraries shipped. "
                "The Frida hook will register a MemoryAccessMonitor over "
                "each library's writable segments, hook SIGSEGV via "
                "Process.setExceptionHandler, and report any buffer "
                "overflows or use-after-free triggered during the scan "
                "window. Rebuild affected libraries with -fsanitize=address "
                "before triaging — the report gives you the crash address "
                "but not the source-level cause."
            ),
            evidence={
                "native_lib_count": native_info.get("count", 0),
                "libs": libs[:20],
                "dynamic_target": True,
                "frida_payload": {
                    "monitor_segments": "writable",
                    "hook_signals": ["SIGSEGV", "SIGABRT", "SIGBUS"],
                    "capture_stack_frames": 20,
                    "window_seconds": 60,
                    "safety_budget": {
                        "max_actions_total": 1,
                        "max_actions_per_sec": 0.1,
                        "wall_clock_budget_s": 120,
                        "max_consecutive_crashes": 3,
                    },
                },
            },
        )]


__all__ = ["NativeHeapAgent"]
