"""D_070 — Picture-in-Picture clickjacking (Dynamic Testing Target)."""
from __future__ import annotations
import logging
import re
from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_PIP_API_RE = re.compile(
    r"\benterPictureInPictureMode\b|\bPictureInPictureParams\b"
    r"|android:supportsPictureInPicture=\"true\""
)


class PipSpyAgent(BaseAgent):
    AGENT_ID = "D_070"
    VULN_CLASS = "Picture-in-Picture Clickjack (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            (self._context.decompiled_dir and self._context.decompiled_dir.exists())
            or (self._context.resources_dir and self._context.resources_dir.exists())
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        pip_files: set[str] = set()
        # Java code
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            scanned = 0
            for path in ctx.decompiled_dir.rglob("*.java"):
                scanned += 1
                if scanned > 2000:
                    break
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _PIP_API_RE.search(text):
                    pip_files.add(str(path.relative_to(ctx.decompiled_dir)))
        # Manifest declaration
        pip_in_manifest = False
        for act in (ctx.manifest or {}).get("activities", []) or []:
            if isinstance(act, dict) and act.get("supports_pip"):
                pip_in_manifest = True
                break
        if not pip_files and not pip_in_manifest:
            return []
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.MEDIUM,
            confidence=0.60,
            recommendation=(
                f"{len(pip_files)} PiP-enabled call site(s); "
                f"manifest-level supportsPictureInPicture: {pip_in_manifest}. "
                "The Frida hook will enter PiP mode and overlay a "
                "transparent button on top of the small window to test "
                "for tap-jacking. Reject touch events on minimized PiP "
                "windows; do not allow background touch passthrough."
            ),
            evidence={
                "pip_files": sorted(pip_files)[:10],
                "pip_in_manifest": pip_in_manifest,
                "dynamic_target": True,
                "frida_payload": {
                    "hook_target": "android.app.Activity.enterPictureInPictureMode",
                    "overlay_test": True,
                    "safety_budget": {
                        "max_actions_total": 5,
                        "max_actions_per_sec": 1,
                        "wall_clock_budget_s": 30,
                        "max_consecutive_crashes": 2,
                    },
                },
            },
        )]


__all__ = ["PipSpyAgent"]
