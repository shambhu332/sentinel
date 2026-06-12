"""LOGIC_001 — Temporal logic + hidden debug-mode detector.

Two related patterns:

1. **Hardcoded date comparisons** — `if (currentTime > Date(2025-01-01))`
   or its long-millis equivalent. These are usually one of:
     - free-trial cut-offs that flip the app into a paid state
     - kill-switches that disable the app after a date
     - feature flags that turn on without server input
   All three are client-side trust boundaries an attacker can flip.

2. **Hidden debug modes triggered by magic strings** — `if
   (input.equals("DEBUG_MODE_ON"))`, secret long-press codes,
   developer-mode passphrases. These ship in production builds and
   give attackers a backdoor that wasn't documented.
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# ISO-style date literal in a comparison context. We anchor on the
# comparison operator so a bare "2025-01-01" in a comment doesn't fire.
_DATE_CMP_RE = re.compile(
    r"(?:<|>|<=|>=|==|!=)\s*[\"']?(\d{4})-(\d{2})-(\d{2})"
)
# Java `long` millis literal that looks like an Epoch in the 1.7e12 range
# (Jan 2024 onward) used in a comparison. We require an `L` suffix to
# distinguish "true millis" from random 13-digit integers.
_EPOCH_CMP_RE = re.compile(
    r"(?:<|>|<=|>=|==|!=)\s*(\d{13})L\b"
)

# Magic-string trigger patterns. These compare a runtime variable
# against an obviously-not-user-facing string literal.
_DEBUG_TRIGGER_RE = re.compile(
    r"\.equals\s*\(\s*\"("
    r"DEBUG[_A-Z0-9]{2,}|"
    r"DEV[_A-Z0-9]{2,}|"
    r"INTERNAL[_A-Z0-9]{2,}|"
    r"UNLOCK[_A-Z0-9]{2,}|"
    r"BACKDOOR[_A-Z0-9]{0,}|"
    r"SUPER[_A-Z0-9]{3,}|"
    r"GODMODE[_A-Z0-9]{0,}"
    r")\"\s*\)"
)

_MAX_FILES = 2000


class TemporalLogicAgent(BaseAgent):
    """LOGIC_001: hardcoded date checks + magic-string backdoors."""

    AGENT_ID = "LOGIC_001"
    VULN_CLASS = "Temporal / Hidden-Mode Logic"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(root))

            for m in _DATE_CMP_RE.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append(self._make_finding(
                    vuln_class="Hardcoded Date Comparison",
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    recommendation=(
                        "A hardcoded calendar date appears in a comparison. "
                        "Trial timers, kill-switches, and feature flags that "
                        "rely on local time can be bypassed by setting the "
                        "device clock or hooking System.currentTimeMillis. "
                        "Move the gate to the server."
                    ),
                    evidence={
                        "file": rel,
                        "line": line_no,
                        "date": f"{m.group(1)}-{m.group(2)}-{m.group(3)}",
                        "snippet": text[max(0, m.start()-40):m.end()+40].strip(),
                    },
                ))

            for m in _EPOCH_CMP_RE.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append(self._make_finding(
                    vuln_class="Hardcoded Epoch-Millis Comparison",
                    severity=Severity.LOW,
                    confidence=0.55,
                    recommendation=(
                        "A 13-digit Java long literal is being compared in a "
                        "branch — likely a hardcoded epoch timestamp. Same "
                        "risk profile as a calendar-date comparison."
                    ),
                    evidence={
                        "file": rel,
                        "line": line_no,
                        "epoch_ms": m.group(1),
                    },
                ))

            for m in _DEBUG_TRIGGER_RE.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append(self._make_finding(
                    vuln_class="Hidden Debug-Mode Trigger",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    recommendation=(
                        "A string-equality check against a hardcoded "
                        "DEBUG/DEV/UNLOCK-style token is shipped in the "
                        "release APK. Anyone who decompiles the binary "
                        "(takes ~30s with jadx) gets the backdoor token. "
                        "Strip debug-only branches from release builds; "
                        "if a runtime override is needed, gate it on a "
                        "signed token from your backend."
                    ),
                    evidence={
                        "file": rel,
                        "line": line_no,
                        "trigger": m.group(1),
                    },
                ))

        return findings


__all__ = ["TemporalLogicAgent"]
