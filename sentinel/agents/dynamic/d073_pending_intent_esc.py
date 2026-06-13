"""D_073 — PendingIntent privilege-escalation probe target.

Static half of the hybrid DAST flow:

* find ``PendingIntent.getActivity/getService/getBroadcast`` call sites
  in decompiled Java;
* flag call sites whose flags expression does not assert
  ``FLAG_IMMUTABLE``;
* emit a bounded Frida payload that the runtime hook can use to probe
  mutability safely when ``PendingIntent.send(...)`` is observed.

This intentionally complements D_021. D_021 passively classifies
runtime factory calls from Frida events. D_073 starts earlier: it
identifies source call sites that deserve active runtime probing.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_FILES = 1500
_MAX_FINDINGS = 100
_MAX_CALL_BYTES = 2000

_FACTORY_RE = re.compile(
    r"\bPendingIntent\s*\.\s*(getActivity|getService|getBroadcast)\s*\(",
)
_PACKAGE_RE = re.compile(r"\bpackage\s+([A-Za-z_][\w.]*);")
_CLASS_RE = re.compile(
    r"\b(?:public\s+|final\s+|abstract\s+|sealed\s+|open\s+)*"
    r"(?:class|interface|enum)\s+([A-Za-z_]\w*)",
)
_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_FLAG_IMMUTABLE_RE = re.compile(
    r"\b(?:PendingIntent\s*\.\s*)?FLAG_IMMUTABLE\b|0x0?4000000\b|67108864\b",
)


@dataclass(frozen=True)
class _PendingIntentCall:
    factory: str
    flags_expr: str
    line: int
    code: str


class PendingIntentEscalationAgent(BaseAgent):
    """D_073: flag mutable/unspecified PendingIntent call sites for DAST."""

    AGENT_ID = "D_073"
    VULN_CLASS = "PendingIntent Privilege Escalation Probe"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        if root is None:
            return []

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES or len(findings) >= _MAX_FINDINGS:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "PendingIntent.get" not in text:
                continue

            class_name = _class_name(path, text)
            rel = str(path.relative_to(root))
            for call in _find_pending_intent_calls(text):
                if _FLAG_IMMUTABLE_RE.search(call.flags_expr):
                    continue
                findings.append(self._finding(rel, class_name, call))
                if len(findings) >= _MAX_FINDINGS:
                    break
        return findings

    def _finding(
        self,
        rel_path: str,
        class_name: str,
        call: _PendingIntentCall,
    ) -> Finding:
        payload = _build_payload(class_name)
        explicit_mutable = "FLAG_MUTABLE" in call.flags_expr
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.82 if explicit_mutable else 0.74,
            recommendation=(
                "Use PendingIntent.FLAG_IMMUTABLE for this factory call. "
                "If a mutable PendingIntent is required for RemoteInput or "
                "notification replies, keep the inner Intent explicit "
                "(fixed component/action/data) and validate every extra key "
                "consumed by the receiver before performing privileged work."
            ),
            evidence={
                "file": rel_path,
                "class_name": class_name,
                "factory": call.factory,
                "line": call.line,
                "flags_expr": call.flags_expr,
                "explicit_mutable": explicit_mutable,
                "dynamic_target": True,
                "frida_payload": payload,
                "code": call.code[:500],
            },
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        )


def _find_pending_intent_calls(text: str) -> list[_PendingIntentCall]:
    cleaned = _BLOCK_COMMENT_RE.sub("", _LINE_COMMENT_RE.sub("", text))
    calls: list[_PendingIntentCall] = []
    for match in _FACTORY_RE.finditer(cleaned):
        args, end = _extract_call_args(cleaned, match.end() - 1)
        if args is None:
            continue
        parts = _split_top_level_args(args)
        if len(parts) < 4:
            continue
        factory = match.group(1)
        flags_expr = parts[3].strip()
        line = cleaned.count("\n", 0, match.start()) + 1
        code = cleaned[match.start():min(end + 1, match.start() + _MAX_CALL_BYTES)]
        calls.append(_PendingIntentCall(
            factory=factory,
            flags_expr=flags_expr,
            line=line,
            code=" ".join(code.split()),
        ))
    return calls


def _extract_call_args(text: str, open_paren: int) -> tuple[str | None, int]:
    depth = 0
    in_string: str | None = None
    escaped = False
    start = open_paren + 1
    for idx in range(open_paren, min(len(text), open_paren + _MAX_CALL_BYTES)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in {"'", '"'}:
            in_string = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:idx], idx
    return None, open_paren


def _split_top_level_args(args: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    depth = 0
    in_string: str | None = None
    escaped = False
    for ch in args:
        if in_string:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in {"'", '"'}:
            in_string = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        out.append("".join(current).strip())
    return out


def _class_name(path: Path, text: str) -> str:
    package = ""
    if match := _PACKAGE_RE.search(text):
        package = match.group(1)
    class_name = path.stem.split("$")[0]
    if match := _CLASS_RE.search(text):
        class_name = match.group(1)
    return f"{package}.{class_name}" if package else class_name


def _build_payload(class_name: str) -> dict[str, Any]:
    return {
        "type": "pending_intent_probe",
        "class_name": class_name,
        "probe_extra_key": "sentinel_probe",
        "probe_extra_value": "SENTINEL_PROBE",
        "safety_budget": {
            "max_actions_total": 20,
            "max_actions_per_sec": 5,
            "wall_clock_budget_s": 30,
            "max_consecutive_crashes": 3,
        },
    }


__all__ = ["PendingIntentEscalationAgent"]
