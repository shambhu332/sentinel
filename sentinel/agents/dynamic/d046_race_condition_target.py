"""D_046 — Race-condition target identifier (+ Frida trigger payload).

Pure SAST: walks decompiled Java for methods whose *names* and
*shape* identify them as classic Android TOCTOU candidates. The win
condition for the static side is two-part:

  1. The method's identifier matches a critical-action regex
     (updateBalance, withdraw, claimReward, redeem, transfer, etc.).
  2. The method's body performs a read-modify-write on a field or
     resource (`balance = balance + x`, `decrement(currentX)`,
     `update(rs.next())`) WITHOUT one of the recognised
     synchronisation primitives (`synchronized`, `AtomicInteger`,
     `AtomicReference`, `Lock`, `ReentrantLock`, `compareAndSet`,
     `Mutex`, `volatile`).

We do not actually race the method here — that's a runtime concern.
Instead, every match is emitted with `dynamic_target: True` plus a
ready-to-paste Frida snippet under `evidence.frida_payload`. The
DAST orchestrator picks these up and the standard Frida agent
injects N parallel calls during Phase 4.5.

This split keeps the SAST pass deterministic (no device required)
while still producing the actionable handoff the spec asks for.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Names that scream "TOCTOU candidate"
_CRITICAL_NAME_RE = re.compile(
    r"\b(update|set|add|sub|decrement|increment|redeem|"
    r"claim|withdraw|deposit|transfer|charge|refund|grant|consume|spend|"
    r"award|credit|debit|burn|mint|stake|unstake)"
    r"(Balance|Wallet|Coins?|Score|Points?|Stars?|Lives?|Credits?|Tokens?|"
    r"Bonus|Reward|Tickets?|Inventory|Quantity|Stock)",
    re.IGNORECASE,
)

# Synchronisation primitives — presence inside the same method body
# disqualifies the method from the candidate list.
_SYNC_TOKENS = (
    "synchronized", "AtomicInteger", "AtomicLong", "AtomicReference",
    "AtomicBoolean", "compareAndSet", "Lock", "ReentrantLock",
    "ReadWriteLock", "Mutex", "volatile",
)

# Read-modify-write evidence inside method bodies
_RMW_RE = re.compile(
    r"\b(\w+)\s*=\s*\1\s*[+\-*/]\s*"
    r"|\b(\w+)\s*[+\-]?=\s*(\w+)\s*"
    r"|--\s*(\w+)\s*\b"
    r"|\+\+\s*(\w+)\s*\b"
)

_METHOD_HEAD_RE = re.compile(
    r"(public|private|protected|static|synchronized|final|\s)+\s*"
    r"(?:[\w<>,\s]+\s+)?(\w+)\s*\(([^)]*)\)\s*"
    r"(?:throws\s+[\w,\s]+)?\s*\{"
)

_MAX_FILES = 2000


class RaceConditionTargetAgent(BaseAgent):
    """D_046: enumerate TOCTOU candidates + emit Frida trigger payload."""

    AGENT_ID = "D_046"
    VULN_CLASS = "Race-Condition Candidate (Dynamic Testing Target)"
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
            if not _CRITICAL_NAME_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            class_name = path.stem.split("$")[0]
            findings.extend(self._scan_class(text, rel, class_name))
        return findings

    # ---------- per-class ----------

    def _scan_class(
        self, text: str, rel: str, class_name: str,
    ) -> list[Finding]:
        out: list[Finding] = []
        for m in _METHOD_HEAD_RE.finditer(text):
            method = m.group(2)
            params = m.group(3).strip()
            if not _CRITICAL_NAME_RE.search(method):
                continue
            body = self._extract_body(text, m.end() - 1)
            if not body:
                continue
            # Check the method head + body together — `synchronized` and
            # `volatile` modifiers live in the head, not the body.
            head_plus_body = m.group(0) + body
            if self._has_synchronisation(head_plus_body):
                continue
            if not _RMW_RE.search(body):
                continue
            line_no = text[:m.start()].count("\n") + 1
            payload = self._build_frida_payload(class_name, method, params)
            out.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.65,
                recommendation=(
                    f"`{class_name}.{method}` reads-modifies-writes state "
                    "with no visible synchronisation. The Frida agent will "
                    "trigger it N times concurrently in the DAST phase and "
                    "watch for inconsistent terminal state. Fix server-side "
                    "by enforcing idempotency keys; if the operation must "
                    "stay client-only, wrap in `AtomicInteger.compareAndSet` "
                    "or a `synchronized` block."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "method": method,
                    "params": params,
                    "line": line_no,
                    "dynamic_target": True,
                    "frida_payload": payload,
                    "n_parallel_default": 10,
                },
            ))
        return out

    @staticmethod
    def _extract_body(text: str, brace_idx: int) -> str:
        if brace_idx >= len(text) or text[brace_idx] != "{":
            return ""
        depth = 1
        i = brace_idx + 1
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        return text[brace_idx + 1: i - 1]

    @staticmethod
    def _has_synchronisation(body: str) -> bool:
        return any(tok in body for tok in _SYNC_TOKENS)

    @staticmethod
    def _build_frida_payload(
        class_name: str, method: str, params: str,
    ) -> dict[str, Any]:
        """Return a structured payload the Frida agent can paste into a hook.

        The actual TypeScript template lives under
        `frida_agent/src/hooks/d046_race_trigger.ts`. Here we provide
        the binding info the trigger script needs.
        """
        # Crude param-type extraction so the Frida hook can call the
        # overload deterministically.
        param_types: list[str] = []
        for raw in params.split(","):
            raw = raw.strip()
            if not raw:
                continue
            # "Foo bar" -> "Foo"
            t = raw.split()[0]
            param_types.append(t)
        return {
            "class_simple_name": class_name,
            "method_name": method,
            "param_types": param_types,
            # User of the Frida hook fills these in from observed call sites
            "args_template": [f"<{t}>" for t in param_types],
            "n_parallel": 10,
            "interval_ms": 0,
            "frida_script_hint":
                f"// auto-generated trigger stub for {class_name}.{method}\n"
                f"Java.perform(() => {{\n"
                f"  const Cls = Java.use('{class_name}');\n"
                f"  const m = Cls.{method}.overload({', '.join(repr(t) for t in param_types)});\n"
                f"  for (let i = 0; i < 10; i++) {{\n"
                f"    setTimeout(() => Cls.$new ? m.apply(Cls.$new(), [/* args */]) : null, 0);\n"
                f"  }}\n"
                f"}});\n",
        }


__all__ = ["RaceConditionTargetAgent"]
