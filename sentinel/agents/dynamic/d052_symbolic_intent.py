"""D_052 — Symbolic Intent solver.

Builds a tiny intra-procedural symbolic-execution pass over decompiled
`onReceive` / `onCreate` / `onStartCommand` bodies. For every
conditional that reads an Intent extra via
`intent.getString(...)`, `getStringExtra(...)`, `getBoolean(...)`,
`getInt(...)`, etc., we collect a symbolic constraint. When a target
sink (e.g. `startActivity`, `setPremium(true)`, `grantAccess(...)`)
appears inside a guarded branch, we ask z3 for a satisfying extras
assignment that *reaches* that sink.

This isn't a full symbolic executor — it does not unroll loops, model
the heap, or chase virtual dispatch. It is intentionally narrow:
"given these visible if-conditions on Intent extras, what extras
reach the sink?". That covers the most common Android auth-bypass
shape:

    if (intent.getBooleanExtra("isPremium", false)) {
        grantAccess();          // <- sink
    }

Output is a structured proof: `{extras: {"isPremium": True}}` plus
the file + line of the sink, emitted with `dynamic_target: True` so
the Frida runtime layer can fire the corresponding broadcast / start
the activity with that extras bag.

Graceful degradation:
  * z3-solver missing  → agent disables itself with a single info log.
  * Java parse failure → that file is skipped, scan continues.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Intent-extras getter patterns — captures (var, key, default-ish).
_GETTERS: list[tuple[str, re.Pattern]] = [
    ("bool", re.compile(
        r"(\w+)\s*=\s*\w*intent\w*\s*\.\s*getBooleanExtra\s*\(\s*"
        r'"([^"]+)"\s*,\s*(true|false)\s*\)',
        re.IGNORECASE,
    )),
    ("int", re.compile(
        r"(\w+)\s*=\s*\w*intent\w*\s*\.\s*getIntExtra\s*\(\s*"
        r'"([^"]+)"\s*,\s*(-?\d+)\s*\)',
        re.IGNORECASE,
    )),
    ("string", re.compile(
        r"(\w+)\s*=\s*\w*intent\w*\s*\.\s*getStringExtra\s*\(\s*"
        r'"([^"]+)"\s*\)',
        re.IGNORECASE,
    )),
]

# Sink patterns inside guarded branches — these are the win condition.
_SINKS: list[tuple[str, re.Pattern]] = [
    ("startActivity",   re.compile(r"\bstartActivity\s*\(")),
    ("grantPermission", re.compile(
        r"\b(grant\w*|set(Admin|Premium|Debug|Vip|Unlocked|Authorised)\w*|"
        r"unlock\w*|enableDebug|makeAdmin|elevate\w*|promote\w*)\s*\("
    )),
    ("logout",          re.compile(r"\blogout\s*\(")),
    ("exec",            re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")),
]

# Comparison patterns inside guards (very limited)
# var == "value"  /  var.equals("value")
# Guard-shape regexes moved to sentinel.symbolic.solver.

_MAX_FILES = 1500
_RECEIVER_RE = re.compile(
    r"public\s+void\s+(onReceive|onCreate|onStartCommand)\s*\("
)


class SymbolicIntentAgent(BaseAgent):
    """D_052: solve for Intent extras that satisfy guarded sinks."""

    AGENT_ID = "D_052"
    VULN_CLASS = "Reachable Intent Auth-Bypass Path"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        try:
            from z3 import (  # noqa: F401  (presence check only)
                Bool,
                BoolVal,
                Int,
                Solver,
                String,
                sat,
            )
        except ImportError:
            logger.info(
                "[D_052] z3-solver not installed — symbolic intent disabled. "
                "pip install z3-solver to enable."
            )
            return []

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
            if "onReceive" not in text and "onStartCommand" not in text \
               and "getStringExtra" not in text and "getBooleanExtra" not in text:
                continue
            rel = str(path.relative_to(root))
            findings.extend(self._analyze_file(text, rel))
        return findings

    # ---------- per-file ----------

    def _analyze_file(self, text: str, rel: str) -> list[Finding]:
        from sentinel.symbolic import SymbolDecl, solve_constraints

        out: list[Finding] = []
        for m in _RECEIVER_RE.finditer(text):
            method = m.group(1)
            body = self._extract_body(text, m.end())
            if not body:
                continue
            # 1) Collect extras-binding map
            extras = self._collect_extras(body)
            if not extras:
                continue
            # Convert the agent's local extras shape into the shared
            # SymbolDecl shape the solver consumes.
            decls = [
                SymbolDecl(name=var, kind=kind, extras_key=key, default=default)
                for var, (kind, key, default) in extras.items()
            ]
            # 2) For each guarded sink, solve via the shared module.
            for sink_name, sink_pattern in _SINKS:
                for s_match in sink_pattern.finditer(body):
                    guards = self._extract_enclosing_guards(body, s_match.start())
                    if not guards:
                        continue
                    result = solve_constraints(decls, guards)
                    if not result.sat:
                        continue
                    line_no = (
                        text[:m.end()].count("\n")
                        + body[:s_match.start()].count("\n") + 1
                    )
                    out.append(self._make_finding(
                        vuln_class=self.VULN_CLASS,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        recommendation=(
                            f"z3 proved a sink `{sink_name}` inside "
                            f"`{method}` is reachable by sending the extras "
                            f"shown in evidence.satisfying_extras. The Frida "
                            "DAST phase will fire this exact intent to "
                            "confirm dynamically. Add a server-side check "
                            "before any privileged action triggered here."
                        ),
                        evidence={
                            "file": rel,
                            "method": method,
                            "sink": sink_name,
                            "line": line_no,
                            "satisfying_extras": result.witness,
                            "guards": guards[:5],
                            "encoded_constraints": result.encoded_constraints[:5],
                            "skipped_guards": result.skipped_guards[:5],
                            "dynamic_target": True,
                            "frida_payload": {
                                "extras": result.witness,
                                "extras_types": {
                                    decl.extras_key: decl.kind for decl in decls
                                    if decl.extras_key in result.witness
                                },
                                "target_method": method,
                                "safety_budget": {
                                    "max_actions_total": 3,
                                    "max_actions_per_sec": 1,
                                    "wall_clock_budget_s": 15,
                                    "max_consecutive_crashes": 2,
                                },
                                "frida_script_hint":
                                    "// D_052 — fire the z3-solved Intent at "
                                    "the target component\n"
                                    "// rpc.exports.symbolicintent(payload) "
                                    "is the entry\n",
                            },
                        },
                    ))
        return out

    # ---------- parsing ----------

    @staticmethod
    def _extract_body(text: str, start: int) -> str:
        """Take the brace-matched body starting just after the method head."""
        # Skip ahead to the first `{`
        open_idx = text.find("{", start)
        if open_idx < 0:
            return ""
        depth = 1
        i = open_idx + 1
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        return text[open_idx + 1: i - 1]

    @staticmethod
    def _collect_extras(body: str) -> dict[str, tuple[str, str, Any]]:
        """Return {var_name: (type, key, default)}."""
        out: dict[str, tuple[str, str, Any]] = {}
        for kind, pat in _GETTERS:
            for m in pat.finditer(body):
                var = m.group(1)
                key = m.group(2)
                default: Any = None
                if kind == "bool":
                    default = m.group(3).lower() == "true"
                elif kind == "int":
                    default = int(m.group(3))
                out[var] = (kind, key, default)
        return out

    @staticmethod
    def _extract_enclosing_guards(body: str, sink_pos: int) -> list[str]:
        """Walk backwards from `sink_pos` collecting `if (...)` heads.

        Cheap & narrow: we look for every `if (...)` whose matching
        block contains `sink_pos`. Misses `else` branches and ternary
        guards by design — those are uncommon in handler shapes.
        """
        guards: list[str] = []
        # All `if (` positions up to sink
        for m in re.finditer(r"\bif\s*\(", body[:sink_pos]):
            cond_start = m.end()
            # Match balanced parens for the condition
            depth = 1
            i = cond_start
            while i < len(body) and depth > 0:
                if body[i] == "(":
                    depth += 1
                elif body[i] == ")":
                    depth -= 1
                i += 1
            if depth != 0:
                continue
            cond = body[cond_start:i - 1].strip()
            # Body should contain the sink position
            block_start = body.find("{", i - 1)
            if block_start < 0 or block_start > sink_pos:
                # Single-statement body — only matches if sink is the very
                # next non-blank statement.
                continue
            depth = 1
            j = block_start + 1
            while j < len(body) and depth > 0:
                if body[j] == "{":
                    depth += 1
                elif body[j] == "}":
                    depth -= 1
                j += 1
            block_end = j
            if block_start < sink_pos < block_end:
                guards.append(cond)
        return guards

    # Solver moved to sentinel.symbolic.solver. The shared module
    # encodes guards and runs z3 so D_072 + future symbolic agents
    # can reuse the same plumbing.


__all__ = ["SymbolicIntentAgent"]
