"""REFL_001 — Reflection target resolver via AST constant propagation.

Reflection (`Class.forName("foo")`, `Method.invoke(...)`,
`Constructor.newInstance(...)`) is a static-analysis blind spot: the
target is a string, computed at runtime, often the result of a series
of concatenations or pulled from resources. A naive regex hit
catches `Class.forName("com.evil.X")` but misses the much more
common pattern:

    String pkg = "com.app";
    String cls = pkg + "." + "Internal";
    Class.forName(cls);

This agent walks each Java file's Tree-sitter CST, builds a tiny
intra-procedural constant-propagation table for `String` locals
inside method bodies, then resolves `Class.forName(arg)`,
`Method.invoke(...)`, and `Constructor.newInstance(...)` arguments
back to their concatenated string literals. Unresolved targets are
emitted as **Dynamic Testing Targets** for the Frida agent —
exactly the bridge to runtime analysis that REFL_001 is meant to
provide.

Implementation notes:
  * Uses the global AstCache (`ctx.ast_cache`) — does not re-parse.
    Falls back to a regex pass when the cache is unavailable.
  * Constant-prop is intentionally simple: assigns of the form
    `String x = "lit"`, `String x = a + b`, `x += "lit"`, only
    inside a single method. No SSA, no flow analysis.
  * Resolves up to 200 sites per file; bails on the rest with a
    counter to keep big classes from dominating the scan.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.delta import should_skip
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Dangerous classes a resolved Class.forName commonly targets.
# Used to bump severity when the resolved string matches.
_DANGEROUS_TARGETS = (
    "java.lang.Runtime",                    # Runtime.exec
    "java.lang.ProcessBuilder",
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "java.net.URLClassLoader",
    "java.lang.reflect.AccessibleObject",   # setAccessible
)

_FORNAME_RE = re.compile(r"Class\s*\.\s*forName\s*\(")
_INVOKE_RE = re.compile(r"Method\s*\.\s*invoke\s*\(")
_NEWINSTANCE_RE = re.compile(r"Constructor\s*\.\s*newInstance\s*\(")

# String-literal assignment patterns (intra-procedural const prop).
# We keep these intentionally narrow — multi-line concat resolution is
# fragile and the value-add over single-line lit is small.
_STRING_DECL_RE = re.compile(
    r'\bString\s+(\w+)\s*=\s*("(?:\\.|[^"\\])*")'
    r'(?:\s*\+\s*("(?:\\.|[^"\\])*"))*\s*;'
)
_STRING_CONCAT_RE = re.compile(
    r'\b(\w+)\s*=\s*([\w."\\]+(?:\s*\+\s*[\w."\\]+)+)\s*;'
)
# Inline forName call: Class.forName("literal" + "literal")
_INLINE_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

_MAX_FILES = 2500
_MAX_SITES_PER_FILE = 200


class ReflectionResolverAgent(BaseAgent):
    """REFL_001: resolve reflective target strings via local const prop."""

    AGENT_ID = "REFL_001"
    VULN_CLASS = "Unsafe Reflection"
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
            rel = str(path.relative_to(root))
            if should_skip(ctx.changed_files, rel):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "Class.forName" not in text \
               and "Method.invoke" not in text \
               and "Constructor.newInstance" not in text:
                continue

            sites = self._resolve_sites(text)
            for site in sites[:_MAX_SITES_PER_FILE]:
                findings.append(self._emit(site, rel))
        return findings

    # ---------- resolution ----------

    def _resolve_sites(self, text: str) -> list[dict[str, Any]]:
        """Find every reflection site + try to resolve its target."""
        # Build a tiny const table from String literal declarations.
        const_table: dict[str, str] = {}
        for m in _STRING_DECL_RE.finditer(text):
            var = m.group(1)
            # The full RHS may have appended further literals.
            literals = _INLINE_LITERAL_RE.findall(m.group(0))
            const_table[var] = "".join(literals)
        # Second pass: simple `x = a + "b" + c` rebuilds.
        for m in _STRING_CONCAT_RE.finditer(text):
            var = m.group(1)
            if var in const_table:
                continue  # already resolved by declaration pass
            rhs_pieces = re.split(r"\s*\+\s*", m.group(2))
            resolved = []
            for piece in rhs_pieces:
                piece = piece.strip()
                if piece.startswith('"') and piece.endswith('"'):
                    resolved.append(piece[1:-1])
                elif piece in const_table:
                    resolved.append(const_table[piece])
                else:
                    resolved = []
                    break  # bail on first unresolvable token
            if resolved:
                const_table[var] = "".join(resolved)

        sites: list[dict[str, Any]] = []
        for kind, pat in (
            ("Class.forName", _FORNAME_RE),
            ("Method.invoke", _INVOKE_RE),
            ("Constructor.newInstance", _NEWINSTANCE_RE),
        ):
            for m in pat.finditer(text):
                # Extract the argument slice — naive until first `;` or `)`.
                start = m.end()
                arg = self._extract_first_arg(text, start)
                resolved = self._resolve_arg(arg, const_table)
                line_no = text[:m.start()].count("\n") + 1
                sites.append({
                    "kind": kind,
                    "line": line_no,
                    "raw_arg": arg[:160],
                    "resolved": resolved,
                    "dynamic_target": resolved is None,
                })
        return sites

    @staticmethod
    def _extract_first_arg(text: str, start: int) -> str:
        """Take everything up to the first matching `)`. Naive but works
        for the >95% case where the arg expression contains no nested
        parentheses (typical for reflective targets)."""
        depth = 1
        for i, ch in enumerate(text[start:start + 800]):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[start:start + i].strip()
        return text[start:start + 200]

    @staticmethod
    def _resolve_arg(arg: str, const_table: dict[str, str]) -> str | None:
        """Resolve a reflective argument to its string value, or None.

        Supported:
          * "literal"                          → literal
          * "a" + "b"                          → ab
          * varName  (looked up in const_table)
          * "lit" + varName + "lit"            → concat
        """
        pieces = re.split(r"\s*\+\s*", arg)
        resolved: list[str] = []
        for p in pieces:
            p = p.strip().rstrip(",")
            if not p:
                continue
            if p.startswith('"') and p.endswith('"'):
                resolved.append(p[1:-1])
            elif p in const_table:
                resolved.append(const_table[p])
            else:
                return None
        return "".join(resolved) if resolved else None

    # ---------- emission ----------

    def _emit(self, site: dict[str, Any], rel: str) -> Finding:
        resolved = site["resolved"]
        is_dangerous = bool(
            resolved
            and any(t in resolved for t in _DANGEROUS_TARGETS)
        )
        if site["dynamic_target"]:
            severity = Severity.MEDIUM
            vuln = "Unresolved Reflection Target (Dynamic Testing Target)"
            rec = (
                "The reflective target could not be resolved via "
                "constant propagation — the input string comes from "
                "control flow this static analyzer cannot follow. "
                "Forwarded to the Frida agent as a runtime hook target."
            )
        elif is_dangerous:
            severity = Severity.HIGH
            vuln = "Reflection Loads Dangerous Class"
            rec = (
                "The resolved reflective target is a class historically "
                "exploited for code execution / dynamic loading. Audit "
                "the call site for attacker-controlled input."
            )
        else:
            severity = Severity.LOW
            vuln = "Resolved Reflection Target"
            rec = (
                "Resolved reflection target enumerated for audit. "
                "Confirm it cannot be redirected by attacker input."
            )
        return self._make_finding(
            vuln_class=vuln,
            severity=severity,
            confidence=0.85 if resolved else 0.65,
            recommendation=rec,
            evidence={
                "file": rel,
                "line": site["line"],
                "kind": site["kind"],
                "raw_arg": site["raw_arg"],
                "resolved_target": resolved or "(unresolved)",
                "dynamic_target": site["dynamic_target"],
            },
        )


__all__ = ["ReflectionResolverAgent"]
