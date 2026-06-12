"""RES_002 — Resource leak tracker (Cursor / InputStream / Socket).

Static scan for the most common Android leak shapes:
  - `Cursor c = ...query(...)` not followed by `c.close()` or
    wrapped in `try-with-resources`.
  - `InputStream / FileInputStream / FileOutputStream` opened and
    discarded.
  - `Socket / ServerSocket` opened without `close()` in a `finally`.

The detection is line-oriented, not flow-sensitive, so it errors on
the side of LOW severity: a leak is annoying, not a vuln, but it
matters for resource exhaustion DoS and for `Cursor` specifically
because leaked cursors hold a SQLite reader lock open.
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Resource type → (open-pattern, close-pattern, severity)
# Open-patterns match the local-variable declaration of the resource.
_RESOURCES: list[tuple[str, re.Pattern, str, Severity]] = [
    (
        "Cursor",
        re.compile(r"\b(?:Cursor)\s+(\w+)\s*=\s*[^;]*\bquery\("),
        "close",
        Severity.MEDIUM,
    ),
    (
        "InputStream",
        re.compile(
            r"\b(?:InputStream|FileInputStream|BufferedInputStream)"
            r"\s+(\w+)\s*=\s*new\s+"
        ),
        "close",
        Severity.LOW,
    ),
    (
        "OutputStream",
        re.compile(
            r"\b(?:OutputStream|FileOutputStream|BufferedOutputStream)"
            r"\s+(\w+)\s*=\s*new\s+"
        ),
        "close",
        Severity.LOW,
    ),
    (
        "Socket",
        re.compile(r"\b(?:Socket|ServerSocket)\s+(\w+)\s*=\s*new\s+"),
        "close",
        Severity.MEDIUM,
    ),
]

# try-with-resources opener — `try (... resource = ...)` immediately
# closes the resource on block exit, so any variable declared inside
# the `try(...)` head is exempt.
_TRY_WITH_RESOURCES_RE = re.compile(r"try\s*\(")

_MAX_FILES = 2000


class ResourceLeakAgent(BaseAgent):
    """RES_002: flag opened resources without a close-call in scope."""

    AGENT_ID = "RES_002"
    VULN_CLASS = "Resource Leak"
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

            # Find positions of try-with-resources heads; any open-decl
            # whose declaration falls inside one of these constructor
            # bodies is exempt (cheaply approximated by "same line").
            twr_lines = {
                text[:m.start()].count("\n") + 1
                for m in _TRY_WITH_RESOURCES_RE.finditer(text)
            }

            for label, pattern, close_method, severity in _RESOURCES:
                for m in pattern.finditer(text):
                    var = m.group(1)
                    line_no = text[:m.start()].count("\n") + 1
                    if line_no in twr_lines:
                        continue  # try-with-resources: auto-closed
                    # Look for a close call on `var` in the rest of the file.
                    close_re = re.compile(
                        rf"\b{re.escape(var)}\s*\.\s*{close_method}\s*\("
                    )
                    if close_re.search(text, m.end()):
                        continue
                    findings.append(self._make_finding(
                        vuln_class=f"{label} Leak",
                        severity=severity,
                        confidence=0.65,
                        recommendation=(
                            f"Variable `{var}` ({label}) is opened but no "
                            f"`{var}.{close_method}()` call appears later "
                            f"in the file. Wrap the resource in "
                            f"`try-with-resources` or close it in a "
                            f"`finally` block."
                        ),
                        evidence={
                            "file": rel,
                            "line": line_no,
                            "variable": var,
                            "resource_type": label,
                        },
                    ))
        return findings


__all__ = ["ResourceLeakAgent"]
