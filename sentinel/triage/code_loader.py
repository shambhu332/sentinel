"""Loads source code context for a finding before LLM triage.

The LLM needs to SEE the code to make a good judgment. This module:
1. Extracts file references from the finding's evidence dict
2. Reads the actual file from the decompiled workspace
3. Returns ~50 lines around the matched location
4. Handles missing files gracefully (returns empty string)

Each agent stores file references slightly differently in evidence. We
normalize that here.
"""
from __future__ import annotations

import logging
from pathlib import Path

from sentinel.core.finding import Finding

logger = logging.getLogger(__name__)


# How many lines of context to include before/after the matched line
_CONTEXT_LINES_BEFORE = 15
_CONTEXT_LINES_AFTER = 25
# Max total characters to send to the LLM (token budget)
_MAX_CODE_CHARS = 4000


def load_code_context(
    finding: Finding,
    decompiled_dir: Path | None,
) -> tuple[str, str]:
    """Returns (code_snippet, file_path) for an LLM prompt.

    Returns ("", "") if no context can be extracted (manifest-only findings,
    missing files, decompiled_dir not set).
    """
    if not decompiled_dir or not decompiled_dir.exists():
        return "", ""

    # Try to find a file reference in the evidence
    file_rel = _extract_file_path(finding.evidence)
    if not file_rel:
        # Manifest-only findings (P_001, C_001, F_001) often have no file ref
        return "", ""

    file_abs = decompiled_dir / file_rel
    if not file_abs.exists() or not file_abs.is_file():
        logger.debug("[triage] File not found for context: %s", file_abs)
        return "", file_rel

    try:
        content = file_abs.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as e:
        logger.debug("[triage] Failed to read %s: %s", file_abs, e)
        return "", file_rel

    # Find the context line within the file
    context_line = _extract_context_line(finding.evidence)
    if not context_line:
        # No specific line — return first ~40 lines
        lines = content.splitlines()[:40]
        snippet = "\n".join(lines)
        return _truncate(snippet), file_rel

    # Find the line that contains the context
    lines = content.splitlines()
    target_idx = -1
    for i, line in enumerate(lines):
        if context_line in line:
            target_idx = i
            break

    if target_idx == -1:
        # Couldn't find the exact line — return file head
        snippet = "\n".join(lines[:40])
        return _truncate(snippet), file_rel

    # Extract surrounding lines
    start = max(0, target_idx - _CONTEXT_LINES_BEFORE)
    end = min(len(lines), target_idx + _CONTEXT_LINES_AFTER + 1)

    # Add line numbers for LLM clarity
    numbered = [
        f"{i + 1:4d}{'  ▶ ' if i == target_idx else '    '}{lines[i]}"
        for i in range(start, end)
    ]
    snippet = "\n".join(numbered)
    return _truncate(snippet), file_rel


def _extract_file_path(evidence: dict) -> str | None:
    """Pull a file path from evidence regardless of which agent produced it."""
    if not evidence:
        return None

    # Most common: hits is a list of dicts with "file" key
    hits = evidence.get("hits")
    if isinstance(hits, list) and hits:
        first = hits[0]
        if isinstance(first, dict):
            f = first.get("file")
            if f:
                return f

    # Some agents use per_file map (C_004 InsecureWebView)
    per_file = evidence.get("per_file")
    if isinstance(per_file, dict) and per_file:
        return next(iter(per_file.keys()))

    # Some have files_with_signals
    files = evidence.get("files_with_signals") or evidence.get("files")
    if isinstance(files, list) and files:
        return files[0]

    # Some store source_file directly
    return evidence.get("source_file") or evidence.get("file")


def _extract_context_line(evidence: dict) -> str | None:
    """Pull a context string we can grep for in the source file."""
    if not evidence:
        return None

    hits = evidence.get("hits")
    if isinstance(hits, list) and hits:
        first = hits[0]
        if isinstance(first, dict):
            ctx = first.get("context")
            if ctx and isinstance(ctx, str):
                # Use first 60 chars as a search anchor
                return ctx[:60].strip()

    return None


def _truncate(text: str) -> str:
    """Cap snippet size for token budget."""
    if len(text) <= _MAX_CODE_CHARS:
        return text
    return text[:_MAX_CODE_CHARS] + "\n... (truncated)"
