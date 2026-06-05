"""APK-vs-APK diff: stable fingerprints, delta computation, renderers.

Every scan produces a fresh per-session workspace
(``workspace/<session>/decompiled/sources/...``) and a fresh
``session_id`` on the Finding objects themselves. Comparing two scans
of two different APK versions therefore can't rely on object identity,
session ids, or absolute file paths — they all change every run.

A :func:`finding_fingerprint` collapses each finding to a stable
hash over four normalised inputs:

* ``agent_id`` — verbatim (the IDs are versioned regex-style).
* ``vuln_class`` — verbatim.
* ``normalized file path`` — workspace prefix + session + decompile-tool
  prefix all stripped so the path becomes
  ``com/example/foo/Bar.java`` regardless of which scan produced it.
* ``normalized code snippet`` — whitespace collapsed, leading line
  numbers stripped, trailing comments removed. Decompilers occasionally
  re-emit the same statement with slightly different formatting; the
  normaliser bridges that gap.

The delta math is then a simple set operation:

* ``new``        = head − base
* ``fixed``      = base − head
* ``unchanged``  = base ∩ head

Two render functions (:func:`render_json`, :func:`render_markdown`)
emit machine-readable and PR-comment-ready outputs respectively.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sentinel.core.finding import Finding, Severity

# ---------- Public types ----------

#: Severities sorted highest → lowest. Used by the markdown renderer
#: to sort the "new findings" table and by the gate to decide whether
#: a finding's severity falls inside the ``--fail-on`` set.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_SEVERITY_BY_NAME: dict[str, Severity] = {s.value.lower(): s for s in Severity}


@dataclass(frozen=True)
class DiffSummary:
    """Result of comparing two scan finding-sets.

    ``new`` is the set of findings present in ``head`` but not in
    ``base`` — these are regressions to gate on. ``fixed`` is the
    reverse (findings removed between versions). ``unchanged`` is
    the intersection — still present, still un-fixed.

    Each field is a list (not a set) so the natural emission order is
    preserved: head order for ``new`` / ``unchanged``, base order for
    ``fixed``. That keeps reports stable across runs of the diff tool
    itself.
    """
    new: list[Finding]
    fixed: list[Finding]
    unchanged: list[Finding]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new":       len(self.new),
            "fixed":     len(self.fixed),
            "unchanged": len(self.unchanged),
        }


# ---------- Fingerprinting ----------

# Workspace prefix patterns — every scan produces a path like
#   workspace/<session_id>/decompiled/sources/com/example/Foo.java
# or absolute variants. We strip everything up to and including the
# decompiler's source root so two scans of the same APK hash the same.
_WORKSPACE_PREFIX_RE = re.compile(
    r"^(?:.*?/)?workspace/[^/]+/(?:decompiled|jadx|apktool)/"
    r"(?:sources/)?",
)

# Even when there is no enclosing workspace dir (custom layouts), the
# leading segment up to the source root needs cleaning. This second
# pattern catches absolute "/tmp/..." prefixes and ".jadx" suffixes.
_TMPDIR_PREFIX_RE = re.compile(r"^(?:/tmp/|/var/tmp/|.+?/jadx-out/)")

# Snippet normalisation. Order matters: strip leading line numbers
# first (``  127: foo()``) so the whitespace collapse doesn't run them
# together.
_LINE_PREFIX_RE = re.compile(r"^\s*\d+\s*[:|]\s*")
_TRAILING_COMMENT_RE = re.compile(r"\s*//.*$")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_path(raw: str | None) -> str:
    """Strip workspace/session/decompiler-tool prefixes from a path.

    Returns an empty string for None / falsy input — fingerprinting
    needs every component, so callers that pass an absent path get a
    deterministic placeholder rather than crashing.
    """
    if not raw:
        return ""
    p = str(raw).replace("\\", "/")
    p = _WORKSPACE_PREFIX_RE.sub("", p)
    p = _TMPDIR_PREFIX_RE.sub("", p)
    # Lowercase only on Windows-style drive letters; we don't fold case
    # generally because Java package paths are case-sensitive.
    if len(p) >= 2 and p[1] == ":":
        p = p[0].lower() + p[1:]
    return p


def _normalize_snippet(raw: str | None) -> str:
    """Whitespace-collapse + line-number / trailing-comment strip."""
    if not raw:
        return ""
    # Just the first line — multi-line snippets are normalised the same
    # way then re-joined with a single space.
    parts: list[str] = []
    for line in str(raw).splitlines():
        line = _LINE_PREFIX_RE.sub("", line)
        line = _TRAILING_COMMENT_RE.sub("", line)
        line = _WHITESPACE_RE.sub(" ", line).strip()
        if line:
            parts.append(line)
    return " ".join(parts)


def _extract_path(finding: Finding) -> str:
    """Best-effort path extraction from a Finding's evidence dict.

    Different agents put the source location under different keys
    (``source_file``, ``sink_file``, ``file``, ``path``). The
    fingerprint reads them in priority order so the same physical
    file hashes identically regardless of which agent produced the
    finding.
    """
    ev = finding.evidence or {}
    for key in ("source_file", "sink_file", "file", "path",
                "decompiled_file", "java_file"):
        val = ev.get(key)
        if val:
            return str(val)
    # Last-resort: the trace structure used by TAINT_001 carries the
    # sink path in trace[-1].file.
    trace = ev.get("trace")
    if isinstance(trace, list) and trace:
        last = trace[-1]
        if isinstance(last, dict) and last.get("file"):
            return str(last["file"])
    return ""


def _extract_snippet(finding: Finding) -> str:
    """Best-effort code-line / context-string extraction."""
    ev = finding.evidence or {}
    for key in ("code", "snippet", "context", "matched_line",
                "evidence", "summary"):
        val = ev.get(key)
        if isinstance(val, str) and val.strip():
            return val
    # TAINT_001 trace style — sink line code excerpt.
    trace = ev.get("trace")
    if isinstance(trace, list) and trace:
        last = trace[-1]
        if isinstance(last, dict) and last.get("code"):
            return str(last["code"])
    return ""


def finding_fingerprint(finding: Finding) -> str:
    """Stable 16-hex-char hash uniquely identifying a finding across versions.

    The same logical bug in two scans hashes identically — that's the
    whole reason this exists. The four inputs are picked because they
    are the smallest tuple that uniquely identifies a bug in practice:

    * agent_id    — versioned ID; never collides across agents.
    * vuln_class  — agent's vuln-class string; distinguishes a single
                    agent's multiple finding types.
    * file path   — normalised to the package-relative path.
    * code        — normalised to canonical-whitespace, sans line nums.

    16 hex chars (SHA-256 truncated) gives ~10⁻¹⁹ collision odds at
    the scale a single repo will ever see — plenty.
    """
    parts = (
        finding.agent_id,
        finding.vuln_class,
        _normalize_path(_extract_path(finding)),
        _normalize_snippet(_extract_snippet(finding)),
    )
    canonical = "\x1f".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(canonical).hexdigest()[:16]


# ---------- Delta computation ----------

def compute_delta(
    base: Iterable[Finding], head: Iterable[Finding],
) -> DiffSummary:
    """Set-difference base against head by fingerprint.

    Both inputs may be any iterable. We materialise once (so a
    generator doesn't get exhausted) and key on fingerprint.
    """
    base_list = list(base)
    head_list = list(head)
    base_by_fp = {finding_fingerprint(f): f for f in base_list}
    head_by_fp = {finding_fingerprint(f): f for f in head_list}

    base_fps = set(base_by_fp)
    head_fps = set(head_by_fp)

    new_fps       = head_fps - base_fps
    fixed_fps     = base_fps - head_fps
    unchanged_fps = base_fps & head_fps

    # Preserve emission order: head-order for new/unchanged, base-order
    # for fixed. Avoids per-run table reshuffling.
    new       = [f for f in head_list if finding_fingerprint(f) in new_fps]
    unchanged = [f for f in head_list if finding_fingerprint(f) in unchanged_fps]
    fixed     = [f for f in base_list if finding_fingerprint(f) in fixed_fps]

    return DiffSummary(new=new, fixed=fixed, unchanged=unchanged)


# ---------- Severity gate ----------

def parse_severity_list(raw: str) -> set[Severity]:
    """Parse a CLI ``--fail-on`` value into a set of Severity enums.

    Accepts comma-separated names case-insensitively. Unknown tokens
    raise ``ValueError`` with a friendly message — the CLI catches
    and re-raises as ``click.BadParameter``.
    """
    out: set[Severity] = set()
    for tok in (raw or "").split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        if tok not in _SEVERITY_BY_NAME:
            raise ValueError(
                f"unknown severity {tok!r}; choose from "
                f"{', '.join(sorted(_SEVERITY_BY_NAME))}",
            )
        out.add(_SEVERITY_BY_NAME[tok])
    return out


def gate_exit_code(summary: DiffSummary, fail_on: set[Severity]) -> int:
    """Return 1 if any ``new`` finding has severity in ``fail_on``,
    else 0. This is the CI-gate exit code."""
    for f in summary.new:
        if f.severity in fail_on:
            return 1
    return 0


# ---------- Renderers ----------

def _finding_to_row(f: Finding) -> dict[str, Any]:
    path = _normalize_path(_extract_path(f))
    snippet = _extract_snippet(f)
    return {
        "fingerprint": finding_fingerprint(f),
        "agent_id":    f.agent_id,
        "vuln_class":  f.vuln_class,
        "severity":    f.severity.value,
        "confidence":  f.confidence,
        "file":        path or "(unknown)",
        "snippet":     (snippet[:160] + "…") if len(snippet) > 161 else snippet,
        "recommendation": f.recommendation,
    }


def render_json(
    summary: DiffSummary,
    base_label: str,
    head_label: str,
) -> dict[str, Any]:
    """Structured JSON payload — schema is stable across versions."""
    return {
        "base": base_label,
        "head": head_label,
        "summary": summary.counts,
        "new_findings":   [_finding_to_row(f) for f in summary.new],
        "fixed_findings": [_finding_to_row(f) for f in summary.fixed],
    }


def _severity_rank(s: Severity) -> int:
    try:
        return SEVERITY_ORDER.index(s)
    except ValueError:
        return len(SEVERITY_ORDER)


def render_markdown(
    summary: DiffSummary,
    base_label: str,
    head_label: str,
) -> str:
    """PR-comment-ready Markdown block."""
    counts = summary.counts
    if counts["new"] == 0 and counts["fixed"] == 0:
        head_line = (
            f"### SENTINEL diff: {head_label} vs {base_label}\n\n"
            f"✅ No change. {counts['unchanged']} pre-existing findings "
            f"still present, 0 new, 0 fixed.\n"
        )
        return head_line

    lines: list[str] = [
        f"### SENTINEL diff: {head_label} vs {base_label}",
        "",
        f"🔴 **{counts['new']} new finding"
        f"{'s' if counts['new'] != 1 else ''} introduced**, "
        f"🟢 **{counts['fixed']} fixed**, "
        f"⚪ {counts['unchanged']} unchanged.",
        "",
    ]

    if summary.new:
        lines.append("#### New findings")
        lines.append("")
        lines.append("| Severity | Agent | Vuln class | File | Snippet |")
        lines.append("|---|---|---|---|---|")
        rows = sorted(summary.new, key=lambda f: _severity_rank(f.severity))
        for f in rows:
            row = _finding_to_row(f)
            snippet = _md_escape(row["snippet"]) or "_(no snippet)_"
            lines.append(
                f"| `{row['severity']}` | `{row['agent_id']}` "
                f"| {_md_escape(row['vuln_class'])} "
                f"| `{_md_escape(row['file'])}` "
                f"| {snippet} |",
            )
        lines.append("")

    if summary.fixed:
        lines.append("#### Fixed findings")
        lines.append("")
        lines.append("| Severity | Agent | Vuln class | File |")
        lines.append("|---|---|---|---|")
        rows = sorted(summary.fixed, key=lambda f: _severity_rank(f.severity))
        for f in rows:
            row = _finding_to_row(f)
            lines.append(
                f"| `{row['severity']}` | `{row['agent_id']}` "
                f"| {_md_escape(row['vuln_class'])} "
                f"| `{_md_escape(row['file'])}` |",
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _md_escape(s: str) -> str:
    """Escape pipe characters so they don't break Markdown tables."""
    return (s or "").replace("|", r"\|").replace("\n", " ")


__all__ = [
    "DiffSummary",
    "SEVERITY_ORDER",
    "finding_fingerprint",
    "compute_delta",
    "parse_severity_list",
    "gate_exit_code",
    "render_json",
    "render_markdown",
]
