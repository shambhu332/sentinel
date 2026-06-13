"""COMPLIANCE_001 — Auditor-ready report renderer.

Takes a Finding list, attaches compliance citations to each, groups by
regulatory framework, and emits a markdown report suitable for handing
to an auditor (or to a PDF converter — `pandoc`, weasyprint, etc.).

We deliberately ship a markdown emitter rather than a direct PDF
binary. PDF generation pulls in heavyweight system deps (libpango,
ghostscript) that aren't worth the install footprint when every CI
runner and every OS already has a 5-line markdown-to-PDF tool wired
up. The output is structured so that `pandoc -o report.pdf` works
out of the box.

The renderer is pure — no I/O. Callers write the resulting string to
disk themselves (matches the rest of the codebase's reporting style).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from sentinel.compliance.mapper import Citation, default_mapper
from sentinel.core.finding import Finding, Severity

_FRAMEWORK_ORDER = ("GDPR", "HIPAA", "PCI-DSS", "SOC2", "DPDP", "CCPA")
_SEV_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO)


def attach_compliance_tags(findings: Iterable[Finding]) -> list[Finding]:
    """Return copies of findings with compliance_tags populated.

    Each tag is the rendered "Framework Reference" string ready to
    drop into the UI. The original findings are not mutated.
    """
    out: list[Finding] = []
    for f in findings:
        cites = default_mapper.cite(f)
        if not cites:
            out.append(f)
            continue
        tags = [c.render() for c in cites if c.framework][:50]
        # Don't overwrite if caller already populated tags
        if f.compliance_tags:
            merged = list(dict.fromkeys(list(f.compliance_tags) + tags))[:50]
        else:
            merged = tags
        out.append(f.model_copy(update={"compliance_tags": merged}))
    return out


def render_markdown(
    findings: list[Finding],
    *,
    app_name: str = "Mobile Application",
    session_id: str = "",
    generated_at: datetime | None = None,
) -> str:
    """Render a single markdown document grouped by framework.

    Each section lists every finding mapped to that framework, with
    severity, agent, and a one-line evidence pointer. Findings without
    any compliance citation appear in a final "Uncategorised" section.
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    by_framework: dict[str, list[tuple[Finding, Citation]]] = defaultdict(list)
    uncategorised: list[Finding] = []

    for f in findings:
        cites = default_mapper.cite(f)
        if not cites:
            uncategorised.append(f)
            continue
        for c in cites:
            by_framework[c.framework].append((f, c))

    lines: list[str] = []
    lines.append(f"# Compliance Audit Report — {app_name}")
    lines.append("")
    lines.append(f"*Generated {generated_at.isoformat(timespec='seconds')}*  ")
    if session_id:
        lines.append(f"*Scan session: `{session_id}`*  ")
    lines.append(f"*Findings considered: {len(findings)}*")
    lines.append("")

    # Executive summary table
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Framework | Findings | Critical | High | Medium | Low |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for fw in _FRAMEWORK_ORDER:
        entries = by_framework.get(fw)
        if not entries:
            continue
        unique = {f.finding_id: f for f, _ in entries}.values()
        sev_counts = {s: 0 for s in _SEV_ORDER}
        for f in unique:
            sev_counts[f.severity] += 1
        lines.append(
            f"| {fw} | {len(unique)} "
            f"| {sev_counts[Severity.CRITICAL]} "
            f"| {sev_counts[Severity.HIGH]} "
            f"| {sev_counts[Severity.MEDIUM]} "
            f"| {sev_counts[Severity.LOW]} |"
        )
    lines.append("")

    # Per-framework detail
    for fw in _FRAMEWORK_ORDER:
        entries = by_framework.get(fw)
        if not entries:
            continue
        lines.append(f"## {fw}")
        lines.append("")
        # Group within framework by reference for readability
        by_ref: dict[str, list[tuple[Finding, Citation]]] = defaultdict(list)
        for fc in entries:
            by_ref[fc[1].reference or "(unspecified)"].append(fc)
        for ref, ref_entries in sorted(by_ref.items()):
            # Section heading per reference
            lines.append(f"### {fw} {ref}")
            # Pull rationale from first citation
            note = ref_entries[0][1].note
            if note:
                lines.append(f"> {note}")
                lines.append("")
            for f, _ in ref_entries:
                file_ref = (f.evidence or {}).get("file") or \
                           (f.evidence or {}).get("path") or "—"
                lines.append(
                    f"- **{f.severity.value}** "
                    f"`{f.agent_id}` {f.vuln_class} "
                    f"— `{file_ref}`"
                )
            lines.append("")
        lines.append("")

    if uncategorised:
        lines.append("## Uncategorised")
        lines.append("")
        lines.append(
            "These findings have no curated regulatory citation in the "
            "compliance mapper yet. Add an entry to "
            "`sentinel/compliance/mappings.yaml` if a citation applies."
        )
        lines.append("")
        for f in uncategorised:
            lines.append(
                f"- **{f.severity.value}** `{f.agent_id}` {f.vuln_class}"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_to_file(
    findings: list[Finding],
    path,
    *,
    app_name: str = "Mobile Application",
    session_id: str = "",
) -> str:
    """Convenience: render + write. Returns the rendered text."""
    text = render_markdown(
        findings, app_name=app_name, session_id=session_id,
    )
    path.write_text(text, encoding="utf-8")
    return text


__all__ = [
    "attach_compliance_tags",
    "render_markdown",
    "render_to_file",
]
