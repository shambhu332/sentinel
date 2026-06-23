"""Markdown renderer for the VAPT report.

The output is GitHub-flavoured Markdown so it renders cleanly on
HackerOne / Bugcrowd / GitHub issues and reads well when piped to a
plain terminal.
"""
from __future__ import annotations

import json
from typing import Iterable

from sentinel.agents.reporting.models import (
    BUCKET_AI_POWERED,
    BUCKET_BLURBS,
    BUCKET_LABELS,
    BUCKET_STATIC_TOOL,
    FindingSection,
    ReferenceBlock,
    ReportData,
    split_sections_by_bucket,
)
from sentinel.core.finding import Severity

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH: "🟠 High",
    Severity.MEDIUM: "🟡 Medium",
    Severity.LOW: "🟢 Low",
    Severity.INFO: "ℹ️ Info",
}

# Human-readable badge for the discrete verification_state enum so the
# bucket the finding belongs to is immediately visible above the body.
_VERIFICATION_STATE_BADGE: dict[str, str] = {
    "verified":       "✅ Runtime-verified",
    "auth_gated":     "🔐 Auth-gated (residual risk)",
    "code_only":      "📄 Code-level only",
    "runtime_failed": "⚠️ Runtime probe failed",
}


def render_markdown(data: ReportData) -> str:
    """Render ``ReportData`` as Markdown."""
    lines: list[str] = []
    _header(lines, data)
    _executive_summary(lines, data)
    _scope_methodology(lines)
    _findings(lines, data)
    _references(lines, data.references)
    _appendix(lines, data)
    return "\n".join(lines).rstrip() + "\n"


# ---------- sections ----------


def _header(lines: list[str], data: ReportData) -> None:
    lines.extend([
        "# Vulnerability Assessment & Penetration Testing Report",
        "",
        f"**Application package:** `{data.package}`  ",
        f"**Version:** `{data.version}`  ",
        f"**Report generated:** {data.generated_at.isoformat(timespec='seconds')}  ",
        f"**Session ID:** `{data.session_id}`  ",
        "**SENTINEL build:** v0.1.0",
        "",
        "---",
        "",
    ])


def _executive_summary(lines: list[str], data: ReportData) -> None:
    lines.extend([
        "## Executive Summary",
        "",
        f"This assessment of **{data.package}** identified "
        f"**{data.total_findings}** finding(s) across "
        f"{len(data.references)} unique controls in the OWASP Mobile "
        "Top 10, MASVS, and CWE catalogues.",
        "",
        f"**Composite risk score:** {data.risk.score}/100 — "
        f"**{data.risk.band.upper()}**.  ",
        data.risk.summary,
        "",
        "### Severity breakdown",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ])
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        lines.append(f"| {sev} | {data.severity_counts.get(sev, 0)} |")
    lines.extend(["", "---", ""])


def _scope_methodology(lines: list[str]) -> None:
    lines.extend([
        "## Scope & Methodology",
        "",
        "**Scope:** the supplied APK was analysed in a sandboxed "
        "scan environment. No live production systems were probed.",
        "",
        "**Phases executed:**",
        "",
        "- Phase 0 — APK ingestion (SHA-256, workspace, manifest)",
        "- Phase 1 — Parallel recon (JADX, Androguard, apktool)",
        "- Phase 2 — Static analysis agents",
        "- Phase 3 — LLM-assisted triage (Groq / Cerebras / Ollama "
        "rotation, RAG-augmented when a knowledge base is built)",
        "- Phase 4 — Dynamic analysis (mitmproxy + Frida) when enabled",
        "- Phase 7 — Exploit-chain correlation",
        "",
        "**False-positive handling:** every finding surfaced here was "
        "either marked _Verified_ by the LLM triager or carries an "
        "_Uncertain_ verdict explicitly flagged in the appendix.",
        "",
        "---",
        "",
    ])


def _findings(lines: list[str], data: ReportData) -> None:
    """Render findings split into AI-Powered AppSec and Static Tool sections.

    Each bucket gets its own H2 (so the TOC reads as two distinct top-
    level findings sections) and inside each bucket findings are
    grouped by severity, deterministically ordered, and numbered F#-N
    so cross-references stay stable across renders.
    """
    lines.extend(["## Findings", ""])
    ai_sections, static_sections = split_sections_by_bucket(data.sections)

    # Quick split summary so a reader skimming the report sees the
    # bucket counts before diving into individual findings.
    lines.extend([
        "| Section | Count |",
        "| --- | ---: |",
        f"| {BUCKET_LABELS[BUCKET_AI_POWERED]} | {len(ai_sections)} |",
        f"| {BUCKET_LABELS[BUCKET_STATIC_TOOL]} | {len(static_sections)} |",
        "",
    ])

    _bucket_section(
        lines,
        prefix="A",
        title=BUCKET_LABELS[BUCKET_AI_POWERED],
        blurb=BUCKET_BLURBS[BUCKET_AI_POWERED],
        sections=ai_sections,
    )
    _bucket_section(
        lines,
        prefix="S",
        title=BUCKET_LABELS[BUCKET_STATIC_TOOL],
        blurb=BUCKET_BLURBS[BUCKET_STATIC_TOOL],
        sections=static_sections,
    )

    lines.extend(["---", ""])


def _bucket_section(
    lines: list[str],
    *,
    prefix: str,
    title: str,
    blurb: str,
    sections: list[FindingSection],
) -> None:
    lines.extend([
        f"## {title}",
        "",
        f"_{blurb}_",
        "",
    ])
    if not sections:
        lines.extend(["_No findings in this section._", "", "---", ""])
        return

    counter = 0
    for severity in (
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        Severity.LOW, Severity.INFO,
    ):
        bucket = [s for s in sections if s.finding.severity == severity]
        if not bucket:
            continue
        lines.extend([
            f"### {_SEVERITY_BADGE[severity]} — {len(bucket)} finding(s)",
            "",
        ])
        for section in bucket:
            counter += 1
            _finding_card(lines, f"{prefix}{counter}", section)
    lines.extend(["---", ""])


def _finding_card(
    lines: list[str],
    label: str | int,
    section: FindingSection,
) -> None:
    f = section.finding
    lines.extend([
        f"#### {label}. {f.vuln_class}",
        "",
        f"- **Agent:** `{f.agent_id}`",
        f"- **Severity:** {_SEVERITY_BADGE[f.severity]}",
        f"- **Confidence:** {f.confidence:.0%}",
        f"- **OWASP:** {f.owasp or '—'}",
        f"- **MASVS:** {f.masvs or '—'}",
        f"- **CVSS:** `{f.cvss_vector or 'n/a'}`",
    ])
    if f.verification_status or f.verification_state:
        state_badge = _VERIFICATION_STATE_BADGE.get(
            f.verification_state or "", "",
        )
        status_text = f.verification_status or ""
        if state_badge and status_text:
            lines.append(
                f"- **Verification:** {state_badge} — {status_text}"
            )
        elif state_badge:
            lines.append(f"- **Verification:** {state_badge}")
        else:
            lines.append(f"- **Verification:** {status_text}")
    if f.test_credentials_used:
        lines.append("- **Authenticated test:** yes (test credentials used)")
    if f.source_tags:
        lines.append(
            f"- **Source tags:** {', '.join(f'`{t}`' for t in f.source_tags)}"
        )
    lines.append("")

    # Blocking-state callout — Djini-style. When a runtime probe was
    # blocked we render the dedicated screenshot above the standard
    # evidence list so reviewers see *why* the bug is unverified before
    # they read the full evidence.
    if f.blocking_state_screenshot:
        lines.extend([
            "> **Blocking state captured.** The runtime probe could not "
            "reach the vulnerable surface; the screenshot below shows "
            "the device state at the moment dispatch was blocked.",
            "",
            f"![Blocking state]({f.blocking_state_screenshot})",
            "",
        ])

    if f.severity_rationale:
        lines.extend([
            "**Severity rationale:**",
            "",
            f.severity_rationale.strip(),
            "",
        ])

    if section.triage_explanation:
        lines.extend([
            "**LLM triage:**",
            "",
            f"> {section.triage_explanation}",
            "",
        ])
    if section.rag_mapping:
        lines.extend([
            "**Standards mapping (retrieved):**",
            "",
        ])
        for cid, title in sorted(section.rag_mapping.items()):
            lines.append(f"- `{cid}` — {title}")
        lines.append("")

    # Code snippets — render multi-snippet field if populated, otherwise
    # fall back to the legacy singular code_snippet.
    snippets = list(f.code_snippets or [])
    if not snippets and f.code_snippet:
        snippets = [f.code_snippet]
    if snippets:
        lines.extend(["**Affected code:**", ""])
        for i, cs in enumerate(snippets, 1):
            file_path = (cs or {}).get("file", "(no file)")
            line_no = (cs or {}).get("line")
            cs_label = (cs or {}).get("label")
            header = f"`{file_path}`"
            if line_no:
                header += f" — line {line_no}"
            if cs_label:
                header = f"_{cs_label}_ · " + header
            lines.append(f"{i}. {header}")
            lines.extend([
                "",
                "```",
                str((cs or {}).get("content", "")),
                "```",
                "",
            ])

    # Steps to reproduce — verifier commands + observed result.
    if f.reproduction_commands:
        lines.extend(["**Steps to reproduce:**", "", "```"])
        lines.extend(str(c) for c in f.reproduction_commands)
        lines.extend(["```", ""])
    if f.observed_result:
        lines.extend([
            "**Observed result:**",
            "",
            f"_{f.observed_result.strip()}_",
            "",
        ])

    # Visual evidence list (paths only — Markdown renders elsewhere may
    # not have access to the workspace, so we link rather than embed).
    if f.screenshots:
        lines.extend(["**Visual evidence:**", ""])
        for entry in f.screenshots:
            if isinstance(entry, str):
                lines.append(f"- `{entry}`")
            elif isinstance(entry, dict) and entry.get("path"):
                caption = entry.get("caption") or entry.get("label") or ""
                if caption:
                    lines.append(f"- `{entry['path']}` — {caption}")
                else:
                    lines.append(f"- `{entry['path']}`")
        lines.append("")

    lines.extend([
        "**Evidence:**",
        "",
        "```json",
        json.dumps(_clean_evidence(f.evidence), indent=2, sort_keys=True),
        "```",
        "",
        "**Recommendation:**",
        "",
        f.recommendation.strip() or "_No recommendation supplied._",
        "",
        "---",
        "",
    ])


def _references(lines: list[str], refs: Iterable[ReferenceBlock]) -> None:
    refs = list(refs)
    if not refs:
        return
    lines.extend([
        "## Standards Cited",
        "",
        "| Source | Control | Title |",
        "| --- | --- | --- |",
    ])
    for r in refs:
        lines.append(f"| {r.source} | `{r.control_id}` | {r.title} |")
    lines.extend(["", "---", ""])


def _appendix(lines: list[str], data: ReportData) -> None:
    lines.extend([
        "## Appendix",
        "",
        f"- **APK SHA-256:** `{data.apk_sha256 or 'n/a'}`",
        f"- **APK size:** {data.apk_size_bytes} bytes",
        "- **Tooling:** SENTINEL v0.1.0 (static + LLM triage + RAG)",
        "",
        "_This report is confidential and intended for the application "
        "owner / engagement requester. Unauthorised distribution is "
        "prohibited._",
        "",
    ])


# ---------- evidence sanitisation ----------

_INTERNAL_EVIDENCE_KEYS = {
    "_triage", "_rag_mapping", "_rag_passage_ids",
    "_severity_original", "_severity_adjusted_by_llm",
}


def _clean_evidence(raw) -> dict:
    """Strip SENTINEL-internal evidence keys from the dump."""
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k not in _INTERNAL_EVIDENCE_KEYS}
