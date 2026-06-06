"""Markdown renderer for the VAPT report.

The output is GitHub-flavoured Markdown so it renders cleanly on
HackerOne / Bugcrowd / GitHub issues and reads well when piped to a
plain terminal.
"""
from __future__ import annotations

import json
from typing import Iterable

from sentinel.agents.reporting.models import (
    FindingSection,
    ReferenceBlock,
    ReportData,
)
from sentinel.core.finding import Severity

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH: "🟠 High",
    Severity.MEDIUM: "🟡 Medium",
    Severity.LOW: "🟢 Low",
    Severity.INFO: "ℹ️ Info",
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
        f"**SENTINEL build:** v0.1.0",
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
    lines.extend(["## Findings", ""])
    for severity in (
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        Severity.LOW, Severity.INFO,
    ):
        bucket = data.by_severity(severity)
        if not bucket:
            continue
        lines.extend([
            f"### {_SEVERITY_BADGE[severity]} — {len(bucket)} finding(s)",
            "",
        ])
        for idx, section in enumerate(bucket, 1):
            _finding_card(lines, idx, section)
    lines.extend(["---", ""])


def _finding_card(lines: list[str], idx: int, section: FindingSection) -> None:
    f = section.finding
    lines.extend([
        f"#### {idx}. {f.vuln_class}",
        "",
        f"- **Agent:** `{f.agent_id}`",
        f"- **Severity:** {_SEVERITY_BADGE[f.severity]}",
        f"- **Confidence:** {f.confidence:.0%}",
        f"- **OWASP:** {f.owasp or '—'}",
        f"- **MASVS:** {f.masvs or '—'}",
        f"- **CVSS:** `{f.cvss_vector or 'n/a'}`",
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
