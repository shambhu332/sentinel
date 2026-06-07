"""Tests for the upgraded R_001 VAPT report generator.

The builder and renderers are tested directly (no agent / memory /
ChromaDB infrastructure needed) — that keeps the suite fast.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from sentinel.agents.reporting import (
    FindingSection,
    ReferenceBlock,
    ReportData,
    RiskScore,
    build_report_data,
    render_html,
    render_markdown,
)
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import generate_session_id


def _finding(
    *,
    agent_id: str = "P_010",
    vuln_class: str = "Intent Redirect",
    severity: Severity = Severity.HIGH,
    masvs: str = "MSTG-PLATFORM-1",
    owasp: str = "M4: Insufficient Input/Output Validation",
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=0.85,
        evidence=evidence or {"issue": "demo"},
        recommendation="Pin Intent target with setPackage.",
        owasp=owasp,
        masvs=masvs,
        session_id=generate_session_id(),
    )


# ---------- RiskScore ----------


def test_risk_score_zero_when_clean():
    rs = RiskScore.from_counts(critical=0, high=0, medium=0, low=0)
    assert rs.score == 0
    assert rs.band == "low"


def test_risk_score_critical_dominates():
    rs = RiskScore.from_counts(critical=1, high=0, medium=0, low=0)
    assert rs.band == "critical"
    assert rs.score >= 30


def test_risk_score_capped_at_100():
    rs = RiskScore.from_counts(critical=10, high=20, medium=30, low=40)
    assert rs.score == 100


def test_risk_score_high_cluster_promotes_band():
    rs = RiskScore.from_counts(critical=0, high=4, medium=0, low=0)
    assert rs.band == "high"


# ---------- builder ----------


def test_builder_orders_findings_by_severity():
    findings = [
        _finding(agent_id="A_002", severity=Severity.LOW),
        _finding(agent_id="A_001", severity=Severity.CRITICAL),
        _finding(agent_id="A_003", severity=Severity.HIGH),
    ]
    data = build_report_data(
        findings=findings,
        package="com.x",
        version="1.0",
        session_id="ses12345",
    )
    severities = [s.finding.severity for s in data.sections]
    assert severities == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]


def test_builder_collects_references_from_finding_and_rag():
    f = _finding(
        evidence={
            "issue": "demo",
            "_rag_mapping": {
                "CWE-926": "Improper Export of Android Components",
                "M4": "Insufficient I/O Validation",
            },
            "_rag_passage_ids": ["CWE-926", "M4"],
        },
    )
    data = build_report_data(
        findings=[f], package="com.x", version="1.0", session_id="ses12345",
    )
    sources = {r.source for r in data.references}
    assert "MASVS" in sources
    assert "CWE" in sources
    assert "OWASP_MOBILE" in sources


def test_builder_extracts_triage_explanation():
    f = _finding(evidence={
        "issue": "demo",
        "_triage": {
            "outcome": "Verified",
            "llm_provider": "groq",
            "verdict": {
                "is_real_bug": True,
                "confidence": 0.9,
                "explanation": "Real Intent-redirect path, dispatched without setPackage.",
            },
        },
    })
    data = build_report_data(
        findings=[f], package="com.x", version="1.0", session_id="ses12345",
    )
    section = data.sections[0]
    assert "Intent-redirect path" in section.triage_explanation
    assert section.llm_provider == "groq"


def test_builder_severity_counts_match():
    findings = [
        _finding(severity=Severity.CRITICAL),
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.LOW),
    ]
    data = build_report_data(
        findings=findings,
        package="com.x", version="1.0", session_id="ses12345",
    )
    assert data.severity_counts["Critical"] == 1
    assert data.severity_counts["High"] == 2
    assert data.severity_counts["Low"] == 1


def test_builder_empty_findings_produces_empty_sections():
    data = build_report_data(
        findings=[], package="com.x", version="1.0", session_id="ses12345",
    )
    assert data.sections == []
    assert data.risk.band == "low"


# ---------- markdown renderer ----------


def _sample_data() -> ReportData:
    findings = [
        _finding(
            severity=Severity.CRITICAL,
            evidence={
                "issue": "Mutable PendingIntent with implicit base",
                "_rag_mapping": {
                    "MSTG-PLATFORM-1": "MSTG-PLATFORM-1",
                    "CWE-926": "Improper Export of Android Components",
                },
                "_rag_passage_ids": ["MSTG-PLATFORM-1", "CWE-926"],
                "_triage": {
                    "outcome": "Verified",
                    "llm_provider": "cerebras",
                    "verdict": {
                        "is_real_bug": True,
                        "confidence": 0.9,
                        "explanation": "Confirmed mutable PendingIntent.",
                    },
                },
            },
        ),
        _finding(severity=Severity.MEDIUM, agent_id="N_010"),
    ]
    return build_report_data(
        findings=findings,
        package="com.example.app",
        version="2.3.1",
        session_id="ses12345678",
        apk_sha256="a" * 64,
        apk_size_bytes=12345,
        generated_at=datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_markdown_includes_executive_summary():
    md = render_markdown(_sample_data())
    assert "# Vulnerability Assessment" in md
    assert "## Executive Summary" in md
    assert "Composite risk score:" in md


def test_markdown_lists_findings_with_rag_mapping():
    md = render_markdown(_sample_data())
    # Evidence "issue" survives into the JSON evidence block.
    assert "Mutable PendingIntent with implicit base" in md
    # RAG-sourced mapping is rendered as its own section.
    assert "Standards mapping (retrieved)" in md
    assert "MSTG-PLATFORM-1" in md
    assert "CWE-926" in md


def test_markdown_strips_internal_evidence_keys():
    md = render_markdown(_sample_data())
    assert "_rag_mapping" not in md
    assert "_triage" not in md


def test_markdown_includes_triage_explanation():
    md = render_markdown(_sample_data())
    assert "Confirmed mutable PendingIntent" in md


# ---------- html renderer ----------


def test_html_is_self_contained():
    html = render_html(_sample_data())
    assert html.startswith("<!doctype html>")
    # CSS inline, no external link tags.
    assert "<link" not in html
    assert "<style>" in html
    # Severity pill present (NCC-grade template uses sev-pill).
    assert "sev-pill Critical" in html


def test_html_includes_finding_card():
    html = render_html(_sample_data())
    assert "com.example.app" in html
    assert "MSTG-PLATFORM-1" in html
    assert "Standards Cited" in html


def test_html_has_vapt_structure():
    html = render_html(_sample_data())
    # Cover page + executive summary + scope + findings + appendix
    assert "Mobile Application Security Assessment" in html
    assert "CONFIDENTIAL" in html
    assert "Executive Summary" in html
    assert "Scope &amp; Methodology" in html
    assert "Technical Findings" in html
    assert "Appendix" in html


def test_html_renders_no_findings_gracefully():
    empty = build_report_data(
        findings=[], package="com.x", version="0", session_id="s12345678",
    )
    html = render_html(empty)
    assert "No findings identified" in html
