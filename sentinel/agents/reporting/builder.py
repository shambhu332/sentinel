"""Build a ``ReportData`` from a scan result.

The builder is the only place that knows about ``ScanContext`` and
``Finding``. Renderers consume the resulting ``ReportData`` and don't
need to import anything else from the agent layer — that keeps the
template code testable in isolation.

The builder is also where we extract the RAG-sourced fields we
persisted into ``finding.evidence`` during triage (see
``LLMTriager._gather_rag_context``). If those fields are absent (the
scan ran without RAG, or with ``--no-triage``), the resulting
sections simply have empty mappings — the renderers handle that.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sentinel.agents.reporting.models import (
    FindingSection,
    ReferenceBlock,
    ReportData,
    RiskScore,
)
from sentinel.compliance.masvs_scorer import MavsScorer
from sentinel.core.finding import Finding, Severity

_SOURCE_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("MSTG-", "MASVS"),
    ("M", "OWASP_MOBILE"),  # M1..M10
    ("CWE-", "CWE"),
    ("OSV-", "OSV"),
    ("GHSA-", "OSV"),
)


def build_report_data(
    *,
    findings: list[Finding],
    package: str,
    version: str,
    session_id: str,
    apk_sha256: str = "",
    apk_size_bytes: int = 0,
    generated_at: datetime | None = None,
    coverage: dict | None = None,
) -> ReportData:
    """Build a ``ReportData`` ready for any renderer."""
    sections = _build_sections(findings)
    references = _collect_references(sections)
    counts = _severity_counts(sections)
    risk = RiskScore.from_counts(
        critical=counts.get("Critical", 0),
        high=counts.get("High", 0),
        medium=counts.get("Medium", 0),
        low=counts.get("Low", 0),
    )
    masvs_compliance = MavsScorer().score(findings).as_dict()
    return ReportData(
        package=package or "(unknown)",
        version=version or "(unknown)",
        session_id=session_id,
        apk_sha256=apk_sha256,
        apk_size_bytes=apk_size_bytes,
        generated_at=generated_at or datetime.now(timezone.utc),
        sections=sections,
        references=references,
        severity_counts=counts,
        risk=risk,
        masvs_compliance=masvs_compliance,
        coverage=coverage or {},
    )


# ---------- helpers ----------


def _build_sections(findings: list[Finding]) -> list[FindingSection]:
    sections = [_to_section(f) for f in findings]
    severity_rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sections.sort(
        key=lambda s: (severity_rank.get(s.finding.severity, 99), s.finding.agent_id),
    )
    return sections


def _to_section(finding: Finding) -> FindingSection:
    evidence: dict[str, Any] = finding.evidence or {}
    rag_mapping = evidence.get("_rag_mapping") or {}
    rag_passage_ids = evidence.get("_rag_passage_ids") or []
    triage = evidence.get("_triage") or {}
    verdict = triage.get("verdict") or {}
    return FindingSection(
        finding=finding,
        rag_mapping=dict(rag_mapping) if isinstance(rag_mapping, dict) else {},
        rag_passage_ids=[str(p) for p in rag_passage_ids] if isinstance(rag_passage_ids, list) else [],
        triage_explanation=str(verdict.get("explanation") or ""),
        llm_provider=str(triage.get("llm_provider") or ""),
    )


def _collect_references(sections: list[FindingSection]) -> list[ReferenceBlock]:
    seen: dict[str, ReferenceBlock] = {}
    for s in sections:
        # Finding-declared mappings
        for key in (s.finding.masvs, s.finding.owasp):
            if not key:
                continue
            cid = key.split(":")[0].strip()
            if cid and cid not in seen:
                seen[cid] = ReferenceBlock(
                    control_id=cid,
                    title=key,
                    source=_source_for(cid),
                )
        # RAG-mapped passages
        for cid, title in s.rag_mapping.items():
            if cid and cid not in seen:
                seen[cid] = ReferenceBlock(
                    control_id=cid,
                    title=title,
                    source=_source_for(cid),
                )
    return sorted(seen.values(), key=lambda r: (r.source, r.control_id))


def _source_for(control_id: str) -> str:
    cid = control_id.strip().upper()
    for prefix, source in _SOURCE_BY_PREFIX:
        if cid.startswith(prefix.upper()):
            return source
    return "OTHER"


def _severity_counts(sections: list[FindingSection]) -> dict[str, int]:
    counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
    }
    for s in sections:
        counts[s.finding.severity.value] = counts.get(
            s.finding.severity.value, 0,
        ) + 1
    return counts
