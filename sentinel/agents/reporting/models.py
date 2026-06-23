"""Dataclasses shared by the VAPT report builder and renderers.

All renderers consume ``ReportData``. Keeping the renderers
template-pure (no agent / context / memory access) means we can test
them against fixture data without touching ChromaDB or
``LightweightMemory``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sentinel.core.finding import Finding, Severity


@dataclass
class FindingSection:
    """A finding plus the RAG-sourced material we render alongside it."""

    finding: Finding
    rag_mapping: dict[str, str] = field(default_factory=dict)
    rag_passage_ids: list[str] = field(default_factory=list)
    triage_explanation: str = ""
    llm_provider: str = ""
    # Advisory-grade narrative (optional). Populated by the enrichment
    # pass before rendering. Keys: summary, affected_components (list),
    # evidence_notes, repro_steps (list[str]), poc_snippet (str|dict),
    # impact_bullets (list[str]), fix_bullets (list[str]),
    # references (list[{label,url}]).
    narrative: dict = field(default_factory=dict)


@dataclass
class ReferenceBlock:
    """A canonical control reference deduplicated across all findings."""

    control_id: str
    title: str
    source: str  # "MASVS" / "OWASP_MOBILE" / "CWE" / "OSV"


@dataclass
class RiskScore:
    """Composite risk indicator computed from the severity histogram."""

    score: int  # 0..100
    band: str   # "low" / "moderate" / "elevated" / "high" / "critical"
    summary: str

    @classmethod
    def from_counts(
        cls,
        critical: int,
        high: int,
        medium: int,
        low: int,
    ) -> "RiskScore":
        # Weight scheme reflects relative remediation urgency, not
        # CVSS arithmetic. Critical dominates; the bound at 100 keeps
        # the score interpretable.
        raw = critical * 30 + high * 12 + medium * 4 + low * 1
        score = min(100, raw)
        if critical:
            band, summary = "critical", (
                f"{critical} critical finding(s) require immediate action."
            )
        elif high >= 3:
            band, summary = "high", (
                f"{high} high-severity findings cluster on this build."
            )
        elif high:
            band, summary = "elevated", (
                f"{high} high-severity finding(s) need a near-term fix."
            )
        elif medium:
            band, summary = "moderate", (
                f"{medium} medium-severity finding(s) — schedule remediation."
            )
        else:
            band, summary = "low", (
                "No critical/high findings — security posture is healthy."
            )
        return cls(score=score, band=band, summary=summary)


@dataclass
class ReportData:
    """All inputs the renderers need.

    ``sections`` is ordered by severity descending then agent_id, so
    every renderer produces stable output. ``references`` is the
    deduplicated catalogue of MASVS / OWASP / CWE controls cited by
    any finding, used to build the standards section.
    """

    package: str
    version: str
    session_id: str
    apk_sha256: str
    apk_size_bytes: int
    generated_at: datetime

    sections: list[FindingSection] = field(default_factory=list)
    references: list[ReferenceBlock] = field(default_factory=list)

    severity_counts: dict[str, int] = field(default_factory=dict)
    risk: RiskScore = field(
        default_factory=lambda: RiskScore(score=0, band="low", summary=""),
    )

    @property
    def total_findings(self) -> int:
        return len(self.sections)

    def by_severity(self, severity: Severity) -> list[FindingSection]:
        return [s for s in self.sections if s.finding.severity == severity]


# ---------- bucket classification ----------

# Sentinel values for the two top-level report buckets. Kept as module-
# level constants so the renderers, R_001._classify_section, the JSON
# payload, and (mirrored) the frontend predicate all agree on the spelling.
BUCKET_AI_POWERED = "ai_powered"
BUCKET_STATIC_TOOL = "static_tool"

BUCKET_LABELS: dict[str, str] = {
    BUCKET_AI_POWERED: "AI-Powered AppSec Findings",
    BUCKET_STATIC_TOOL: "Static Tool Findings",
}

BUCKET_BLURBS: dict[str, str] = {
    BUCKET_AI_POWERED: (
        "Findings that an LLM triager verified, that a runtime "
        "verifier reproduced, or that a multi-agent swarm enriched. "
        "Each one carries narrative rationale and reproduction evidence "
        "beyond what the originating detector emitted."
    ),
    BUCKET_STATIC_TOOL: (
        "Findings produced by static analysis alone — manifest, "
        "decompiled-source, and configuration-file checks. They have "
        "not been verified at runtime and may require manual review "
        "to confirm exploitability in your deployment."
    ),
}


def bucket_for_section(section: FindingSection) -> str:
    """Return the report bucket for a single section.

    Mirrored by ``R_001._classify_section`` and by the frontend's
    ``findingBucket()`` in ``scan-detail.js``. Keep all three predicates
    in sync — they decide which top-level section a finding lands in.
    """
    f = section.finding
    ev = f.evidence if isinstance(f.evidence, dict) else {}

    if f.severity_rationale:
        return BUCKET_AI_POWERED
    # New: discrete state takes precedence over the free-form string.
    # Anything that isn't "code_only" is AI-Powered material.
    if f.verification_state and f.verification_state != "code_only":
        return BUCKET_AI_POWERED
    if f.verification_status and f.verification_status != "Code-level only":
        return BUCKET_AI_POWERED
    verify = ev.get("_verify")
    if isinstance(verify, dict) and verify.get("outcome"):
        return BUCKET_AI_POWERED
    if ev.get("_swarm"):
        return BUCKET_AI_POWERED
    if ev.get("dynamic_target"):
        return BUCKET_AI_POWERED
    if section.triage_explanation:
        return BUCKET_AI_POWERED
    return BUCKET_STATIC_TOOL


def split_sections_by_bucket(
    sections: list[FindingSection],
) -> tuple[list[FindingSection], list[FindingSection]]:
    """Partition sections into (ai_powered, static_tool) preserving order."""
    ai: list[FindingSection] = []
    static: list[FindingSection] = []
    for s in sections:
        if bucket_for_section(s) == BUCKET_AI_POWERED:
            ai.append(s)
        else:
            static.append(s)
    return ai, static
