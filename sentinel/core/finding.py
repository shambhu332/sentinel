"""Finding and BountyScope schemas — canonical data model.

Every agent emits Finding objects. Strict Pydantic validation prevents
malicious APK content from injecting junk into reports.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# Discrete verification routing key (Djini-parity).
#   verified       — runtime probe fired and observed the bug
#   auth_gated     — runtime probe blocked at login/authz before reaching the
#                    vulnerable surface (residual risk only)
#   code_only      — no runtime probe ran; finding is static-source only
#   runtime_failed — probe ran but crashed / returned a failure signal
# `verification_status` (the free-form string) stays the human-readable
# explanation; this enum is what the bucket classifier + UI + triager
# route on so we don't grep substrings of an English sentence.
VerificationState = Literal[
    "verified", "auth_gated", "code_only", "runtime_failed",
]

MAX_STRING_LEN = 10_000
MAX_EVIDENCE_FIELDS = 50
SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")
AGENT_ID_PATTERN = re.compile(r"^[A-Z]+_\d{3}$")


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class TriageState(str, Enum):
    UNREVIEWED = "Unreviewed"
    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    NEEDS_VERIFICATION = "Needs Verification"


class Finding(BaseModel):
    model_config = ConfigDict(
        str_max_length=MAX_STRING_LEN,
        extra="forbid",
        validate_assignment=True,
    )

    agent_id: str
    vuln_class: str = Field(..., min_length=1, max_length=200)
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    cvss_vector: str | None = Field(default=None, max_length=200)
    owasp: str | None = Field(default=None, max_length=50)
    masvs: str | None = Field(default=None, max_length=20)
    poc: str | None = None
    recommendation: str = Field(..., min_length=1)
    session_id: str
    # Multi-tenant SaaS field. None for OSS / local CLI runs; set by the
    # API ingest layer from the JWT before persisting. The Postgres RLS
    # policy refuses INSERT/UPDATE when this disagrees with the
    # session-set `sentinel.tenant_id` GUC, so the value is enforced
    # by the database, not by application code.
    tenant_id: str | None = Field(default=None, max_length=64)
    # Estimated single-incident financial impact in USD as populated by
    # IMPACT_001. None means "not scored yet" — every consumer treats
    # None as "unknown" rather than zero. Negative values rejected.
    financial_impact_score: float | None = Field(default=None, ge=0.0)
    # Regulatory citations attached by COMPLIANCE_001 (e.g.
    # ["GDPR Art. 32(1)(a)", "PCI-DSS 3.4", "SOC2 CC6.1"]). Each entry
    # is a free-form "framework reference" string; rendering happens in
    # the report layer.
    compliance_tags: list[str] = Field(default_factory=list, max_length=50)
    # Visual evidence. Two accepted shapes:
    #   - list[str]:  legacy — relative paths under workspace/{session}/evidence/
    #   - list[dict]: rich   — {path, caption, step_index} per screenshot
    # The frontend handles both. New code should emit dicts (via
    # AdbRunner.capture_evidence) so screenshots can be tied to repro steps.
    screenshots: list[Any] | None = Field(default=None, max_length=40)
    # Precise vulnerable-line metadata emitted by SAST agents. Keys:
    #   file (str), line (int), start_col (int), end_col (int),
    #   content (str, the snippet itself, max ~4 KB).
    # Single-snippet field kept for back-compat with existing agents.
    code_snippet: dict[str, Any] | None = Field(default=None)
    # Multi-snippet variant. Each entry has the same keys as code_snippet
    # plus an optional `label` for the section header (e.g.
    # "Activity declaration" / "Intent-filter handler"). The detail view
    # renders these as numbered, file-pathed code blocks.
    code_snippets: list[dict[str, Any]] | None = Field(default=None, max_length=20)
    # Five-point qualitative ratings produced by IMPACT_001 / triage.
    # Keys: exposure, controls, impact, likelihood (each a short string
    # like "Network-reachable" or "None"). Free-form so different
    # rating systems can coexist.
    context_factors: dict[str, str] | None = Field(default=None)
    # LLM-generated narrative explaining *why* this finding earned its
    # severity rating. Surfaced under the description in the detail view
    # so reviewers can sanity-check the scoring without re-reading evidence.
    severity_rationale: str | None = Field(default=None, max_length=4000)
    # Verification outcome for dynamic findings. Free-form so we can grow
    # the vocabulary without a migration; today the common values are
    # "Verified", "Unverified due to auth gating", "Code-level only".
    verification_status: str | None = Field(default=None, max_length=120)
    # Discrete routing key derived from / parallel to verification_status.
    # Lets the bucket classifier, UI, and triager switch on an enum instead
    # of substring-matching a free-form sentence. Defaults to None so
    # existing callers (and tests) don't need updating; consumers should
    # fall back to verification_status when this is None.
    verification_state: VerificationState | None = Field(default=None)
    # Single canonical screenshot captured at the moment a runtime probe
    # was blocked (auth gate, SELinux denial, frida crash). Renders as
    # the "Blocking State" hero image under verification_status. Optional
    # — full evidence stream still goes through `screenshots`.
    blocking_state_screenshot: str | None = Field(default=None, max_length=500)
    # True when the DAST credential manager attempted automated login
    # against the target package during this scan. Used in reports to
    # distinguish "we tested unauthenticated paths" from "we tested
    # authenticated paths and the bug reproduced anyway".
    test_credentials_used: bool = Field(default=False)
    # Exact ADB / Frida / curl commands the verifier ran. Renders as a
    # monospace block under the repro steps so a developer can re-run
    # the exploit locally without reading the verifier source.
    reproduction_commands: list[str] = Field(default_factory=list, max_length=20)
    # What actually happened when the exploit was attempted, in plain
    # English. Renders italicised under reproduction_commands so it
    # reads as evidence, not instruction.
    observed_result: str | None = Field(default=None, max_length=4000)
    # Free-form taxonomy tags (e.g. "Deep Link / URL Scheme",
    # "Untrusted Web Content"). Rendered as the metadata-row source
    # badges in the detail view.
    source_tags: list[str] = Field(default_factory=list, max_length=20)
    triage: TriageState = TriageState.UNREVIEWED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, v: str) -> str:
        if not AGENT_ID_PATTERN.match(v):
            raise ValueError(f"agent_id must match XXX_NNN, got: {v}")
        return v

    @field_validator("session_id")
    @classmethod
    def _validate_session_id(cls, v: str) -> str:
        if not SESSION_ID_PATTERN.match(v):
            raise ValueError("session_id must be 8-64 chars, alphanumeric/_/-")
        return v

    @field_validator("evidence")
    @classmethod
    def _validate_evidence(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > MAX_EVIDENCE_FIELDS:
            raise ValueError(f"evidence has too many fields (max {MAX_EVIDENCE_FIELDS})")
        return v

    @field_validator("screenshots")
    @classmethod
    def _validate_screenshots(cls, v: list[Any] | None) -> list[Any] | None:
        if v is None:
            return v
        for entry in v:
            if isinstance(entry, str):
                continue
            if isinstance(entry, dict) and "path" in entry:
                continue
            raise ValueError(
                "screenshots entries must be str paths or dicts with a 'path' key"
            )
        return v

    @property
    def finding_id(self) -> str:
        canonical = f"{self.agent_id}|{self.vuln_class}|{sorted(self.evidence.items())}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class BountyScope(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    program_name: str = Field(default="", max_length=200)
    platform: str = Field(default="", max_length=50)
    in_scope_packages: list[str] = Field(default_factory=list)
    in_scope_domains: list[str] = Field(default_factory=list)
    out_of_scope_packages: list[str] = Field(default_factory=list)
    out_of_scope_domains: list[str] = Field(default_factory=list)
    excluded_vuln_classes: set[str] = Field(default_factory=set)
    forbidden_techniques: set[str] = Field(default_factory=set)
    reward_ranges: dict[str, tuple[int, int]] = Field(default_factory=dict)

    def is_unrestricted(self) -> bool:
        return not (self.in_scope_packages or self.in_scope_domains)

    def package_in_scope(self, package: str) -> bool:
        if self.is_unrestricted():
            return True
        if package in self.out_of_scope_packages:
            return False
        return package in self.in_scope_packages

    def technique_allowed(self, technique: str) -> bool:
        return technique not in self.forbidden_techniques


# ---------- Verification-state derivation ----------

_VERIFIED_PREFIXES = (
    "verified", "runtime-verified", "verified by",
)
_AUTH_GATED_PREFIXES = (
    "auth_gated", "auth-gated", "unverified due to auth",
    "blocked by login", "login required",
)
_RUNTIME_FAILED_PREFIXES = (
    "unverified at runtime",
    "llm triage uncertain",
    "runtime-failed",
)


def derive_verification_state(finding: "Finding") -> VerificationState | None:
    """Return the discrete state for a finding.

    Preference order:
      1. Finding.verification_state if explicitly set (authoritative).
      2. Map verification_status by case-insensitive prefix match.
      3. None when there is no signal either way.
    """
    if finding.verification_state is not None:
        return finding.verification_state
    status = (finding.verification_status or "").strip().lower()
    if not status:
        return None
    if any(status.startswith(p) for p in _VERIFIED_PREFIXES):
        return "verified"
    if any(status.startswith(p) for p in _AUTH_GATED_PREFIXES):
        return "auth_gated"
    if any(status.startswith(p) for p in _RUNTIME_FAILED_PREFIXES):
        return "runtime_failed"
    if status.startswith(("code-level", "code only", "code_only")):
        return "code_only"
    return None

