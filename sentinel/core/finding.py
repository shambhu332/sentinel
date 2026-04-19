"""Finding and BountyScope schemas — canonical data model.

Every agent emits Finding objects. Strict Pydantic validation prevents
malicious APK content from injecting junk into reports.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    owasp: str | None = Field(default=None, max_length=20)
    masvs: str | None = Field(default=None, max_length=20)
    poc: str | None = None
    recommendation: str = Field(..., min_length=1)
    session_id: str
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