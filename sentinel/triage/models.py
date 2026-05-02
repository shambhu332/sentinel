"""Pydantic models for the triage system."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TriageState(str, Enum):
    """Triage outcome for a finding.

    - VERIFIED: LLM confirmed this is a real bug worth submitting
    - FILTERED: LLM determined this is a false positive
    - UNCERTAIN: LLM was unsure or triage failed (rate limit, parsing error)
    - SKIPPED: Triage was disabled (--no-triage) or finding type doesn't need it
    """

    VERIFIED = "verified"
    FILTERED = "filtered"
    UNCERTAIN = "uncertain"
    SKIPPED = "skipped"


class TriageVerdict(BaseModel):
    """Schema the LLM is asked to produce.

    The LLM is instructed to return JSON matching this exact shape.
    Fields are validated; missing or malformed JSON is treated as UNCERTAIN.
    """

    model_config = ConfigDict(extra="forbid")

    is_real_bug: bool = Field(
        ..., description="True if this is a real exploitable vulnerability."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="LLM's confidence in this verdict, 0.0 to 1.0.",
    )
    explanation: str = Field(
        ..., min_length=10, max_length=2000,
        description="Specific explanation referencing the actual code. "
                    "Should mention variable names, line context, "
                    "and why the finding does or does not represent a bug.",
    )
    adjusted_severity: Optional[str] = Field(
        default=None,
        description="If the LLM thinks the agent's severity is wrong, the "
                    "corrected severity (Critical/High/Medium/Low/Info). "
                    "Null means the agent's severity is correct.",
    )
    false_positive_reason: Optional[str] = Field(
        default=None, max_length=500,
        description="If is_real_bug=False, a brief reason why this is a "
                    "false positive (e.g., 'used for game animation, not "
                    "security'). Null when is_real_bug=True.",
    )


class TriageResult(BaseModel):
    """Complete triage outcome attached to a finding."""

    model_config = ConfigDict(extra="forbid")

    state: TriageState
    verdict: Optional[TriageVerdict] = None
    error: Optional[str] = None
    llm_provider: Optional[str] = None  # "cerebras", "ollama", or None
    duration_ms: int = 0

    def is_displayable(self) -> bool:
        """Should this finding be shown in default scan output?

        VERIFIED, UNCERTAIN, and SKIPPED show by default.
        FILTERED is hidden unless --show-filtered is passed.
        """
        return self.state != TriageState.FILTERED
