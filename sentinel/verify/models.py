"""Dataclasses shared by the verify engine and its verifiers.

Kept free of agent / memory / ChromaDB imports so verifier modules
can be unit-tested with fixture data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from sentinel.core.scan_context import ScanContext


class VerificationOutcome(str, Enum):
    """The four possible verifier verdicts.

    * ``VERIFIED`` — the verifier saw concrete evidence that the
      finding's claim holds in the analysed APK / captures.
    * ``REFUTED`` — the verifier ran successfully and the finding's
      claim does not hold (likely false positive).
    * ``INCONCLUSIVE`` — the verifier ran but couldn't decide
      either way (e.g. flow data present but ambiguous).
    * ``UNSUPPORTED`` — required inputs (decompiled dir, mitm
      capture, frida capture, device) were absent.
    """

    VERIFIED = "verified"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


@dataclass
class VerificationResult:
    """A single verifier's verdict on a single finding."""

    outcome: VerificationOutcome
    confidence: float = 0.0  # 0..1
    method: str = ""         # e.g. "manifest-reread" / "mitm-flow-match"
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    @classmethod
    def unsupported(cls, method: str, reason: str) -> "VerificationResult":
        """Shorthand for the common "we couldn't check" path."""
        return cls(
            outcome=VerificationOutcome.UNSUPPORTED,
            confidence=0.0,
            method=method,
            notes=reason,
        )

    @classmethod
    def verified(
        cls,
        method: str,
        evidence: dict[str, Any] | None = None,
        confidence: float = 0.9,
        notes: str = "",
    ) -> "VerificationResult":
        return cls(
            outcome=VerificationOutcome.VERIFIED,
            confidence=confidence,
            method=method,
            evidence=evidence or {},
            notes=notes,
        )

    @classmethod
    def refuted(
        cls,
        method: str,
        evidence: dict[str, Any] | None = None,
        confidence: float = 0.85,
        notes: str = "",
    ) -> "VerificationResult":
        return cls(
            outcome=VerificationOutcome.REFUTED,
            confidence=confidence,
            method=method,
            evidence=evidence or {},
            notes=notes,
        )

    @classmethod
    def inconclusive(
        cls,
        method: str,
        reason: str,
    ) -> "VerificationResult":
        return cls(
            outcome=VerificationOutcome.INCONCLUSIVE,
            confidence=0.5,
            method=method,
            notes=reason,
        )


@dataclass
class VerifierContext:
    """Scope-narrowed view of the scan context passed to verifiers.

    A verifier should never reach back into the broader pipeline. The
    context exposes the read-only inputs it needs and nothing else.
    """

    scan: ScanContext

    @property
    def decompiled_dir(self) -> Path | None:
        return self.scan.decompiled_dir

    @property
    def resources_dir(self) -> Path | None:
        return self.scan.resources_dir

    @property
    def manifest(self) -> dict[str, Any]:
        return self.scan.manifest or {}

    @property
    def mitm_capture(self) -> Any | None:
        return (self.scan.sources or {}).get("mitmproxy")

    @property
    def frida_capture(self) -> Any | None:
        return (self.scan.sources or {}).get("frida")
