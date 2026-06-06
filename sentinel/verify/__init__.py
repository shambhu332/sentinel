"""SENTINEL verify engine — per-finding-class dynamic verification.

The verify engine sits between Phase 3 (LLM triage) and Phase 8
(report generation). For every triaged finding it routes to a
``Verifier`` keyed by ``agent_id``; each verifier returns a
``VerificationResult`` carrying the outcome
(``verified`` / ``refuted`` / ``inconclusive`` / ``unsupported``)
and the evidence backing the call.

The engine is deliberately conservative:

* Missing captures, missing device, missing decompiled sources → the
  verifier returns ``unsupported`` rather than raising. The engine
  never blocks the scan pipeline.
* Verifiers must not modify the device under test or the captured
  artifacts. Read-only by contract.
"""
from sentinel.verify.engine import VerifyEngine
from sentinel.verify.models import (
    VerificationOutcome,
    VerificationResult,
    VerifierContext,
)

__all__ = [
    "VerificationOutcome",
    "VerificationResult",
    "VerifierContext",
    "VerifyEngine",
]
