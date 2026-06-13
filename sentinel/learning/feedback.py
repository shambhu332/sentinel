"""FEEDBACK_001 — Dynamic verification → SAST confidence loop.

The orchestrator's verify phase produces VerificationOutcome values
(VERIFIED, REFUTED, INCONCLUSIVE) per finding. FEEDBACK_001 turns
those into a per-`(agent_id, vuln_class)` confidence adjustment that
applies on subsequent scans of the **same app** (keyed by
`apk_sha256` via the existing `AppLearningProfile.confidence_priors`).

Two values come out of every loop pass:

  * `confidence_multiplier`  — applied to raw agent confidence on the
                               next scan. Bounded to [0.5, 1.3] to
                               keep one bad scan from collapsing or
                               inflating an agent's calibration.
  * `auto_triage_state`      — if the prior accept-rate is below a
                               threshold (default 0.25 over >= 5
                               samples), new findings of that
                               (agent_id, vuln_class) are auto-marked
                               NEEDS_VERIFICATION rather than the
                               default UNREVIEWED.

Design notes (Sprint 12 — to be wired into the orchestrator):

  * Storage rides on the existing `AppLearningProfile.confidence_priors`
    + `triage_decisions` maps. No new tables.
  * The actual mutator on the scan side runs *after* Phase 6 verify,
    when `VerifyEngine` has emitted outcomes for every finding it
    could touch. The mutator calls
    `loop.record_outcome(profile, finding, outcome)` per finding;
    then `default_store.save(profile)` persists.
  * The reader runs *before* Phase 2. The orchestrator does
    `profile = default_store.load(ctx.apk_sha256)` and threads
    `profile` into `ScanContext.app_profile['learning']`.
    Individual agents call
    `FeedbackLoop.adjusted_confidence(agent_id, vuln_class, base)`
    and `FeedbackLoop.auto_triage(agent_id, vuln_class)`.

The module ships **without** the orchestrator wiring (that touches
multiple phase boundaries and merits its own commit). What we do
ship: a pure, deterministic adjuster that the orchestrator can drop
in as soon as the wiring lands.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sentinel.core.finding import Finding, TriageState
from sentinel.learning.profile_store import AppLearningProfile

logger = logging.getLogger(__name__)


# Verification outcome -> triage state — kept here so neither
# sentinel.verify nor sentinel.core.finding has to import from
# the other.
_OUTCOME_TO_TRIAGE = {
    "verified":      "True Positive",
    "refuted":       "False Positive",
    "inconclusive":  "Unreviewed",
    "skipped":       "Unreviewed",
    "unsupported":   "Unreviewed",
}


@dataclass
class FeedbackLoop:
    """Per-app confidence adjuster + auto-triage suggester."""

    profile: AppLearningProfile

    # Tunables — kept as fields so unit tests can override
    multiplier_floor: float = 0.5
    multiplier_ceiling: float = 1.3
    auto_verify_threshold: float = 0.25
    auto_verify_min_samples: int = 5

    # ---------- write side ----------

    def record_outcome(self, finding: Finding, outcome: str) -> None:
        """Record one verification outcome into the profile."""
        triage = _OUTCOME_TO_TRIAGE.get(outcome.lower(), "Unreviewed")
        if triage == "Unreviewed":
            return  # No signal — don't pollute the prior
        self.profile.record_triage(
            fingerprint=finding.finding_id,
            vuln_class=finding.vuln_class,
            agent_id=finding.agent_id,
            triage=triage,
        )

    # ---------- read side ----------

    def adjusted_confidence(
        self, agent_id: str, vuln_class: str, base_confidence: float,
    ) -> float:
        """Apply the prior to a raw agent confidence."""
        rate = self.profile.prior_accept_rate(agent_id, vuln_class)
        if rate is None:
            return base_confidence
        # Map accept-rate (0..1) onto multiplier in
        # [multiplier_floor, multiplier_ceiling] linearly. 0.5 maps to 1.0.
        spread = self.multiplier_ceiling - self.multiplier_floor
        multiplier = self.multiplier_floor + rate * spread
        return _clamp(base_confidence * multiplier, 0.0, 1.0)

    def auto_triage(self, agent_id: str, vuln_class: str) -> TriageState:
        """Return the triage state new findings should default to."""
        key = f"{agent_id}|{vuln_class}"
        prior = self.profile.confidence_priors.get(key)
        if not prior or prior["n"] < self.auto_verify_min_samples:
            return TriageState.UNREVIEWED
        rate = prior["tp"] / prior["n"]
        if rate < self.auto_verify_threshold:
            # Lots of historical FPs — flag for verification
            return TriageState.NEEDS_VERIFICATION
        return TriageState.UNREVIEWED

    def is_known_false_positive(self, finding: Finding) -> bool:
        return self.profile.is_known_false_positive(finding.finding_id)


def _clamp(x: float, lo: float, hi: float) -> float:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


__all__ = ["FeedbackLoop"]
