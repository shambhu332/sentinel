"""IMPACT_001 — Economic-impact calculator.

Deterministic. No LLM. Loss estimate is a product of four scalars:

    estimate_usd = base_loss[vuln_class]
                 * severity_multiplier[finding.severity]
                 * asset_category_multiplier[matched_asset]
                 * tenant_plan_multiplier[tenant_plan]

The schedule lives in `loss_schedule.yaml` — review-friendly. Asset
category is inferred from any file/path string in the finding's
evidence by matching against regex bands for payment / admin / kyc /
wallet / vault / transfer / auth / api. When nothing matches the
multiplier is 1.0.

Outputs:

    Finding.financial_impact_score  -> float (USD)
    Finding.evidence['_impact']     -> rationale block (kept short)

This module never mutates the input Finding. Callers use `score()`
to get the ImpactResult and then attach it themselves via
Finding.model_copy(update=...). That keeps the calculator pure and
testable.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_DEFAULT_YAML = Path(__file__).parent / "loss_schedule.yaml"

# Asset-category regexes — substring-on-lowercased-path
_ASSET_BANDS: list[tuple[str, re.Pattern]] = [
    ("payment",  re.compile(r"payment|payout|charge|invoice|credit")),
    ("admin",    re.compile(r"admin|backoffice|root")),
    ("kyc",      re.compile(r"kyc|onboard|verify_identity")),
    ("wallet",   re.compile(r"wallet|coin|crypto|nft")),
    ("vault",    re.compile(r"vault|safe|secret")),
    ("transfer", re.compile(r"transfer|remit|sendmoney")),
    ("auth",     re.compile(r"auth|login|signin|otp|2fa|biometric|password")),
    ("api",      re.compile(r"/api/|apicall|endpoint|retrofit|okhttp")),
]


@dataclass(frozen=True)
class ImpactResult:
    """One score per finding."""

    estimate_usd: float
    vuln_class_matched: str          # bucket key from the schedule
    asset_category: str              # one of _ASSET_BANDS keys or "default"
    severity_multiplier: float
    asset_multiplier: float
    tenant_multiplier: float
    rationale: str

    def to_evidence_block(self) -> dict[str, Any]:
        return {
            "estimate_usd": round(self.estimate_usd, 2),
            "vuln_class_matched": self.vuln_class_matched,
            "asset_category": self.asset_category,
            "multipliers": {
                "severity": self.severity_multiplier,
                "asset": self.asset_multiplier,
                "tenant": self.tenant_multiplier,
            },
            "rationale": self.rationale[:400],
        }


@dataclass
class EconomicCalculator:
    """YAML-backed loss calculator."""

    schedule_path: Path = _DEFAULT_YAML
    _defaults: dict[str, Any] = field(default_factory=dict)
    _classes: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._load()

    # ---------- loading ----------

    def _load(self) -> None:
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML missing — IMPACT_001 disabled")
            return
        try:
            data = yaml.safe_load(self.schedule_path.read_text(encoding="utf-8")) or {}
        except (OSError, Exception) as e:  # noqa: BLE001
            logger.warning("Loss schedule load failed: %s", e)
            return
        self._defaults = data.get("defaults") or {}
        self._classes = data.get("classes") or {}

    # ---------- scoring ----------

    def score_finding(
        self,
        finding: Finding,
        tenant_plan: str = "free",
    ) -> ImpactResult:
        klass, klass_body = self._match_class(finding.vuln_class)
        base = float(klass_body.get("base_loss_usd",
                                     self._defaults.get("base_loss_usd", 5000)))
        sev_mult = float(self._defaults
                          .get("severity_multiplier", {})
                          .get(finding.severity.value, 1.0))
        asset = self._match_asset_category(finding)
        asset_mult = float(self._defaults
                            .get("asset_category_multiplier", {})
                            .get(asset, 1.0))
        tenant_mult = float(self._defaults
                             .get("tenant_plan_multiplier", {})
                             .get(tenant_plan, 1.0))
        estimate = base * sev_mult * asset_mult * tenant_mult
        rationale = (
            klass_body.get("rationale", "").strip()
            or "Base loss applied with no class-specific rationale on file."
        )
        return ImpactResult(
            estimate_usd=estimate,
            vuln_class_matched=klass,
            asset_category=asset,
            severity_multiplier=sev_mult,
            asset_multiplier=asset_mult,
            tenant_multiplier=tenant_mult,
            rationale=rationale,
        )

    # ---------- helpers ----------

    def _match_class(self, vuln_class: str) -> tuple[str, dict[str, Any]]:
        lowered = vuln_class.lower()
        for klass, body in self._classes.items():
            needles = body.get("needles") or []
            for n in needles:
                if isinstance(n, str) and n.lower() in lowered:
                    return klass, body
        return "default", {}

    @staticmethod
    def _match_asset_category(finding: Finding) -> str:
        """Inspect every string-valued evidence key for HVT keywords."""
        ev = finding.evidence or {}
        candidates: list[str] = []
        for key in ("file", "path", "url", "endpoint", "snippet", "context"):
            v = ev.get(key)
            if isinstance(v, str):
                candidates.append(v.lower())
        # Also inspect nested 'hits'/'matches' list shapes
        for key in ("hits", "matches"):
            v = ev.get(key)
            if isinstance(v, list):
                for entry in v[:30]:
                    if isinstance(entry, dict):
                        for k in ("file", "path", "url"):
                            s = entry.get(k)
                            if isinstance(s, str):
                                candidates.append(s.lower())
        joined = " ".join(candidates)
        for label, pattern in _ASSET_BANDS:
            if pattern.search(joined):
                return label
        return "default"


# ---------- public surface ----------

default_calculator = EconomicCalculator()


def score(finding: Finding, tenant_plan: str = "free") -> ImpactResult:
    """Module-level convenience."""
    return default_calculator.score_finding(finding, tenant_plan=tenant_plan)


def attach_impact(finding: Finding, tenant_plan: str = "free") -> Finding:
    """Score a finding and return a copy with the score attached.

    Sets `Finding.financial_impact_score` to the USD estimate and
    appends the rationale to evidence['_impact'].
    """
    result = score(finding, tenant_plan=tenant_plan)
    new_evidence = dict(finding.evidence or {})
    new_evidence["_impact"] = result.to_evidence_block()
    return finding.model_copy(update={
        "financial_impact_score": round(result.estimate_usd, 2),
        "evidence": new_evidence,
    })


__all__ = [
    "EconomicCalculator",
    "ImpactResult",
    "attach_impact",
    "default_calculator",
    "score",
]
