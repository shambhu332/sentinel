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

from sentinel.core.finding import Finding

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


def extract_hvt_endpoints_from_strings_xml(strings_xml: Path) -> set[str]:
    """Pull High-Value-Target endpoint strings from a Resources strings.xml.

    Targets are HTTP/HTTPS URLs and `/api/...` path literals whose
    lowercased form matches any HVT keyword (payment, admin, kyc,
    wallet, vault, transfer, auth, api). The returned set is consumed
    by `EconomicCalculator._match_asset_category` as additional
    candidate text for the asset-band regexes.

    Returns an empty set on any failure — the call is best-effort
    enrichment, not a correctness invariant.
    """
    if not strings_xml.is_file():
        return set()
    try:
        text = strings_xml.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    # Cheap regex extraction — avoids an XML parser dependency. The
    # only thing we need is the URL/path substring inside <string>...
    url_re = re.compile(
        r'>(https?://[^\s<>"]+|/api/[^\s<>"]+)<',
        re.IGNORECASE,
    )
    out: set[str] = set()
    hvt_words = {
        "payment", "payout", "admin", "kyc", "wallet", "vault",
        "transfer", "remit", "auth", "login", "checkout",
    }
    for m in url_re.finditer(text):
        url = m.group(1).lower()
        if any(w in url for w in hvt_words):
            out.add(url)
    return out


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
        hvt_endpoints: set[str] | None = None,
    ) -> ImpactResult:
        klass, klass_body = self._match_class(finding.vuln_class)
        base = float(klass_body.get("base_loss_usd",
                                     self._defaults.get("base_loss_usd", 5000)))
        sev_mult = float(self._defaults
                          .get("severity_multiplier", {})
                          .get(finding.severity.value, 1.0))
        asset = self._match_asset_category(finding, hvt_endpoints=hvt_endpoints)
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
    def _match_asset_category(
        finding: Finding,
        hvt_endpoints: set[str] | None = None,
    ) -> str:
        """Inspect every string-valued evidence key for HVT keywords.

        When `hvt_endpoints` is provided (a set of URL strings extracted
        from strings.xml), a finding whose evidence file/path is
        referenced *by* any HVT URL gets escalated to that URL's
        category. This catches the case where a vuln lives in a
        generic-named file (`NetworkClient.java`) that's only invoked
        from `/api/payments`.
        """
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
        # strings.xml HVT augmentation — add every HVT URL to the
        # candidate text so the regex bands can match them too.
        if hvt_endpoints:
            candidates.extend(hvt_endpoints)
        joined = " ".join(candidates)
        for label, pattern in _ASSET_BANDS:
            if pattern.search(joined):
                return label
        return "default"


# ---------- public surface ----------

default_calculator = EconomicCalculator()


def score(
    finding: Finding, tenant_plan: str = "free",
    hvt_endpoints: set[str] | None = None,
) -> ImpactResult:
    """Module-level convenience."""
    return default_calculator.score_finding(
        finding, tenant_plan=tenant_plan, hvt_endpoints=hvt_endpoints,
    )


def attach_impact(
    finding: Finding, tenant_plan: str = "free",
    hvt_endpoints: set[str] | None = None,
) -> Finding:
    """Score a finding and return a copy with the score attached.

    Sets `Finding.financial_impact_score`, appends the rationale to
    evidence['_impact'], and derives ``context_factors`` (exposure /
    controls / impact / likelihood) from the same signals the score
    uses — so the Finding Detail View's Context grid has consistent
    inputs without IMPACT_001 needing a second pass.
    """
    result = score(finding, tenant_plan=tenant_plan, hvt_endpoints=hvt_endpoints)
    new_evidence = dict(finding.evidence or {})
    new_evidence["_impact"] = result.to_evidence_block()
    return finding.model_copy(update={
        "financial_impact_score": round(result.estimate_usd, 2),
        "evidence": new_evidence,
        "context_factors": _derive_context_factors(finding, result),
    })


def _derive_context_factors(finding: Finding, result: ImpactResult) -> dict[str, str]:
    """Map score inputs onto the four user-facing context labels.

    Heuristic, intentionally short — the goal is a glanceable summary,
    not a quantitative model. The Finding Detail View renders these as
    cards under "Context."
    """
    sev = finding.severity.value
    likelihood_by_sev = {
        "Critical": "High", "High": "High", "Medium": "Medium",
        "Low": "Low", "Info": "Low",
    }
    exposure_by_asset = {
        "payment":  "Payment-flow surface",
        "admin":    "Privileged / admin surface",
        "kyc":      "KYC / identity data path",
        "wallet":   "Wallet / crypto custody path",
        "vault":    "Secrets-storage path",
        "transfer": "Money-movement surface",
        "auth":     "Authentication surface",
        "api":      "Public API surface",
        "default":  "Application-internal",
    }
    # Confidence proxies "controls in place against this finding": a
    # high-confidence finding means existing controls failed to stop
    # the analyzer from confirming it.
    if finding.confidence >= 0.85:
        controls = "Insufficient"
    elif finding.confidence >= 0.6:
        controls = "Partial"
    else:
        controls = "Likely present (low-confidence finding)"
    return {
        "exposure":   exposure_by_asset.get(result.asset_category, "Application-internal"),
        "controls":   controls,
        "impact":     f"{sev} — ${result.estimate_usd:,.0f} est. single-incident loss",
        "likelihood": likelihood_by_sev.get(sev, "Medium"),
    }


__all__ = [
    "EconomicCalculator",
    "ImpactResult",
    "attach_impact",
    "default_calculator",
    "score",
]
