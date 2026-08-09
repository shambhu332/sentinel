from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from sentinel.core.finding import Finding, Severity

MASVS_V2_CONTROLS: dict[str, str] = {
    "MASVS-STORAGE-1": "User credential storage",
    "MASVS-STORAGE-2": "Sensitive data storage",
    "MASVS-CRYPTO-1": "Cryptography configuration",
    "MASVS-CRYPTO-2": "Key management",
    "MASVS-AUTH-1": "User authentication",
    "MASVS-AUTH-2": "Biometric authentication",
    "MASVS-AUTH-3": "Authentication factor management",
    "MASVS-NETWORK-1": "Secure communication",
    "MASVS-NETWORK-2": "TLS configuration",
    "MASVS-PLATFORM-1": "Component interaction",
    "MASVS-PLATFORM-2": "WebView interaction",
    "MASVS-PLATFORM-3": "UI interaction",
    "MASVS-CODE-1": "Code quality",
    "MASVS-CODE-2": "Dependency management",
    "MASVS-CODE-3": "Anti-tampering",
    "MASVS-CODE-4": "Memory safety",
    "MASVS-RESILIENCE-1": "Application integrity",
    "MASVS-RESILIENCE-2": "Anti-reversing",
    "MASVS-RESILIENCE-3": "Device binding",
    "MASVS-RESILIENCE-4": "Network interception prevention",
    "MASVS-PRIVACY-1": "Data minimization",
    "MASVS-PRIVACY-2": "Data retention",
    "MASVS-PRIVACY-3": "Third-party data sharing",
}

LEGACY_MSTG_MAP: dict[str, str] = {
    "MSTG-STORAGE-1": "MASVS-STORAGE-1",
    "MSTG-STORAGE-2": "MASVS-STORAGE-2",
    "MSTG-CRYPTO-1": "MASVS-CRYPTO-1",
    "MSTG-CRYPTO-2": "MASVS-CRYPTO-2",
    "MSTG-AUTH-1": "MASVS-AUTH-1",
    "MSTG-AUTH-8": "MASVS-AUTH-2",
    "MSTG-NETWORK-1": "MASVS-NETWORK-1",
    "MSTG-NETWORK-2": "MASVS-NETWORK-2",
    "MSTG-PLATFORM-1": "MASVS-PLATFORM-1",
    "MSTG-PLATFORM-2": "MASVS-PLATFORM-2",
    "MSTG-CODE-1": "MASVS-CODE-1",
    "MSTG-CODE-4": "MASVS-CODE-3",
    "MSTG-RESILIENCE-1": "MASVS-RESILIENCE-1",
}

# Weighted deduction per finding (not per control).
# Adapted from DragonJAR Android-Pentesting-Skill scoring model.
_DEDUCTION_WEIGHTS: dict[str, int] = {
    "Critical": 10,
    "High": 5,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}

_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class ControlResult:
    control_id: str
    description: str
    status: Literal["pass", "fail", "not_tested"]
    severity: str | None
    finding_ids: list[str] = field(default_factory=list)


@dataclass
class MavsScore:
    score: float
    grade: str
    controls_total: int
    controls_passed: int
    controls_failed: int
    controls_not_tested: int
    total_deductions: int
    results: list[ControlResult] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "controls_total": self.controls_total,
            "controls_passed": self.controls_passed,
            "controls_failed": self.controls_failed,
            "controls_not_tested": self.controls_not_tested,
            "total_deductions": self.total_deductions,
            "results": [
                {
                    "control_id": r.control_id,
                    "description": r.description,
                    "status": r.status,
                    "severity": r.severity,
                    "finding_ids": r.finding_ids,
                }
                for r in self.results
            ],
        }

    def summary_text(self) -> str:
        return (
            f"MASVS Score: {self.score:.1f}/100 (Grade: {self.grade})"
            f" — {self.controls_passed}/{self.controls_total} controls passed,"
            f" {self.controls_failed} failed,"
            f" {self.controls_not_tested} not tested"
        )


def _normalize_control_id(raw: str) -> str | None:
    upper = raw.strip().upper()
    if upper in MASVS_V2_CONTROLS:
        return upper
    return LEGACY_MSTG_MAP.get(upper)


def _grade(score: float) -> str:
    """DragonJAR-aligned grade thresholds."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


class MavsScorer:
    """MASVS v2 compliance scorer using weighted-deduction model.

    Scoring model (adapted from DragonJAR Android-Pentesting-Skill):
      score = max(0, 100 - sum(weight * finding_count_per_severity))
      weights: Critical=10, High=5, Medium=2, Low=1, Info=0

    Control status semantics:
      fail       — one or more findings reference this control
      not_tested — no finding (of any severity) references this control;
                   the scanner did not produce evidence either way
      pass       — reserved for explicit agent attestation (currently unused
                   since agents only emit findings, not passing verdicts)
    """

    def score(self, findings: list[Finding]) -> MavsScore:
        # Group non-Info findings by control_id for control-level status
        failing: dict[str, list[Finding]] = {}
        # Track all referenced controls (including Info) so we know what was touched
        referenced: set[str] = set()

        total_deductions = 0

        for f in findings:
            raw = f.masvs
            if not raw:
                continue
            control_id = _normalize_control_id(raw)
            if control_id is None:
                continue

            sev_value = f.severity.value if f.severity else "Info"
            weight = _DEDUCTION_WEIGHTS.get(sev_value, 0)
            total_deductions += weight

            # Info findings are informational observations (e.g. RASP detected)
            # — they do not represent a pass verdict, only that the control was
            # touched. Only non-Info findings drive control failure.
            if sev_value != "Info":
                referenced.add(control_id)
                failing.setdefault(control_id, []).append(f)

        score = max(0.0, 100.0 - total_deductions)

        results: list[ControlResult] = []
        for control_id, description in MASVS_V2_CONTROLS.items():
            if control_id in failing:
                failed_findings = failing[control_id]
                worst = min(
                    failed_findings,
                    key=lambda f: _SEVERITY_RANK.get(f.severity.value, 99),
                )
                results.append(ControlResult(
                    control_id=control_id,
                    description=description,
                    status="fail",
                    severity=worst.severity.value,
                    finding_ids=[f.finding_id for f in failed_findings],
                ))
            else:
                # No agent produced evidence for this control
                results.append(ControlResult(
                    control_id=control_id,
                    description=description,
                    status="not_tested",
                    severity=None,
                    finding_ids=[],
                ))

        total = len(MASVS_V2_CONTROLS)
        passed = sum(1 for r in results if r.status == "pass")
        failed = sum(1 for r in results if r.status == "fail")
        not_tested = sum(1 for r in results if r.status == "not_tested")

        return MavsScore(
            score=round(score, 1),
            grade=_grade(score),
            controls_total=total,
            controls_passed=passed,
            controls_failed=failed,
            controls_not_tested=not_tested,
            total_deductions=total_deductions,
            results=results,
        )
