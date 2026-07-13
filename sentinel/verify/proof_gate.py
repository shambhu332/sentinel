"""Final proof gate for reportable, bounty-ready findings.

Detection, verification, and exploitation are separate concerns. This module
does not try to exploit anything itself; it classifies each finding based on
the proof already collected by agents, verifiers, API replay, Frida dispatch,
and PoC generation.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from sentinel.core.finding import (
    BountyScope,
    Finding,
    ProofStatus,
    Severity,
    derive_verification_state,
)
from sentinel.core.scan_context import ScanContext

_POSITIVE_REPLAY_VERDICTS = {
    "accepted",
    "bola",
    "exploited",
    "leaked",
    "positive",
    "reflected",
    "verified",
}


@dataclass(frozen=True)
class ProofAssessment:
    status: ProofStatus
    summary: str
    requirements: dict[str, bool]
    missing: list[str]
    duplicate_key: str


def apply_proof_gate(findings: list[Finding], scan: ScanContext) -> list[Finding]:
    """Attach proof-gate fields to every finding.

    The gate is intentionally same-scan scoped. Historical duplicate handling
    should be layered on top when a durable baseline store is selected.
    """
    seen: set[str] = set()
    updated: list[Finding] = []
    for finding in findings:
        assessment = assess_proof(finding, scan.scope, seen)
        seen.add(assessment.duplicate_key)
        updated.append(finding.model_copy(update={
            "proof_status": assessment.status,
            "proof_summary": assessment.summary,
            "proof_requirements": assessment.requirements,
            "proof_missing": assessment.missing,
            "duplicate_key": assessment.duplicate_key,
            "finding_category": _finding_category(finding),
        }))
    return updated


def assess_proof(
    finding: Finding,
    scope: BountyScope,
    seen_duplicate_keys: set[str] | None = None,
) -> ProofAssessment:
    """Classify proof strength for one finding."""
    duplicate_key = _duplicate_key(finding)
    seen = seen_duplicate_keys or set()

    explicit_scope = not scope.is_unrestricted()
    in_scope = explicit_scope and _finding_in_scope(finding, scope)
    high_or_critical = finding.severity in (Severity.HIGH, Severity.CRITICAL)
    evidence_valid = _has_valid_evidence(finding)
    reachable = _has_reachability_proof(finding)
    runtime_verified = _has_runtime_verification(finding)
    poc_ready = _has_poc_or_replay(finding)
    impact_proven = _has_impact_proof(finding)
    unique = duplicate_key not in seen

    requirements = {
        "high_or_critical": high_or_critical,
        "explicit_scope": explicit_scope,
        "in_scope": in_scope,
        "reachable": reachable,
        "valid_evidence": evidence_valid,
        "runtime_verified": runtime_verified,
        "poc_ready": poc_ready,
        "impact_proven": impact_proven,
        "unique": unique,
    }
    missing = [
        label for label, ok in requirements.items()
        if not ok
    ]

    state = derive_verification_state(finding)
    exploit_status = finding.exploitation_status

    if not unique:
        status: ProofStatus = "duplicate"
    elif all(requirements.values()):
        status = "bounty_ready"
    elif exploit_status == "Verified_Exploited":
        status = "verified_exploited"
    elif exploit_status == "Auth_Gated" or state == "auth_gated":
        status = "auth_gated"
    elif exploit_status == "Runtime_Failed" or state == "runtime_failed":
        status = "runtime_failed"
    elif runtime_verified:
        status = "runtime_verified"
    elif state == "code_only" or exploit_status == "Code_Only":
        status = "code_only"
    else:
        status = "candidate"

    return ProofAssessment(
        status=status,
        summary=_summary_for(status, missing),
        requirements=requirements,
        missing=missing,
        duplicate_key=duplicate_key,
    )


def _summary_for(status: ProofStatus, missing: list[str]) -> str:
    if status == "bounty_ready":
        return (
            "Bounty-ready: explicit scope, reachability, runtime verification, "
            "PoC/replay material, impact proof, and same-scan uniqueness are present."
        )
    if status == "verified_exploited":
        return (
            "Exploit proof exists, but the finding is not bounty-ready because "
            f"these gate(s) are missing: {', '.join(missing)}."
        )
    if status == "runtime_verified":
        return (
            "Runtime verification exists, but exploit/impact proof or another "
            f"bounty gate is missing: {', '.join(missing)}."
        )
    if status == "auth_gated":
        return "Runtime proof is blocked by authentication or authorization."
    if status == "runtime_failed":
        return "Runtime proof was attempted but failed or produced no decisive proof."
    if status == "duplicate":
        return "Duplicate of another same-scan finding surface."
    if status == "code_only":
        return "Code/static evidence only; no runtime proof has been collected."
    return (
        "Candidate only; collect the missing gate(s) before treating it as "
        f"reportable: {', '.join(missing)}."
    )


def _finding_category(finding: Finding) -> str:
    """Return the Djini report bucket requested by Phase 7.6.

    Phase 7.6 is the final place where all static, triage, runtime, and
    exploitation metadata has converged. Keep the rule intentionally simple:
    a finding is AI-Powered when it has an explicit severity rationale or any
    verification state beyond Code_Only; otherwise it remains Static_Tool.
    Legacy free-form verification_status strings are tolerated during the
    migration to canonical Djini values.
    """
    if finding.severity_rationale:
        return "AI-Powered"

    state = derive_verification_state(finding)
    if state is not None:
        return "Static_Tool" if state == "code_only" else "AI-Powered"

    status = (finding.verification_status or "").strip().lower()
    if status and status not in {
        "code_only",
        "code-level only",
        "code only",
        "code-only",
    }:
        return "AI-Powered"
    return "Static_Tool"


def _finding_in_scope(finding: Finding, scope: BountyScope) -> bool:
    packages = _packages(finding)
    hosts = _hosts(finding)
    package_ok = any(scope.package_in_scope(pkg) for pkg in packages)
    host_ok = any(scope.domain_in_scope(host) for host in hosts)
    return package_ok or host_ok


def _packages(finding: Finding) -> set[str]:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    out = {
        str(v)
        for k, v in ev.items()
        if k in {"package", "target_package", "application_id"} and v
    }
    return out


def _hosts(finding: Finding) -> set[str]:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    out: set[str] = set()
    for key in ("host", "hostname", "domain"):
        value = ev.get(key)
        if value:
            out.add(str(value).lower())
    for key in ("url", "endpoint"):
        value = ev.get(key)
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            if parsed.hostname:
                out.add(parsed.hostname.lower())
    for row in finding.api_replay_logs or []:
        value = row.get("url") if isinstance(row, dict) else None
        if isinstance(value, str):
            parsed = urlparse(value)
            if parsed.hostname:
                out.add(parsed.hostname.lower())
    return out


def _has_valid_evidence(finding: Finding) -> bool:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    public_evidence = {k: v for k, v in ev.items() if not str(k).startswith("_")}
    return bool(
        public_evidence
        or finding.code_snippet
        or finding.code_snippets
        or finding.screenshots
        or finding.reproduction_commands
        or finding.observed_result
        or finding.api_replay_logs
        or finding.exploit_proof
    )


def _has_reachability_proof(finding: Finding) -> bool:
    return bool(
        _has_runtime_verification(finding)
        or _positive_replay(finding)
        or finding.exploit_proof
    )


def _has_runtime_verification(finding: Finding) -> bool:
    if finding.exploitation_status == "Verified_Exploited":
        return True
    state = derive_verification_state(finding)
    if state is not None:
        return state == "verified"
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    verify = ev.get("_verify")
    return isinstance(verify, dict) and verify.get("outcome") == "verified"


def _has_poc_or_replay(finding: Finding) -> bool:
    return bool(
        finding.poc_artifacts
        or finding.reproduction_commands
        or _positive_replay(finding)
        or finding.exploit_proof
    )


def _has_impact_proof(finding: Finding) -> bool:
    return bool(
        finding.exploitation_status == "Verified_Exploited"
        and (finding.exploit_proof or _positive_replay(finding))
    )


def _positive_replay(finding: Finding) -> bool:
    for row in finding.api_replay_logs or []:
        if not isinstance(row, dict):
            continue
        verdict = str(row.get("verdict", "")).lower()
        if verdict in _POSITIVE_REPLAY_VERDICTS:
            return True
    return False


def _duplicate_key(finding: Finding) -> str:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    parts = [
        finding.agent_id,
        finding.vuln_class,
        *sorted(_packages(finding)),
        *sorted(_hosts(finding)),
    ]
    for key in (
        "url",
        "endpoint",
        "path",
        "file",
        "component",
        "activity",
        "provider",
        "permission",
        "sink",
        "source",
    ):
        value = ev.get(key)
        if value:
            parts.append(f"{key}={value}")
    if len(parts) <= 2:
        parts.append(finding.finding_id)
    return "|".join(str(p) for p in parts)
