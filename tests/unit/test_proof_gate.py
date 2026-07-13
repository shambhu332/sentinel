"""Tests for the final proof/readiness gate."""
from __future__ import annotations

from pathlib import Path

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext
from sentinel.verify.proof_gate import apply_proof_gate


def _scan(tmp_path: Path, *, scope: BountyScope | None = None) -> ScanContext:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    return ScanContext(
        session_id="proofsess123",
        apk_path=apk,
        workspace=tmp_path / "workspace",
        scope=scope or BountyScope(),
    )


def _api_finding(**overrides) -> Finding:
    data = {
        "agent_id": "API_002",
        "vuln_class": "Broken Object Level Authorization",
        "severity": Severity.CRITICAL,
        "confidence": 0.95,
        "session_id": "proofsess123",
        "recommendation": "Enforce object-level authorization.",
        "evidence": {
            "host": "api.example.com",
            "endpoint": "https://api.example.com/v1/users/42",
            "method": "GET",
            "_verify": {
                "outcome": "verified",
                "method": "active-replay",
                "confidence": 0.95,
                "evidence": {"status": 200},
                "notes": "",
            },
        },
        "verification_state": "verified",
        "exploitation_status": "Verified_Exploited",
        "exploit_proof": "Mutated user id returned another account profile.",
        "api_replay_logs": [{
            "url": "https://api.example.com/v1/users/43",
            "verdict": "bola",
            "status": 200,
            "response_snippet": "{\"email\":\"victim@example.com\"}",
        }],
        "poc_artifacts": ["poc_artifacts/api_002_replay.py"],
    }
    data.update(overrides)
    return Finding(**data)


def test_bounty_ready_requires_all_proof_gates(tmp_path: Path):
    scope = BountyScope(in_scope_domains=["api.example.com"])
    [finding] = apply_proof_gate([_api_finding()], _scan(tmp_path, scope=scope))

    assert finding.proof_status == "bounty_ready"
    assert finding.proof_requirements
    assert all(finding.proof_requirements.values())
    assert finding.proof_missing == []


def test_unrestricted_scope_prevents_bounty_ready(tmp_path: Path):
    [finding] = apply_proof_gate([_api_finding()], _scan(tmp_path))

    assert finding.proof_status == "verified_exploited"
    assert finding.proof_requirements
    assert finding.proof_requirements["explicit_scope"] is False
    assert "explicit_scope" in finding.proof_missing


def test_code_only_finding_stays_candidate_not_bounty_ready(tmp_path: Path):
    scope = BountyScope(in_scope_domains=["api.example.com"])
    finding = _api_finding(
        verification_state="code_only",
        exploitation_status="Code_Only",
        exploit_proof=None,
        api_replay_logs=[],
        poc_artifacts=[],
    )

    [updated] = apply_proof_gate([finding], _scan(tmp_path, scope=scope))

    assert updated.proof_status == "code_only"
    assert "runtime_verified" in updated.proof_missing
    assert "impact_proven" in updated.proof_missing


def test_same_scan_duplicate_is_not_bounty_ready(tmp_path: Path):
    scope = BountyScope(in_scope_domains=["api.example.com"])
    f1 = _api_finding()
    f2 = _api_finding(session_id="proofsess123")

    first, second = apply_proof_gate([f1, f2], _scan(tmp_path, scope=scope))

    assert first.proof_status == "bounty_ready"
    assert second.proof_status == "duplicate"
    assert second.proof_requirements
    assert second.proof_requirements["unique"] is False
