"""Sanity tests for the per-agent narrative boilerplate library."""
from __future__ import annotations

import pytest

from sentinel.agents.reporting.enrich import _BOILERPLATE, _fallback_narrative
from sentinel.core.finding import Finding, Severity


@pytest.mark.parametrize("agent_id", [
    # Static / SAST seed library
    "P_001", "A_001", "B_002", "N_002", "P_010",
    # Dynamic agents shipped this sprint
    "D_001", "D_002", "D_003", "D_005", "D_007", "D_009",
    "D_010", "D_011", "D_012", "D_013", "D_014", "D_015",
    "D_016", "D_017", "D_018", "D_019",
])
def test_boilerplate_is_well_formed(agent_id):
    bp = _BOILERPLATE[agent_id]
    assert bp["summary"], f"{agent_id} missing summary"
    assert isinstance(bp["summary"], str)
    assert len(bp["summary"]) >= 100, f"{agent_id} summary too short"
    assert bp["fix_bullets"], f"{agent_id} missing fix_bullets"
    assert isinstance(bp["fix_bullets"], list)
    assert all(isinstance(b, str) for b in bp["fix_bullets"])
    assert bp["references"], f"{agent_id} missing references"
    assert all(isinstance(r, dict)
               and "label" in r and "url" in r
               for r in bp["references"])
    # impact_bullets / repro_steps optional but well-typed when present
    for key in ("impact_bullets", "repro_steps"):
        if key in bp:
            assert isinstance(bp[key], list)
            assert all(isinstance(b, str) for b in bp[key])


def test_fallback_uses_boilerplate_when_keyed():
    f = Finding(
        session_id="testabcd",
        agent_id="D_007",
        vuln_class="Race condition",
        severity=Severity.HIGH,
        confidence=0.75,
        evidence={"host": "api.example.com",
                  "method": "POST",
                  "path": "/api/v1/coupon/redeem"},
        recommendation="x",
    )
    narrative = _fallback_narrative(f)
    assert "TOCTOU" in narrative["summary"]
    assert any("Idempotency-Key" in b for b in narrative["fix_bullets"])


def test_fallback_synthesises_when_no_boilerplate():
    f = Finding(
        session_id="testabcd",
        agent_id="ZZZ_999",
        vuln_class="Synthetic class",
        severity=Severity.MEDIUM,
        confidence=0.6,
        evidence={"issue": "Specific scanner-derived issue"},
        recommendation="apply x. also do y. and finally z.",
    )
    narrative = _fallback_narrative(f)
    assert narrative["summary"]
    assert narrative["fix_bullets"]
    # Recommendation split into bullets on '. '
    assert len(narrative["fix_bullets"]) >= 2
