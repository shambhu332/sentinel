"""Sanity tests for the per-agent narrative boilerplate library."""
from __future__ import annotations

import pytest

from sentinel.agents.reporting.enrich import (
    _BOILERPLATE,
    _coerce_narrative,
    _fallback_narrative,
)
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


@pytest.mark.parametrize(
    ("agent_id", "vuln_class", "evidence", "expected"),
    [
        (
            "C_015",
            "Weak PRNG Seed",
            {
                "file": "sources/Q1/W1.java",
                "package": "com.global.edu.campus",
                "seed_expression": "nanoTime ^ currentTimeMillis",
            },
            "System\\.currentTimeMillis",
        ),
        (
            "A_004",
            "Hardcoded Secret",
            {
                "file": "res/values/strings.xml",
                "provider": "Google API Key",
                "package": "com.global.edu.campus",
            },
            "google_api_key",
        ),
        (
            "N_002",
            "Missing Certificate Pinning",
            {
                "https_usage_files": ["sources/Q1/F.java"],
                "package": "com.global.edu.campus",
            },
            "CertificatePinner",
        ),
        (
            "STG_007",
            "Insecure FileProvider Path Mapping",
            {
                "file": "res/xml/flutter_image_picker_file_paths.xml",
                "authority": "com.global.edu.campus.fileprovider",
                "path": ".",
                "package": "com.global.edu.campus",
            },
            "FileProvider|getUriForFile",
        ),
        (
            "WV_003",
            "JavaScript Interface Bridge",
            {
                "file": "a4/C0252v.java",
                "method": "postMessage",
                "class": "C0252v",
                "package": "com.global.edu.campus",
            },
            "bridgeObject.postMessage",
        ),
    ],
)
def test_report_recipes_are_vulnerability_specific(
    agent_id,
    vuln_class,
    evidence,
    expected,
):
    f = Finding(
        session_id="testabcd",
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=Severity.MEDIUM,
        confidence=0.75,
        evidence=evidence,
        recommendation="Fix the specific issue.",
    )
    narrative = _fallback_narrative(f)

    joined_steps = "\n".join(narrative["repro_steps"])
    assert "Pull the APK with `apkanalyzer`" not in joined_steps
    assert narrative["poc_snippet"]
    assert expected in narrative["poc_snippet"]


def test_generic_llm_repro_and_empty_poc_do_not_override_static_recipe():
    f = Finding(
        session_id="testabcd",
        agent_id="A_004",
        vuln_class="Hardcoded Secret",
        severity=Severity.HIGH,
        confidence=0.85,
        evidence={
            "file": "res/values/strings.xml",
            "provider": "Google API Key",
            "package": "com.global.edu.campus",
        },
        recommendation="Remove the secret.",
    )

    narrative = _coerce_narrative(
        {
            "summary": "A hardcoded key exists.",
            "repro_steps": [
                "Install the application on a test device.",
                "Run the application.",
                "Verify the vulnerability.",
            ],
            "poc_snippet": (
                "No safe, generic PoC snippet is appropriate for this "
                "finding without manual triage."
            ),
            "impact_bullets": ["Generic impact."],
            "fix_bullets": ["Generic fix."],
        },
        f,
    )

    assert any("Decode the APK" in step for step in narrative["repro_steps"])
    assert "google_api_key" in narrative["poc_snippet"]
    assert "Generic impact." not in narrative["impact_bullets"]
    assert "Generic fix." not in narrative["fix_bullets"]


def test_report_agents_from_campus_sample_do_not_share_one_recipe():
    fixtures = [
        ("C_015", "Weak PRNG Seed", {"file": "sources/Q1/W1.java"}),
        ("P_005", "Sensitive Permission: SYSTEM_ALERT_WINDOW", {
            "permission": "android.permission.SYSTEM_ALERT_WINDOW",
            "package": "com.global.edu.campus",
        }),
        ("IPC_001", "Exposed IPC Component", {
            "package": "com.global.edu.campus",
            "components": [{"name": "com.example.vcheck.MainActivity"}],
        }),
        ("RES_002", "InputStream Leak", {
            "file": "sources/F0/r.java",
            "variable": "fileInputStream",
            "package": "com.global.edu.campus",
        }),
    ]
    recipes = []
    for agent_id, vuln_class, evidence in fixtures:
        f = Finding(
            session_id="testabcd",
            agent_id=agent_id,
            vuln_class=vuln_class,
            severity=Severity.MEDIUM,
            confidence=0.7,
            evidence=evidence,
            recommendation="Fix.",
        )
        narrative = _fallback_narrative(f)
        recipes.append("\n".join(narrative["repro_steps"]))

    assert len(set(recipes)) == len(recipes)
