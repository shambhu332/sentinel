"""Tests for the visionary-tier batch:
   IMPACT_001, SWARM_001, SCA_004, LEARN_001, COMPLIANCE_001, FEEDBACK_001.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.supply_chain.sca004_malicious_lib_detector import (
    MaliciousLibDetectorAgent,
)
from sentinel.compliance import (
    attach_compliance_tags,
    default_mapper,
    render_markdown,
)
from sentinel.core.finding import BountyScope, Finding, Severity, TriageState
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.impact import attach_impact, default_calculator, score
from sentinel.learning import (
    AppLearningProfile,
    AppProfileStore,
    FeedbackLoop,
)
from sentinel.memory import LightweightMemory
from sentinel.swarm import SwarmOrchestrator, sanitize_evidence
from sentinel.swarm.sanitize import sanitize_text


# ============================================================
# Finding schema additions
# ============================================================

def _f(agent_id="A_004", vuln_class="Hardcoded Secret",
       sev=Severity.HIGH, evidence=None) -> Finding:
    return Finding(
        agent_id=agent_id, vuln_class=vuln_class, severity=sev,
        confidence=0.9, recommendation="x",
        session_id="sess_vbatch01", evidence=evidence or {},
    )


def test_finding_carries_financial_score():
    f = _f().model_copy(update={"financial_impact_score": 123.45})
    assert f.financial_impact_score == 123.45


def test_finding_carries_compliance_tags():
    f = _f().model_copy(update={"compliance_tags": ["GDPR Art. 32"]})
    assert "GDPR Art. 32" in f.compliance_tags


def test_finding_rejects_negative_impact_score():
    # Direct construction goes through the field validator
    with pytest.raises(ValueError):
        Finding(
            agent_id="A_004", vuln_class="X", severity=Severity.HIGH,
            confidence=0.5, recommendation="r",
            session_id="sess_neg_test", financial_impact_score=-1.0,
        )


# ============================================================
# IMPACT_001
# ============================================================

def test_impact_scores_hardcoded_secret_high():
    f = _f("A_004", "Hardcoded Secret", Severity.CRITICAL,
           evidence={"file": "PaymentService.java"})
    r = score(f, tenant_plan="enterprise")
    # base 40k * sev 4.0 * payment 3.0 * enterprise 1.5
    assert r.estimate_usd > 500_000
    assert r.asset_category == "payment"
    assert r.vuln_class_matched == "hardcoded_secret"


def test_impact_falls_back_to_default_class():
    f = _f("X_999", "Some Vuln Class We Have Not Categorised",
           Severity.LOW, evidence={"file": "App.java"})
    r = score(f, tenant_plan="free")
    assert r.vuln_class_matched == "default"
    assert r.estimate_usd > 0


def test_attach_impact_populates_finding_field():
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH,
           evidence={"file": "Auth.java"})
    out = attach_impact(f, tenant_plan="pro")
    assert out.financial_impact_score is not None
    assert out.financial_impact_score > 0
    assert "_impact" in (out.evidence or {})


def test_impact_asset_category_for_admin_path():
    f = _f("B_007", "Client-Side Authorisation",
           Severity.HIGH, evidence={"file": "AdminPanel.java"})
    r = score(f)
    assert r.asset_category == "admin"


# ============================================================
# SWARM_001 — sanitiser
# ============================================================

def test_sanitize_strips_secrets():
    s = sanitize_text(
        "AWS key AKIAIOSFODNN7EXAMPLE in com.acme.payments at /src/main/Pay.java"
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in s
    assert "<aws-key>" in s
    assert "com.acme.payments" not in s
    assert "<pkg>" in s
    assert "/src/main/Pay.java" not in s
    assert "<file>" in s


def test_sanitize_evidence_recurses():
    ev = {
        "file": "/src/x.java",
        "matches": [
            {"path": "/lib/y.java", "value": "AKIAIOSFODNN7EXAMPLE"},
        ],
        "ok": 42,
    }
    cleaned = sanitize_evidence(ev)
    assert "<file>" in cleaned["file"]
    assert "<file>" in cleaned["matches"][0]["path"]
    assert "<aws-key>" in cleaned["matches"][0]["value"]
    assert cleaned["ok"] == 42  # non-string left alone


# ============================================================
# SWARM_001 — orchestrator
# ============================================================

@pytest.mark.asyncio
async def test_swarm_skips_below_severity_floor():
    async def fake_llm(**kw):
        raise AssertionError("LLM must not be called for low severity")
    s = SwarmOrchestrator(llm_query=fake_llm)
    res = await s.run_one(_f(sev=Severity.LOW))
    assert res.red is None and res.blue is None
    assert res.error and "below floor" in res.error


@pytest.mark.asyncio
async def test_swarm_runs_red_then_blue_and_caches():
    calls = []

    async def fake_llm(messages, **kw):
        calls.append(messages[0]["content"][:6])
        if "Red Agent" in messages[0]["content"]:
            return {"content": '{"poc_pseudocode": "step1; step2",'
                               ' "exploitation_steps": ["a","b"],'
                               ' "impact_narrative": "loss is X"}'}
        return {"content": '{"semgrep_rule": "rules: [...]",'
                           ' "waf_rule": "SecRule REQUEST_URI ..",'
                           ' "log_signature": "regex"}'}

    s = SwarmOrchestrator(llm_query=fake_llm)
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH,
           evidence={"file": "X.java", "snippet": "AKIAIOSFODNN7EXAMPLE"})
    r1 = await s.run_one(f)
    assert r1.red is not None
    assert r1.blue is not None
    assert r1.cached is False
    assert r1.red.poc_pseudocode == "step1; step2"
    # Second run with same finding hits cache
    r2 = await s.run_one(f)
    assert r2.cached is True
    # 2 LLM calls only (one per role), not 4
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_swarm_sanitises_evidence_before_calling_llm():
    captured: list[str] = []

    async def fake_llm(messages, **kw):
        captured.append(messages[1]["content"])
        return {"content": '{"poc_pseudocode": "",'
                           ' "exploitation_steps": [],'
                           ' "impact_narrative": ""}'}

    s = SwarmOrchestrator(llm_query=fake_llm)
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH,
           evidence={"file": "/src/com/acme/Pay.java",
                     "snippet": "key=AKIAIOSFODNN7EXAMPLE"})
    await s.run_one(f)
    user_prompt = captured[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in user_prompt
    assert "/src/com/acme/Pay.java" not in user_prompt


# ============================================================
# SCA_004
# ============================================================

def _ctx_with_libs(tmp_path: Path, libs: dict[str, dict[str, str]]) -> ScanContext:
    apk = tmp_path / "t.apk"
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    for lib_path, files in libs.items():
        d = decompiled
        for part in lib_path.split("/"):
            d = d / part
            d.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (d / name).write_text(content)
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    ctx.manifest = {"package": "com.app.real"}
    return ctx


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


@pytest.mark.asyncio
async def test_sca004_flags_utility_with_http(tmp_path, memory):
    ctx = _ctx_with_libs(tmp_path, {
        "io/utils/strings": {
            "Strings.java":
                "package io.utils.strings;\n"
                "class Strings {\n"
                "  void leak() { OkHttpClient c = new OkHttpClient(); }\n"
                "}\n",
        },
    })
    findings = await MaliciousLibDetectorAgent(context=ctx, memory=memory).analyze()
    assert any(
        "Mission Creep" in f.vuln_class and "http_call" in (f.evidence.get("primitive") or "")
        for f in findings
    )


# ============================================================
# LEARN_001
# ============================================================

def test_app_profile_store_roundtrip(tmp_path):
    s = AppProfileStore(root=tmp_path / "learning")
    p = s.load("a" * 64)
    assert p.scans_count == 0
    p.scans_count = 1
    p.record_triage("fp1234", "Hardcoded Secret", "A_004", "False Positive")
    s.save(p)
    p2 = s.load("a" * 64)
    assert p2.scans_count == 1
    assert p2.is_known_false_positive("fp1234")


def test_app_profile_record_scan_start_increments(tmp_path):
    s = AppProfileStore(root=tmp_path / "learning")
    p1 = s.record_scan_start("b" * 64, package="com.app")
    assert p1.scans_count == 1
    p2 = s.record_scan_start("b" * 64)
    assert p2.scans_count == 2
    assert p2.package == "com.app"


def test_app_profile_priors_need_minimum_samples():
    p = AppLearningProfile(apk_sha256="c" * 64)
    # Two TPs is not enough — returns None
    p.record_triage("x1", "V", "A_004", "True Positive")
    p.record_triage("x2", "V", "A_004", "True Positive")
    assert p.prior_accept_rate("A_004", "V") is None
    # Three is enough
    p.record_triage("x3", "V", "A_004", "False Positive")
    rate = p.prior_accept_rate("A_004", "V")
    assert rate is not None
    assert abs(rate - 2 / 3) < 1e-6


# ============================================================
# FEEDBACK_001
# ============================================================

def test_feedback_record_outcome_then_adjust():
    profile = AppLearningProfile(apk_sha256="d" * 64)
    loop = FeedbackLoop(profile=profile)
    # 5 outcomes mostly FP
    for i in range(5):
        outcome = "refuted" if i < 4 else "verified"
        loop.record_outcome(_f("A_004", "Hardcoded Secret"), outcome)
    # Each record_outcome creates a unique fingerprint? No — record_outcome
    # uses Finding.finding_id which is content-hashed. Two calls on the same
    # finding overwrite. Adjust the test:
    for i, outcome in enumerate(["refuted"] * 4 + ["verified"]):
        f = _f("A_004", f"Hardcoded Secret v{i}",
               sev=Severity.HIGH, evidence={"k": str(i)})
        loop.record_outcome(f, outcome)
    # 4 FP + 1 TP -> accept rate ~0.2 across the variant vuln_class strings
    # so the prior is split across keys. Use a single vuln_class for the
    # actual assertion:
    profile = AppLearningProfile(apk_sha256="e" * 64)
    loop = FeedbackLoop(profile=profile)
    for i, outcome in enumerate(["refuted"] * 4 + ["verified"]):
        f = _f("A_004", "Hardcoded Secret",
               sev=Severity.HIGH, evidence={"k": str(i)})
        loop.record_outcome(f, outcome)
    auto = loop.auto_triage("A_004", "Hardcoded Secret")
    assert auto == TriageState.NEEDS_VERIFICATION


def test_feedback_adjusted_confidence_within_bounds():
    profile = AppLearningProfile(apk_sha256="f" * 64)
    loop = FeedbackLoop(profile=profile)
    # No history -> no adjustment
    assert loop.adjusted_confidence("A_004", "Hardcoded Secret", 0.9) == 0.9
    # Build history: all TPs -> multiplier 1.3 (capped)
    for i in range(5):
        f = _f("A_004", "Hardcoded Secret",
               sev=Severity.HIGH, evidence={"k": str(i)})
        loop.record_outcome(f, "verified")
    adj = loop.adjusted_confidence("A_004", "Hardcoded Secret", 0.5)
    assert adj > 0.5  # bumped
    assert adj <= 1.0  # clamped to valid Pydantic range


# ============================================================
# COMPLIANCE_001
# ============================================================

def test_attach_compliance_tags_populates():
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH)
    [out] = attach_compliance_tags([f])
    assert any("PCI-DSS" in t for t in out.compliance_tags)
    assert any("GDPR" in t for t in out.compliance_tags)


def test_attach_compliance_no_double_population():
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH).model_copy(
        update={"compliance_tags": ["GDPR Art. 32(1)(a)"]},
    )
    [out] = attach_compliance_tags([f])
    # Existing tag preserved, new ones appended
    assert "GDPR Art. 32(1)(a)" in out.compliance_tags
    assert any("PCI-DSS" in t for t in out.compliance_tags)


def test_render_markdown_groups_by_framework():
    findings = [
        _f("A_004", "Hardcoded Secret", Severity.CRITICAL,
           evidence={"file": "Pay.java"}),
        _f("PRIV_001", "Pre-Consent Sensitive Data Collection",
           Severity.HIGH, evidence={"file": "App.java"}),
    ]
    md = render_markdown(findings, app_name="TestApp",
                          session_id="abcdefgh1234")
    assert "# Compliance Audit Report — TestApp" in md
    assert "## GDPR" in md
    assert "## PCI-DSS" in md
    assert "abcdefgh1234" in md


def test_render_markdown_uncategorised_section():
    f = _f("Z_999", "Some Brand-New Vuln Type", Severity.LOW)
    md = render_markdown([f], app_name="X")
    assert "## Uncategorised" in md
    assert "Z_999" in md


def test_soc2_present_in_default_mapper():
    cites = default_mapper.cite_by_agent_id("A_004")
    assert any(c.framework == "SOC2" for c in cites)
    cites = default_mapper.cite_by_agent_id("PRIV_001")
    assert any(c.framework == "SOC2" for c in cites)
