"""Tests for the 4 visionary deltas:
   Purple swarm agent · strings.xml HVT · ISO 27001 · SCA_004 graph view.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.supply_chain.sca004_malicious_lib_detector import (
    MaliciousLibDetectorAgent,
)
from sentinel.compliance import default_mapper, render_markdown
from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.impact import (
    extract_hvt_endpoints_from_strings_xml,
    score,
)
from sentinel.swarm import SwarmOrchestrator


def _f(agent_id="A_004", vuln_class="Hardcoded Secret",
       sev=Severity.HIGH, evidence=None) -> Finding:
    return Finding(
        agent_id=agent_id, vuln_class=vuln_class, severity=sev,
        confidence=0.9, recommendation="x",
        session_id="sess_delta001", evidence=evidence or {},
    )


@pytest.fixture
async def memory(tmp_path):
    from sentinel.memory import LightweightMemory
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ============================================================
# Delta 1 — Purple agent
# ============================================================

@pytest.mark.asyncio
async def test_purple_disabled_by_default():
    async def fake_llm(messages, **kw):
        role = messages[0]["content"][:11]
        if "Red Agent" in messages[0]["content"]:
            return {"content": '{"poc_pseudocode":"step","exploitation_steps":[],"impact_narrative":"x"}'}
        if "Blue Agent" in messages[0]["content"]:
            return {"content": '{"semgrep_rule":"r","waf_rule":"w","log_signature":"l"}'}
        raise AssertionError(f"Purple was called but should be disabled: {role}")
    s = SwarmOrchestrator(llm_query=fake_llm)
    r = await s.run_one(_f(sev=Severity.HIGH,
                           evidence={"file": "Pay.java", "snippet": "x"}))
    assert r.purple is None


@pytest.mark.asyncio
async def test_purple_runs_when_enabled():
    async def fake_llm(messages, **kw):
        sys = messages[0]["content"]
        if "Red Agent" in sys:
            return {"content": '{"poc_pseudocode":"step","exploitation_steps":["a"],"impact_narrative":"x"}'}
        if "Blue Agent" in sys:
            return {"content": '{"semgrep_rule":"r","waf_rule":"w","log_signature":"l"}'}
        # Purple
        return {"content":
            '{"business_narrative": "Customer trust collapses if Y.",'
            ' "affected_stakeholders": ["customers", "regulators", "merchants"],'
            ' "estimated_blast_radius": "every account in EU + US"}'}
    s = SwarmOrchestrator(llm_query=fake_llm, purple_enabled=True)
    r = await s.run_one(_f(sev=Severity.HIGH,
                           evidence={"file": "Pay.java", "snippet": "x"}))
    assert r.purple is not None
    assert "customer" in r.purple.business_narrative.lower()
    assert "regulators" in r.purple.affected_stakeholders


# ============================================================
# Delta 2 — strings.xml HVT extraction + IMPACT augmentation
# ============================================================

def test_extract_hvt_pulls_payment_url(tmp_path):
    sx = tmp_path / "strings.xml"
    sx.write_text(
        '<resources>\n'
        '  <string name="home_url">https://example.com/</string>\n'
        '  <string name="pay_url">https://api.example.com/payments/transfer</string>\n'
        '  <string name="admin">/api/admin/users</string>\n'
        '</resources>\n'
    )
    hvt = extract_hvt_endpoints_from_strings_xml(sx)
    assert any("payments" in u for u in hvt)
    assert any("admin" in u for u in hvt)
    assert not any("example.com/" == u for u in hvt)  # generic URL skipped


def test_extract_hvt_missing_file_returns_empty(tmp_path):
    assert extract_hvt_endpoints_from_strings_xml(tmp_path / "nope.xml") == set()


def test_impact_uses_hvt_to_categorize_generic_file():
    # A vulnerability in a generic-named file
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH,
           evidence={"file": "NetworkClient.java"})
    # Without HVT — falls back to default category
    r1 = score(f)
    # With HVT URLs referencing payments — should escalate
    hvt = {"https://api.example.com/payments/transfer"}
    r2 = score(f, hvt_endpoints=hvt)
    assert r1.asset_category == "default"
    assert r2.asset_category in {"payment", "transfer"}
    assert r2.estimate_usd > r1.estimate_usd


# ============================================================
# Delta 3 — ISO 27001 in compliance mappings
# ============================================================

def test_iso27001_present_in_mapper():
    for aid in ("A_004", "N_001", "I_001", "PRIV_001",
                "C_018", "LOGIC_001", "RES_002", "SCA_004"):
        cites = default_mapper.cite_by_agent_id(aid)
        assert any(c.framework == "ISO27001" for c in cites), \
            f"{aid} missing ISO27001 citation"


def test_render_markdown_includes_iso27001():
    f = _f("A_004", "Hardcoded Secret", Severity.HIGH,
           evidence={"file": "Auth.java"})
    md = render_markdown([f], app_name="TestApp")
    assert "## ISO27001" in md
    assert "A.8.24" in md


# ============================================================
# Delta 4 — SCA_004 NetworkX graph evidence
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


@pytest.mark.asyncio
async def test_sca004_emits_graph_finding(tmp_path, memory):
    ctx = _ctx_with_libs(tmp_path, {
        "io/utils/strings": {
            "Strings.java":
                "package io.utils.strings;\n"
                "class Strings {\n"
                "  void leak() { OkHttpClient c = new OkHttpClient(); }\n"
                "}\n",
        },
        "io/utils/math": {
            "Math.java":
                "package io.utils.math;\n"
                "class Math { void x() { Runtime.getRuntime().exec(\"\"); } }\n",
        },
    })
    findings = await MaliciousLibDetectorAgent(context=ctx, memory=memory).analyze()
    graph_findings = [
        f for f in findings
        if f.vuln_class == "Third-Party Library Behaviour Graph"
    ]
    assert len(graph_findings) == 1
    g = graph_findings[0].evidence.get("graph") or {}
    assert g.get("library_count") >= 1
    # Two distinct primitives: http_call and runtime_exec
    assert g.get("primitive_count") >= 2
    nodes = g.get("nodes") or []
    edges = g.get("edges") or []
    assert any(n.get("type") == "library" for n in nodes)
    assert any(n.get("type") == "primitive" for n in nodes)
    assert all("source" in e and "target" in e for e in edges)
