"""End-to-end wiring tests for the visionary Phase 2.6 enrichment."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.scan_context import ScanContext, generate_session_id


def _apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=_apk(tmp_path / "t.apk"),
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )


class _StubScanResult:
    def __init__(self) -> None:
        self.warnings: list[str] = []


@pytest.fixture
async def memory(tmp_path):
    from sentinel.memory import LightweightMemory
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


def _finding(severity: Severity = Severity.HIGH, **kw) -> Finding:
    return Finding(
        agent_id=kw.get("agent_id", "A_004"),
        vuln_class=kw.get("vuln_class", "Hardcoded Secret"),
        severity=severity,
        confidence=0.9,
        recommendation="x",
        session_id="sess_wire0001",
        evidence=kw.get("evidence", {"file": "Pay.java"}),
    )


# ============================================================
# Phase 2.6 — impact + compliance attach
# ============================================================

@pytest.mark.asyncio
async def test_phase26_impact_and_compliance_attached(tmp_path, memory):
    ctx = _ctx(tmp_path)
    orch = Orchestrator(
        context=ctx, memory=memory, agents=[],
        impact_enabled=True,
        compliance_tags_enabled=True,
        swarm_enabled=False,
    )
    findings = [_finding()]
    out = await orch._phase26_enrich(findings, _StubScanResult())
    assert len(out) == 1
    assert out[0].financial_impact_score is not None
    assert out[0].financial_impact_score > 0
    assert any("PCI-DSS" in t for t in out[0].compliance_tags)
    assert any("GDPR" in t for t in out[0].compliance_tags)
    assert "_impact" in (out[0].evidence or {})


@pytest.mark.asyncio
async def test_phase26_respects_disabled_flags(tmp_path, memory):
    ctx = _ctx(tmp_path)
    orch = Orchestrator(
        context=ctx, memory=memory, agents=[],
        impact_enabled=False,
        compliance_tags_enabled=False,
        swarm_enabled=False,
    )
    findings = [_finding()]
    out = await orch._phase26_enrich(findings, _StubScanResult())
    assert out[0].financial_impact_score is None
    assert out[0].compliance_tags == []


@pytest.mark.asyncio
async def test_phase26_swarm_runs_with_injected_llm(tmp_path, memory):
    ctx = _ctx(tmp_path)

    async def fake_llm(messages, **kw):
        if "Red Agent" in messages[0]["content"]:
            return {"content": '{"poc_pseudocode": "step1",'
                               ' "exploitation_steps": ["a"],'
                               ' "impact_narrative": "loss"}'}
        return {"content": '{"semgrep_rule": "rules: ...",'
                           ' "waf_rule": "SecRule ...",'
                           ' "log_signature": "/regex/"}'}

    orch = Orchestrator(
        context=ctx, memory=memory, agents=[],
        impact_enabled=False,
        compliance_tags_enabled=False,
        swarm_enabled=True,
        swarm_llm_query=fake_llm,
    )
    findings = [_finding(Severity.HIGH), _finding(Severity.LOW,
                                                    evidence={"file": "Low.java"})]
    out = await orch._phase26_enrich(findings, _StubScanResult())
    # HIGH finding gets a swarm block; LOW is below floor
    by_sev = {f.severity: f for f in out}
    assert "_swarm" in (by_sev[Severity.HIGH].evidence or {})
    assert "_swarm" not in (by_sev[Severity.LOW].evidence or {})


# ============================================================
# Phase 0.5 — learning profile load
# ============================================================

def test_learning_profile_loaded_at_phase0(tmp_path):
    # We exercise the helper directly — running the full Phase 0
    # would require a real APK + decompiler infrastructure.
    ctx = _ctx(tmp_path)
    ctx.apk_sha256 = "f" * 64
    ctx.manifest = {"package": "com.testapp"}

    from sentinel.memory import LightweightMemory
    async def _go():
        memory = LightweightMemory(data_dir=tmp_path / "data")
        await memory.connect()
        try:
            orch = Orchestrator(
                context=ctx, memory=memory, agents=[],
                learning_dir=tmp_path / "learning",
            )
            orch._maybe_load_learning_profile()
            assert ctx.learning_profile is not None
            assert ctx.learning_profile.scans_count == 1
            assert ctx.learning_profile.package == "com.testapp"
            # Second invocation increments
            orch._maybe_load_learning_profile()
            assert ctx.learning_profile.scans_count == 2
        finally:
            await memory.close()

    asyncio.run(_go())


def test_learning_profile_skipped_when_dir_unset(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.apk_sha256 = "e" * 64

    from sentinel.memory import LightweightMemory
    async def _go():
        memory = LightweightMemory(data_dir=tmp_path / "data")
        await memory.connect()
        try:
            orch = Orchestrator(
                context=ctx, memory=memory, agents=[],
                learning_dir=None,
            )
            orch._maybe_load_learning_profile()
            assert ctx.learning_profile is None
        finally:
            await memory.close()

    asyncio.run(_go())
