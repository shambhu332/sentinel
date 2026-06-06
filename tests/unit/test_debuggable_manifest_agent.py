"""Unit tests for META_002 DebuggableManifestAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.meta import DebuggableManifestAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, manifest=None):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if manifest is not None:
        ctx.manifest = manifest
    return ctx


@pytest.mark.asyncio
async def test_not_applicable_without_manifest(memory, tmp_path):
    agent = DebuggableManifestAgent(context=_ctx(tmp_path), memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_debuggable_true_is_critical(memory, tmp_path):
    ctx = _ctx(tmp_path, {"package": "com.x", "debuggable": True})
    agent = DebuggableManifestAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "META_002"
    assert f.severity == Severity.CRITICAL
    assert f.confidence == 0.99


@pytest.mark.asyncio
async def test_debuggable_false_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path, {"package": "com.x", "debuggable": False})
    agent = DebuggableManifestAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_debuggable_missing_no_finding(memory, tmp_path):
    ctx = _ctx(tmp_path, {"package": "com.x"})
    agent = DebuggableManifestAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path, {"package": "com.x", "debuggable": True})
    agent = DebuggableManifestAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-CODE-2"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.evidence["package"] == "com.x"
