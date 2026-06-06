"""Unit tests for P_005 ExcessivePermissionsAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.platform import ExcessivePermissionsAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, permissions: list[str] | None = None):
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
    ctx.manifest = {"package": "com.x", "permissions": permissions or []}
    return ctx


@pytest.mark.asyncio
async def test_not_applicable_with_no_permissions(memory, tmp_path):
    ctx = _make_ctx(tmp_path, permissions=[])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_high_severity_for_read_sms(memory, tmp_path):
    ctx = _make_ctx(tmp_path, ["android.permission.READ_SMS"])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "READ_SMS" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_medium_severity_for_camera(memory, tmp_path):
    ctx = _make_ctx(tmp_path, ["android.permission.CAMERA"])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_info_severity_for_internet(memory, tmp_path):
    ctx = _make_ctx(tmp_path, ["android.permission.INTERNET"])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_unknown_permission_not_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path, ["com.x.permission.CUSTOM_THING"])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_multiple_permissions_each_get_finding(memory, tmp_path):
    ctx = _make_ctx(tmp_path, [
        "android.permission.READ_SMS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.CAMERA",
        "android.permission.INTERNET",
        "android.permission.WAKE_LOCK",
    ])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 6
    by_sev = {f.severity: 0 for f in findings}
    for f in findings:
        by_sev[f.severity] += 1
    assert by_sev[Severity.HIGH] == 3
    assert by_sev[Severity.MEDIUM] == 1
    assert by_sev[Severity.INFO] == 2


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path, ["android.permission.SYSTEM_ALERT_WINDOW"])
    agent = ExcessivePermissionsAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.agent_id == "P_005"
    assert f.owasp == "M1: Improper Platform Usage"
    assert f.masvs == "MSTG-PLATFORM-1"
    assert f.recommendation
    assert f.evidence["permission_count_declared"] == 1
