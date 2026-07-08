"""Unit tests for D_001 Anti-Frida agent — mocks all Frida calls."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.agents.dast.base_dast_agent import RuntimeEvent
from sentinel.agents.dast.d_001_anti_frida import D001AntiFridaAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ws = tmp_path / "ws"
    ws.mkdir()
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )


def _agent(ctx, memory) -> D001AntiFridaAgent:
    return D001AntiFridaAgent(context=ctx, memory=memory)


def _event(check_type: str, **extra) -> RuntimeEvent:
    return RuntimeEvent(
        agent_id="D_001",
        event_type="anti_frida_check",
        timestamp=1000.0,
        data={"check_type": check_type, **extra},
    )


class TestIsApplicable:
    @pytest.mark.asyncio
    async def test_false_when_frida_missing(self, ctx, memory):
        agent = _agent(ctx, memory)
        with patch.dict("sys.modules", {"frida": None}):
            assert await agent.is_applicable() is False

    @pytest.mark.asyncio
    async def test_false_when_no_device(self, ctx, memory):
        agent = _agent(ctx, memory)
        mock_frida = MagicMock()
        mock_frida.get_usb_device.side_effect = Exception("no device")
        with patch.dict("sys.modules", {"frida": mock_frida}):
            assert await agent.is_applicable() is False

    @pytest.mark.asyncio
    async def test_true_when_device_available(self, ctx, memory):
        agent = _agent(ctx, memory)
        mock_frida = MagicMock()
        mock_frida.get_usb_device.return_value = MagicMock()
        with patch.dict("sys.modules", {"frida": mock_frida}):
            assert await agent.is_applicable() is True


class TestAnalyzeEvents:
    @pytest.mark.asyncio
    async def test_no_events_returns_empty(self, ctx, memory):
        assert await _agent(ctx, memory).analyze_events([], ctx) == []

    @pytest.mark.asyncio
    async def test_file_exists_check_detected(self, ctx, memory):
        events = [_event("file_exists", path="/proc/self/maps")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert len(findings) == 1
        assert findings[0].agent_id == "D_001"

    @pytest.mark.asyncio
    async def test_debugger_check_detected(self, ctx, memory):
        events = [_event("debugger_check")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_single_check_type_is_low(self, ctx, memory):
        events = [_event("file_exists", path="/proc/self/maps")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_multiple_check_types_is_medium(self, ctx, memory):
        events = [
            _event("file_exists", path="/proc/self/maps"),
            _event("debugger_check"),
            _event("system_property", key="ro.debuggable"),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_hook_errors_ignored(self, ctx, memory):
        events = [RuntimeEvent("D_001", "hook_error", 0.0, {"error": "ClassNotFound"})]
        assert await _agent(ctx, memory).analyze_events(events, ctx) == []

    @pytest.mark.asyncio
    async def test_finding_category_is_static_tool(self, ctx, memory):
        events = [_event("debugger_check")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].finding_category == "Static_Tool"

    @pytest.mark.asyncio
    async def test_evidence_contains_check_count(self, ctx, memory):
        events = [_event("file_exists", path="/tmp/frida")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].evidence["check_count"] == 1

    @pytest.mark.asyncio
    async def test_evidence_bypass_applied_true(self, ctx, memory):
        events = [_event("debugger_check")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].evidence["bypass_applied"] is True

    @pytest.mark.asyncio
    async def test_cwe_656_in_compliance_tags(self, ctx, memory):
        events = [_event("debugger_check")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert "CWE-656" in findings[0].compliance_tags


class TestNoDevice:
    @pytest.mark.asyncio
    async def test_returns_info_when_frida_missing(self, ctx, memory):
        agent = _agent(ctx, memory)
        with patch.dict("sys.modules", {"frida": None}):
            findings = await agent.analyze()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_returns_info_when_no_device(self, ctx, memory):
        agent = _agent(ctx, memory)
        mock_frida = MagicMock()
        mock_frida.get_usb_device.side_effect = Exception("no device")
        with patch.dict("sys.modules", {"frida": mock_frida}):
            findings = await agent.analyze()
        assert findings[0].severity == Severity.INFO
