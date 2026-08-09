"""Unit tests for D_004 Runtime Taint Tracking agent."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.agents.dast.base_dast_agent import RuntimeEvent
from sentinel.agents.dast.d_004_runtime_taint import D004RuntimeTaintAgent
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


def _agent(ctx, memory) -> D004RuntimeTaintAgent:
    return D004RuntimeTaintAgent(context=ctx, memory=memory)


def _flow(source_key: str, sink_type: str, tainted: str = "evil") -> RuntimeEvent:
    return RuntimeEvent("D_004", "taint_flow", 1000.0, {
        "event_type": "taint_flow",
        "source_type": "intent_extra",
        "source_key": source_key,
        "sink_type": sink_type,
        "tainted_value": tainted,
        "sink_value": f"SELECT * FROM users WHERE id={tainted}",
    })


class TestAnalyzeEvents:
    @pytest.mark.asyncio
    async def test_no_events_returns_empty(self, ctx, memory):
        assert await _agent(ctx, memory).analyze_events([], ctx) == []

    @pytest.mark.asyncio
    async def test_webview_taint_is_high(self, ctx, memory):
        events = [_flow("data", "webview_loadurl", "javascript:alert(1)")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_sql_taint_is_critical(self, ctx, memory):
        events = [_flow("query", "sqlite_exec", "1 OR 1=1")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_exec_taint_is_critical(self, ctx, memory):
        events = [_flow("cmd", "runtime_exec", "id")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_duplicate_flows_deduped(self, ctx, memory):
        events = [
            _flow("query", "sqlite_exec", "1 OR 1=1"),
            _flow("query", "sqlite_exec", "2 OR 2=2"),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_different_sinks_produce_separate_findings(self, ctx, memory):
        events = [
            _flow("data", "webview_loadurl"),
            _flow("query", "sqlite_exec"),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_source_key_in_evidence(self, ctx, memory):
        events = [_flow("userId", "sqlite_exec")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].evidence["source_key"] == "userId"

    @pytest.mark.asyncio
    async def test_cwe_89_for_sql_injection(self, ctx, memory):
        events = [_flow("q", "sqlite_exec")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert "CWE-89" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_cwe_79_for_webview_xss(self, ctx, memory):
        events = [_flow("url", "webview_loadurl")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert "CWE-79" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_agent_id_is_d004(self, ctx, memory):
        events = [_flow("x", "sqlite_exec")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].agent_id == "DAST_004"

    @pytest.mark.asyncio
    async def test_no_device_returns_info(self, ctx, memory):
        mock_frida = MagicMock()
        mock_frida.get_usb_device.side_effect = Exception("no device")
        with patch.dict("sys.modules", {"frida": mock_frida}):
            findings = await _agent(ctx, memory).analyze()
        assert findings[0].severity == Severity.INFO
