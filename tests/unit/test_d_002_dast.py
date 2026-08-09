"""Unit tests for D_002 SSL Bypass agent."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.agents.dast.base_dast_agent import RuntimeEvent
from sentinel.agents.dast.d_002_ssl_bypass import D002SSLBypassAgent
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


def _agent(ctx, memory) -> D002SSLBypassAgent:
    return D002SSLBypassAgent(context=ctx, memory=memory)


def _ev(event_type: str, **data) -> RuntimeEvent:
    return RuntimeEvent("D_002", event_type, 1000.0, {"event_type": event_type, **data})


class TestIsApplicable:
    @pytest.mark.asyncio
    async def test_false_when_no_frida(self, ctx, memory):
        with patch.dict("sys.modules", {"frida": None}):
            assert await _agent(ctx, memory).is_applicable() is False

    @pytest.mark.asyncio
    async def test_true_when_device_present(self, ctx, memory):
        mock_frida = MagicMock()
        mock_frida.get_usb_device.return_value = MagicMock()
        with patch.dict("sys.modules", {"frida": mock_frida}):
            assert await _agent(ctx, memory).is_applicable() is True


class TestAnalyzeEvents:
    @pytest.mark.asyncio
    async def test_no_events_returns_no_pinning_finding(self, ctx, memory):
        findings = await _agent(ctx, memory).analyze_events([], ctx)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_pinning_detected_and_bypassed_is_high(self, ctx, memory):
        events = [
            _ev("pinning_detected", mechanism="okhttp_certificate_pinner", host="api.example.com"),
            _ev("ssl_bypass_applied", mechanism="okhttp_certificate_pinner"),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_bypass_evidence_recorded(self, ctx, memory):
        events = [
            _ev("pinning_detected", mechanism="okhttp_certificate_pinner"),
            _ev("ssl_bypass_applied", mechanism="okhttp_certificate_pinner"),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert findings[0].evidence["bypass_applied"] is True

    @pytest.mark.asyncio
    async def test_no_pinning_medium_severity(self, ctx, memory):
        findings = await _agent(ctx, memory).analyze_events([], ctx)
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["bypass_applied"] is False

    @pytest.mark.asyncio
    async def test_cwe_295_in_compliance_tags(self, ctx, memory):
        findings = await _agent(ctx, memory).analyze_events([], ctx)
        assert "CWE-295" in findings[0].compliance_tags

    @pytest.mark.asyncio
    async def test_webview_bypass_detected(self, ctx, memory):
        events = [
            _ev("pinning_detected", mechanism="webview_ssl_error"),
            _ev("ssl_bypass_applied", mechanism="webview_ssl_error"),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert "webview_ssl_error" in findings[0].evidence["pinning_mechanisms"]

    @pytest.mark.asyncio
    async def test_agent_id_correct(self, ctx, memory):
        findings = await _agent(ctx, memory).analyze_events([], ctx)
        assert findings[0].agent_id == "DAST_002"

    @pytest.mark.asyncio
    async def test_no_device_returns_info(self, ctx, memory):
        mock_frida = MagicMock()
        mock_frida.get_usb_device.side_effect = Exception("no device")
        with patch.dict("sys.modules", {"frida": mock_frida}):
            findings = await _agent(ctx, memory).analyze()
        assert findings[0].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_hook_errors_dont_create_findings(self, ctx, memory):
        events = [_ev("hook_error", error="ClassNotFound", hook="CertificatePinner")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        # Only the "no pinning" finding (from no pinning_detected events)
        assert findings[0].evidence["pinning_mechanisms"] == []
