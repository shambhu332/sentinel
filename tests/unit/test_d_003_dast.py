"""Unit tests for D_003 Runtime Crypto agent."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.agents.dast.base_dast_agent import RuntimeEvent
from sentinel.agents.dast.d_003_runtime_crypto import D003RuntimeCryptoAgent
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


def _agent(ctx, memory) -> D003RuntimeCryptoAgent:
    return D003RuntimeCryptoAgent(context=ctx, memory=memory)


def _weakness(weakness: str, **extra) -> RuntimeEvent:
    return RuntimeEvent("D_003", "crypto_weakness", 1000.0,
                        {"event_type": "crypto_weakness", "weakness": weakness, **extra})


def _weak_random(**extra) -> RuntimeEvent:
    return RuntimeEvent("D_003", "weak_random", 1000.0,
                        {"event_type": "weak_random", "type": "java.util.Random", **extra})


class TestAnalyzeEvents:
    @pytest.mark.asyncio
    async def test_no_events_returns_empty(self, ctx, memory):
        assert await _agent(ctx, memory).analyze_events([], ctx) == []

    @pytest.mark.asyncio
    async def test_ecb_mode_detected(self, ctx, memory):
        events = [_weakness("ecb_mode", algorithm="AES/ECB/PKCS5Padding")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert any(f.evidence.get("weakness") == "ecb_mode" for f in findings)

    @pytest.mark.asyncio
    async def test_ecb_severity_is_high(self, ctx, memory):
        events = [_weakness("ecb_mode", algorithm="AES/ECB/PKCS5Padding")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        ecb = next(f for f in findings if f.evidence.get("weakness") == "ecb_mode")
        assert ecb.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_static_iv_detected(self, ctx, memory):
        events = [_weakness("static_zero_iv", iv_length=16)]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert any(f.evidence.get("weakness") == "static_zero_iv" for f in findings)

    @pytest.mark.asyncio
    async def test_static_iv_severity_is_high(self, ctx, memory):
        events = [_weakness("static_zero_iv", iv_length=16)]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        iv_f = next(f for f in findings if f.evidence.get("weakness") == "static_zero_iv")
        assert iv_f.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_weak_random_is_critical(self, ctx, memory):
        events = [_weak_random(bound=1000000)]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_weaknesses_produce_multiple_findings(self, ctx, memory):
        events = [
            _weakness("ecb_mode", algorithm="AES/ECB/PKCS5Padding"),
            _weakness("static_zero_iv", iv_length=16),
            _weak_random(bound=100),
        ]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert len(findings) == 3

    @pytest.mark.asyncio
    async def test_cwe_327_for_ecb(self, ctx, memory):
        events = [_weakness("ecb_mode", algorithm="AES/ECB/PKCS5Padding")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        ecb = next(f for f in findings if f.evidence.get("weakness") == "ecb_mode")
        assert "CWE-327" in ecb.compliance_tags

    @pytest.mark.asyncio
    async def test_sast_correlation_in_evidence(self, ctx, memory):
        events = [_weakness("ecb_mode", algorithm="AES/ECB/PKCS5Padding")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        ecb = next(f for f in findings if f.evidence.get("weakness") == "ecb_mode")
        assert "C_001" in ecb.evidence.get("sast_correlation", "")

    @pytest.mark.asyncio
    async def test_agent_id_is_d003(self, ctx, memory):
        events = [_weakness("ecb_mode", algorithm="AES/ECB")]
        findings = await _agent(ctx, memory).analyze_events(events, ctx)
        assert all(f.agent_id == "DAST_003" for f in findings)

    @pytest.mark.asyncio
    async def test_no_device_returns_info(self, ctx, memory):
        mock_frida = MagicMock()
        mock_frida.get_usb_device.side_effect = Exception("no device")
        with patch.dict("sys.modules", {"frida": mock_frida}):
            findings = await _agent(ctx, memory).analyze()
        assert findings[0].severity == Severity.INFO
