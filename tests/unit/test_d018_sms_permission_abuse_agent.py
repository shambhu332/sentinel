"""Unit tests for D_018 SmsPermissionAbuseAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import SmsPermissionAbuseAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


def _ev(kind: str, **payload) -> FridaHookEvent:
    return FridaHookEvent(kind=kind, payload=payload, timestamp=0.0)


def _capture(*events: FridaHookEvent) -> FridaCapture:
    return FridaCapture(
        events=list(events), duration_seconds=10.0,
        target_package="com.example.app", target_pid=12345,
    )


@pytest.fixture
def ctx(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    c = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk, workspace=tmp_path, scope=BountyScope(),
    )
    c.manifest = {"package": "com.example.app"}
    return c


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "mem")
    await mem.connect()
    yield mem
    await mem.close()


@pytest.mark.asyncio
async def test_no_capture_skips(ctx, memory):
    agent = SmsPermissionAbuseAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_only_retriever_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sms.retriever_started", api="startSmsRetriever"),
    )
    findings = await SmsPermissionAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_broadcast_without_retriever_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sms.broadcast_received",
            sender="HDFC…BK", body_redacted="Your…23",
            has_otp_shape=True,
            source_method="android.provider.Telephony.SMS_RECEIVED"),
    )
    findings = await SmsPermissionAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["otp_shaped_count"] == 1


@pytest.mark.asyncio
async def test_overlapping_intake_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sms.retriever_started", api="startSmsRetriever"),
        _ev("sms.broadcast_received",
            sender="HDFC…BK", body_redacted="Your…23",
            has_otp_shape=True,
            source_method="android.provider.Telephony.SMS_RECEIVED"),
    )
    findings = await SmsPermissionAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    overlap = [f for f in findings if "Overlapping" in f.vuln_class]
    assert len(overlap) == 1
    assert overlap[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_content_provider_query_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sms.content_provider_query",
            uri="content://sms/inbox",
            stack="com.example.app.SmsInboxReader.run"),
    )
    findings = await SmsPermissionAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    deep = [f for f in findings if "Deep Scan" in f.vuln_class]
    assert len(deep) == 1
    assert deep[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_both_signals_emit_both_findings(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("sms.content_provider_query", uri="content://sms"),
        _ev("sms.broadcast_received",
            sender="UNK", body_redacted="x",
            has_otp_shape=False,
            source_method="android.provider.Telephony.SMS_RECEIVED"),
    )
    findings = await SmsPermissionAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 2
