"""Unit tests for D_016 AccessibilityAbuseAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import AccessibilityAbuseAgent
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
    agent = AccessibilityAbuseAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_action_on_third_party_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("a11y.action_performed",
            action="node.performAction(16)",
            source_package="com.bank.target"),
    )
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1
    assert "com.bank.target" in crit[0].evidence["targets"]


@pytest.mark.asyncio
async def test_action_on_system_pkg_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("a11y.action_performed",
            action="performGlobalAction(1)",
            source_package="com.android.systemui"),
    )
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_observe_third_party_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("a11y.event_observed",
            event_type=2048,
            source_package="com.bank.target",
            source_text_redacted="Bala…00"),
    )
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    high = [f for f in findings if "Observation" in f.vuln_class]
    assert len(high) == 1
    assert high[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_observe_own_pkg_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("a11y.event_observed",
            event_type=2048,
            source_package="com.example.app",
            source_text_redacted="x"),
    )
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_notif_listener_otp_from_sms_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notif_listener.notification_received",
            source_package="com.google.android.apps.messaging",
            title_redacted="HDFC…", text_redacted="OTP…13",
            has_otp_shape=True),
    )
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    otp = [f for f in findings if "OTP Exfiltration" in f.vuln_class]
    assert len(otp) == 1
    assert otp[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_notif_listener_financial_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notif_listener.notification_received",
            source_package="com.somebank.app",
            title_redacted="Tran…", text_redacted="debited ₹500"),
    )
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    fin = [f for f in findings if "Financial Activity" in f.vuln_class]
    assert len(fin) == 1
    assert fin[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_broad_event_spectrum_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(*[
        _ev("a11y.event_observed",
            event_type=t,
            source_package="com.target",
            source_text_redacted="x")
        for t in (1, 2, 4, 8, 16, 32, 64)
    ])
    findings = await AccessibilityAbuseAgent(
        context=ctx, memory=memory,
    ).analyze()
    broad = [f for f in findings if "Broad-Spectrum" in f.vuln_class]
    assert len(broad) == 1
    assert broad[0].severity == Severity.MEDIUM
