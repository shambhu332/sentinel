"""Unit tests for D_012 NotificationLeakAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import NotificationLeakAgent
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
    agent = NotificationLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_otp_with_public_visibility_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="auth",
            channel_importance=4,
            visibility=1,
            has_public_version=False,
            title="Your OTP",
            text="Your verification code is 482913"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_balance_notification_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="account",
            channel_importance=3,
            visibility=1,
            title="Account update",
            text="₹5,000 debited from your account"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    cred = [f for f in findings if "Lockscreen" in f.vuln_class]
    assert len(cred) == 1
    assert cred[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_private_visibility_suppresses(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="auth", channel_importance=4,
            visibility=0,
            title="Your OTP",
            text="Your verification code is 482913"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_secret_visibility_suppresses(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="auth", channel_importance=4,
            visibility=-1,
            title="Your OTP",
            text="Your code is 482913"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_otp_shaped_without_keyword_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="msg", channel_importance=3,
            visibility=1,
            title="Hello",
            text="482913 — please use this"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_benign_text_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="news", channel_importance=2,  # below DEFAULT
            visibility=1,
            title="Daily news",
            text="Top stories of the day"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_implicit_public_with_default_importance(ctx, memory):
    # No visibility passed → default-importance channel = lockscreen-visible.
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="auth", channel_importance=3,
            title="OTP", text="Your code 999111"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_redaction_in_evidence_preview(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("notification.posted",
            channel_id="auth", channel_importance=4, visibility=1,
            title="OTP",
            text="Your OTP is 482913, do not share with anyone"),
    )
    findings = await NotificationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    f = findings[0]
    sample = f.evidence["samples"][0]
    # The raw text must not appear in the preview verbatim.
    assert "482913, do not share with anyone" not in sample["text_preview"]
    assert "…" in sample["text_preview"]
