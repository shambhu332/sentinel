"""Unit tests for D_015 ImplicitIntentLeakAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import ImplicitIntentLeakAgent
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
    agent = ImplicitIntentLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_explicit_intent_not_flagged(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("intent.dispatched",
            method="startActivity",
            action="com.example.SHOW",
            has_component=True,
            package="",
            extras=["auth_token"]),
    )
    findings = await ImplicitIntentLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_implicit_send_broadcast_with_token_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("intent.dispatched",
            method="sendBroadcast",
            action="com.example.NEW_TOKEN",
            has_component=False,
            package="",
            extras=["auth_token", "user_id"]),
    )
    findings = await ImplicitIntentLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_implicit_start_activity_with_password_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("intent.dispatched",
            method="startActivity",
            action="android.intent.action.SEND",
            has_component=False,
            package="",
            extras=["password", "subject"]),
    )
    findings = await ImplicitIntentLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_implicit_intent_with_explicit_package_not_flagged(ctx, memory):
    # If setPackage was used, the dispatch is constrained to that
    # package — not truly implicit. Don't flag.
    ctx.sources["frida"] = _capture(
        _ev("intent.dispatched",
            method="sendBroadcast",
            action="com.example.NEW_TOKEN",
            has_component=False,
            package="com.target.app",
            extras=["auth_token"]),
    )
    findings = await ImplicitIntentLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_implicit_intent_with_benign_extras_not_flagged(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("intent.dispatched",
            method="startActivity",
            action="android.intent.action.SEND",
            has_component=False,
            package="",
            extras=["android.intent.extra.TEXT", "title"]),
    )
    findings = await ImplicitIntentLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_two_methods_produce_two_findings(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("intent.dispatched",
            method="sendBroadcast", has_component=False,
            extras=["token"]),
        _ev("intent.dispatched",
            method="startActivity", has_component=False,
            extras=["secret"]),
    )
    findings = await ImplicitIntentLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 2
    severities = sorted(f.severity for f in findings)
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities
