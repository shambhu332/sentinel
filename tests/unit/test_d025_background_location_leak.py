"""Unit tests for D_025 BackgroundLocationLeakAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import BackgroundLocationLeakAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent

# Mirror the constants in the agent file.
IMP_FG = 100
IMP_FG_SERVICE = 125
IMP_VISIBLE = 200
IMP_PERCEPTIBLE = 230
IMP_SERVICE = 300
IMP_CACHED = 400


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
    agent = BackgroundLocationLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_service_caller_with_background_importance_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="FusedLocationProviderClient.requestLocationUpdates",
            caller_class="com.example.app.tracker.PingService",
            importance=IMP_CACHED,
            interval_ms=60_000, priority=100),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_worker_caller_at_service_importance_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="LocationManager.requestLocationUpdates",
            caller_class="com.example.app.work.LocationWorker",
            importance=IMP_SERVICE,
            interval_ms=900_000),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_activity_caller_at_foreground_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="FusedLocationProviderClient.requestLocationUpdates",
            caller_class="com.example.app.MapActivity",
            importance=IMP_FG,
            interval_ms=5_000, priority=100),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_foreground_service_importance_is_ignored(ctx, memory):
    """IMPORTANCE_FOREGROUND_SERVICE is the *correct* place to request."""
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="LocationManager.requestLocationUpdates",
            caller_class="com.example.app.tracker.PingService",
            importance=IMP_FG_SERVICE,
            interval_ms=10_000),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_unknown_caller_at_service_importance_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="LocationManager.requestLocationUpdates",
            caller_class="com.example.app.util.Helper",
            importance=IMP_SERVICE,
            interval_ms=30_000),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_perceptible_with_service_caller_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="FusedLocationProviderClient.requestLocationUpdates",
            caller_class="com.example.app.PingReceiver",
            importance=IMP_PERCEPTIBLE,
            interval_ms=20_000),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_missing_importance_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("location.update_requested",
            api="LocationManager.requestLocationUpdates",
            caller_class="com.example.app.tracker.PingService",
            importance=None),
    )
    findings = await BackgroundLocationLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
