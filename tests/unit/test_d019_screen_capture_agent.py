"""Unit tests for D_019 ScreenCaptureAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import ScreenCaptureAgent
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
    agent = ScreenCaptureAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_no_projection_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("crypto.cipher", algorithm="AES"),
    )
    findings = await ScreenCaptureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_projection_only_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("screen.projection_started", result_code=-1),
    )
    findings = await ScreenCaptureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Consent" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_active_pipeline_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("screen.projection_started", result_code=-1),
        _ev("screen.virtual_display_created",
            width=1080, height=2400, dpi=420,
            surface_type="android.media.ImageReader$SurfaceImage"),
        _ev("screen.image_reader_used", api="acquireLatestImage"),
        _ev("screen.image_reader_used", api="acquireLatestImage"),
    )
    findings = await ScreenCaptureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence["image_reads_observed"] == 2


@pytest.mark.asyncio
async def test_active_with_recorder_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("screen.projection_started", result_code=-1),
        _ev("screen.virtual_display_created",
            width=1080, height=2400, dpi=420,
            surface_type="android.view.Surface"),
        _ev("screen.image_reader_used", api="acquireLatestImage"),
        _ev("screen.media_recorder_set_video_source", source=2),
    )
    findings = await ScreenCaptureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_recorder_with_non_surface_source_not_critical(ctx, memory):
    # CAMERA = 1, SURFACE = 2. Camera-source recorder shouldn't lift
    # the screen-capture severity.
    ctx.sources["frida"] = _capture(
        _ev("screen.projection_started", result_code=-1),
        _ev("screen.virtual_display_created",
            width=1080, height=2400, dpi=420,
            surface_type="android.view.Surface"),
        _ev("screen.image_reader_used", api="acquireLatestImage"),
        _ev("screen.media_recorder_set_video_source", source=1),
    )
    findings = await ScreenCaptureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
