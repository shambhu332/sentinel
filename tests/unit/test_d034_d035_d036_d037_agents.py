"""Unit tests for D_034 / D_035 / D_036 / D_037."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import (
    BroadcastWiretapAgent,
    ClipboardListenerSnoopAgent,
    ExportedActivityResultLeakAgent,
    LocalFileLogLeakAgent,
)
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


# ---------- D_034 ----------


@pytest.mark.asyncio
async def test_d034_cross_app_sensitive_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("activity.set_result",
            activity_class="com.example.app.LoginActivity",
            result_code=-1,
            extras_keys=["auth_token", "user_id"],
            extras_sensitive=["auth_token"],
            calling_package="com.attacker.app",
            own_package="com.example.app"),
    )
    findings = await ExportedActivityResultLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d034_cross_app_non_sensitive_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("activity.set_result",
            activity_class="com.example.app.PickerActivity",
            result_code=-1,
            extras_keys=["selected_color", "selected_index"],
            extras_sensitive=[],
            calling_package="com.partner.app",
            own_package="com.example.app"),
    )
    findings = await ExportedActivityResultLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d034_same_app_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("activity.set_result",
            activity_class="com.example.app.LoginActivity",
            result_code=-1,
            extras_keys=["auth_token"],
            extras_sensitive=["auth_token"],
            calling_package="com.example.app",
            own_package="com.example.app"),
    )
    findings = await ExportedActivityResultLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_035 ----------


@pytest.mark.asyncio
async def test_d035_jwt_in_log_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("log.line_emitted",
            api="Log", level="DEBUG", tag="ApiClient",
            message_redacted="auth: eyJ…(redacted)",
            sensitive_shapes=["jwt", "bearer"]),
    )
    findings = await LocalFileLogLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Log / Local File" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_d035_sdcard_write_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("log.line_emitted",
            api="FileOutputStream",
            target_path="/sdcard/Download/diagnostics.txt",
            sensitive_shapes=[]),
    )
    findings = await LocalFileLogLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Outside App Private Dir" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_d035_email_in_log_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("log.line_emitted",
            api="Log", level="INFO", tag="UserService",
            message_redacted="hello user@example.com",
            sensitive_shapes=["email"]),
    )
    findings = await LocalFileLogLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d035_clean_log_produces_nothing(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("log.line_emitted",
            api="Log", level="DEBUG", tag="LifecycleLogger",
            message_redacted="onResume fired",
            sensitive_shapes=[]),
        _ev("log.line_emitted",
            api="FileOutputStream",
            target_path="/data/data/com.example.app/files/cache.bin",
            sensitive_shapes=[]),
    )
    findings = await LocalFileLogLeakAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_036 ----------


@pytest.mark.asyncio
async def test_d036_background_get_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.read_observed",
            api="getPrimaryClip",
            caller_class="com.example.app.poll.PollService",
            importance=400,
            content_shape="arbitrary"),
    )
    findings = await ClipboardListenerSnoopAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d036_background_listener_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.read_observed",
            api="addPrimaryClipChangedListener",
            caller_class="com.example.app.poll.PollService",
            importance=400,
            content_shape=""),
    )
    findings = await ClipboardListenerSnoopAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Listener" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_d036_foreground_read_with_otp_shape_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.read_observed",
            api="getPrimaryClip",
            caller_class="com.example.app.LoginActivity",
            importance=100,
            content_shape="otp_like"),
    )
    findings = await ClipboardListenerSnoopAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d036_foreground_arbitrary_read_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("clipboard.read_observed",
            api="getPrimaryClip",
            caller_class="com.example.app.LoginActivity",
            importance=100,
            content_shape="short"),
    )
    findings = await ClipboardListenerSnoopAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ---------- D_037 ----------


@pytest.mark.asyncio
async def test_d037_phone_state_no_permission_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.PhoneListener",
            actions=["android.intent.action.PHONE_STATE"],
            permission=""),
    )
    findings = await BroadcastWiretapAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d037_permission_gated_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.PhoneListener",
            actions=["android.intent.action.PHONE_STATE"],
            permission="android.permission.READ_PHONE_STATE"),
    )
    findings = await BroadcastWiretapAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d037_broad_telemetry_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.TelemetryReceiver",
            actions=[
                "android.intent.action.SCREEN_ON",
                "android.intent.action.SCREEN_OFF",
                "android.net.conn.CONNECTIVITY_CHANGE",
                "android.media.RINGER_MODE_CHANGED",
            ],
            permission=""),
    )
    findings = await BroadcastWiretapAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d037_single_broad_action_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.NetReceiver",
            actions=["android.net.conn.CONNECTIVITY_CHANGE"],
            permission=""),
    )
    findings = await BroadcastWiretapAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []
