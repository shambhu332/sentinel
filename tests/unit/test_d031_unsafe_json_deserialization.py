"""Unit tests for D_031 UnsafeJsonDeserializationAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import UnsafeJsonDeserializationAgent
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
    agent = UnsafeJsonDeserializationAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_polymorphic_marker_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("json.deserialize_called",
            library="Jackson",
            target_type="com.example.app.api.Payload",
            polymorphic_marker="com.fasterxml.jackson.databind.jsontype.impl.ClassNameIdResolver",
            caller_class="com.example.app.api.ApiClient"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_typeless_target_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("json.deserialize_called",
            library="Gson",
            target_type="java.lang.Object",
            polymorphic_marker="",
            caller_class="com.example.app.RouterDispatcher"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Typeless" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_map_target_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("json.deserialize_called",
            library="Gson",
            target_type="java.util.HashMap",
            caller_class="com.example.app.RouterDispatcher"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_class_forname_followed_by_fromjson_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("reflection.class_forname",
            name="com.example.app.handlers.AdminHandler"),
        _ev("json.deserialize_called",
            library="Gson",
            target_type="com.example.app.handlers.AdminHandler",
            caller_class="com.example.app.dispatcher.Plugin"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Dynamically" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_concrete_target_no_class_forname_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("json.deserialize_called",
            library="Gson",
            target_type="com.example.app.api.UserResponse",
            caller_class="com.example.app.api.ApiClient"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_class_forname_window_does_not_leak_after_32_events(ctx, memory):
    # Pile up 33 unrelated class names between the forName and the
    # fromJson. The fromJson should NOT pair with it.
    fillers = [
        _ev("reflection.class_forname", name=f"com.filler.A{i}")
        for i in range(33)
    ]
    ctx.sources["frida"] = _capture(
        _ev("reflection.class_forname",
            name="com.example.app.handlers.AdminHandler"),
        *fillers,
        _ev("json.deserialize_called",
            library="Gson",
            target_type="com.example.app.handlers.AdminHandler",
            caller_class="com.example.app.dispatcher.Plugin"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_polymorphic_takes_precedence_over_typeless(ctx, memory):
    """A polymorphic call with a typeless target only fires CRITICAL once."""
    ctx.sources["frida"] = _capture(
        _ev("json.deserialize_called",
            library="Jackson",
            target_type="java.lang.Object",
            polymorphic_marker="ClassNameIdResolver",
            caller_class="com.example.app.api.ApiClient"),
    )
    findings = await UnsafeJsonDeserializationAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
