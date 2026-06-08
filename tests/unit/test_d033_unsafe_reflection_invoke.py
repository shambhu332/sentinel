"""Unit tests for D_033 UnsafeReflectionInvokeAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import UnsafeReflectionInvokeAgent
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
    agent = UnsafeReflectionInvokeAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_runtime_exec_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("reflection.method_invoked",
            target_class="java.lang.Runtime",
            method_name="exec",
            declaring_class="java.lang.Runtime",
            caller_class="com.example.app.utils.ShellHelper"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_dex_classloader_constructor_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("reflection.constructor_invoked",
            target_class="dalvik.system.DexClassLoader",
            caller_class="com.example.app.plugins.PluginManager"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_class_forname_chain_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("reflection.class_forname",
            name="com.example.app.handlers.AdminHandler"),
        _ev("reflection.method_invoked",
            target_class="com.example.app.handlers.AdminHandler",
            method_name="execute",
            declaring_class="com.example.app.handlers.AdminHandler",
            caller_class="com.example.app.dispatcher.Router"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "forName" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_class_forname_chain_window_boundary(ctx, memory):
    fillers = [
        _ev("reflection.class_forname", name=f"com.filler.A{i}")
        for i in range(33)
    ]
    ctx.sources["frida"] = _capture(
        _ev("reflection.class_forname",
            name="com.example.app.handlers.AdminHandler"),
        *fillers,
        _ev("reflection.method_invoked",
            target_class="com.example.app.handlers.AdminHandler",
            method_name="execute",
            declaring_class="com.example.app.handlers.AdminHandler",
            caller_class="com.example.app.dispatcher.Router"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    # Out of window — no dynamic-chain finding.
    assert findings == []


@pytest.mark.asyncio
async def test_dispatcher_pattern_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("reflection.method_invoked",
            target_class="com.example.app.actions.SaveAction",
            method_name="run",
            declaring_class="com.example.app.actions.SaveAction",
            caller_class="com.example.app.dispatcher.Router"),
        _ev("reflection.method_invoked",
            target_class="com.example.app.actions.LoadAction",
            method_name="run",
            declaring_class="com.example.app.actions.LoadAction",
            caller_class="com.example.app.dispatcher.Router"),
        _ev("reflection.method_invoked",
            target_class="com.example.app.actions.DeleteAction",
            method_name="run",
            declaring_class="com.example.app.actions.DeleteAction",
            caller_class="com.example.app.dispatcher.Router"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_single_target_no_chain_is_clean(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("reflection.method_invoked",
            target_class="com.example.app.api.UserResponse",
            method_name="getId",
            declaring_class="com.example.app.api.UserResponse",
            caller_class="com.example.app.api.ApiClient"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_sensitive_takes_precedence_over_dispatcher(ctx, memory):
    """A Runtime invocation must fire CRITICAL even when the same
    caller drove a dispatcher pattern on other classes."""
    ctx.sources["frida"] = _capture(
        _ev("reflection.method_invoked",
            target_class="com.example.app.actions.A",
            method_name="run",
            caller_class="com.example.app.dispatcher.Router"),
        _ev("reflection.method_invoked",
            target_class="com.example.app.actions.B",
            method_name="run",
            caller_class="com.example.app.dispatcher.Router"),
        _ev("reflection.method_invoked",
            target_class="java.lang.Runtime",
            method_name="exec",
            caller_class="com.example.app.dispatcher.Router"),
    )
    findings = await UnsafeReflectionInvokeAgent(
        context=ctx, memory=memory,
    ).analyze()
    severities = {f.severity for f in findings}
    assert Severity.CRITICAL in severities
