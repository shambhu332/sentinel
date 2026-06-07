"""Unit tests for the Sprint 8.10 dynamic agents.

* D_020 DynamicReceiverExportAgent
* D_021 PendingIntentMutableAgent
* D_022 LocalSocketServerAgent
"""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import (
    DynamicReceiverExportAgent,
    LocalSocketServerAgent,
    PendingIntentMutableAgent,
)
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.frida_runner import FridaCapture, FridaHookEvent


_FLAG_IMMUTABLE = 0x04000000
_FLAG_MUTABLE = 0x02000000


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


# ---------- D_020 ----------


@pytest.mark.asyncio
async def test_d020_no_capture_skips(ctx, memory):
    agent = DynamicReceiverExportAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d020_implicit_export_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.PushReceiver",
            actions=["com.example.app.PUSH"],
            flags=0, has_explicit_export=False, permission=""),
    )
    findings = await DynamicReceiverExportAgent(
        context=ctx, memory=memory,
    ).analyze()
    implicit = [f for f in findings if "Implicit" in f.vuln_class]
    assert len(implicit) == 1
    assert implicit[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d020_not_exported_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.Local",
            actions=["com.example.app.LOCAL"],
            flags=0x4, has_explicit_export=True, permission=""),
    )
    findings = await DynamicReceiverExportAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d020_permission_gate_suppresses(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.Push",
            actions=["com.example.app.PUSH"],
            flags=0, has_explicit_export=False,
            permission="com.example.app.PUSH_PERM"),
    )
    findings = await DynamicReceiverExportAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d020_all_system_actions_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.BatteryWatcher",
            actions=["android.intent.action.BATTERY_CHANGED",
                     "android.intent.action.SCREEN_ON"],
            flags=0, has_explicit_export=False, permission=""),
    )
    findings = await DynamicReceiverExportAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d020_explicit_export_custom_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("receiver.dynamic_registered",
            receiver_class="com.example.app.OpenAPI",
            actions=["com.example.app.OPEN_API"],
            flags=0x2, has_explicit_export=True, permission=""),
    )
    findings = await DynamicReceiverExportAgent(
        context=ctx, memory=memory,
    ).analyze()
    cust = [f for f in findings if "Without Permission" in f.vuln_class]
    assert len(cust) == 1
    assert cust[0].severity == Severity.MEDIUM


# ---------- D_021 ----------


@pytest.mark.asyncio
async def test_d021_no_capture_skips(ctx, memory):
    agent = PendingIntentMutableAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d021_mutable_no_component_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("pending_intent.created",
            factory="getBroadcast",
            flags=_FLAG_MUTABLE,
            intent_action="android.intent.action.VIEW",
            intent_has_component=False),
    )
    findings = await PendingIntentMutableAgent(
        context=ctx, memory=memory,
    ).analyze()
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1


@pytest.mark.asyncio
async def test_d021_mutable_with_component_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("pending_intent.created",
            factory="getBroadcast",
            flags=_FLAG_MUTABLE,
            intent_action="com.example.app.REPLY",
            intent_has_component=True),
    )
    findings = await PendingIntentMutableAgent(
        context=ctx, memory=memory,
    ).analyze()
    hi = [f for f in findings if "With Component" in f.vuln_class]
    assert len(hi) == 1
    assert hi[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d021_immutable_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("pending_intent.created",
            factory="getActivity",
            flags=_FLAG_IMMUTABLE,
            intent_action="com.example.app.OPEN",
            intent_has_component=True),
    )
    findings = await PendingIntentMutableAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d021_unspecified_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("pending_intent.created",
            factory="getActivity",
            flags=0x10000000,  # FLAG_UPDATE_CURRENT, no immut/mut bit
            intent_action="com.example.app.OPEN",
            intent_has_component=True),
    )
    findings = await PendingIntentMutableAgent(
        context=ctx, memory=memory,
    ).analyze()
    med = [f for f in findings if "Unspecified" in f.vuln_class]
    assert len(med) == 1
    assert med[0].severity == Severity.MEDIUM


# ---------- D_022 ----------


@pytest.mark.asyncio
async def test_d022_no_capture_skips(ctx, memory):
    agent = LocalSocketServerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_d022_abstract_namespace_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("local_socket.server_created",
            namespace="ABSTRACT", name="stetho_dbg",
            stack="com.example.app.Debug"),
    )
    findings = await LocalSocketServerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_d022_private_dir_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("local_socket.server_created",
            namespace="FILESYSTEM",
            name="/data/data/com.example.app/files/ipc.sock"),
    )
    findings = await LocalSocketServerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d022_local_tmp_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("local_socket.server_created",
            namespace="FILESYSTEM",
            name="/data/local/tmp/debug.sock"),
    )
    findings = await LocalSocketServerAgent(
        context=ctx, memory=memory,
    ).analyze()
    cross = [f for f in findings if "Outside Private" in f.vuln_class]
    assert len(cross) == 1
    assert cross[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_d022_other_app_dir_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("local_socket.server_created",
            namespace="FILESYSTEM",
            name="/data/data/com.other.app/files/leak.sock"),
    )
    findings = await LocalSocketServerAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert any("Outside Private" in f.vuln_class for f in findings)
