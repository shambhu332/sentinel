"""Unit tests for D_023 ContentProviderUriExposureAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import ContentProviderUriExposureAgent
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
    agent = ContentProviderUriExposureAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_write_into_private_dir_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("provider.uri_opened",
            caller_uid=10101, target_uid=10202,
            uri="content://com.example.app.fp/files/db",
            mode="rw",
            real_path="/data/data/com.example.app/databases/secrets.db"),
    )
    findings = await ContentProviderUriExposureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "Cross-UID" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_read_into_private_dir_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("provider.uri_opened",
            caller_uid=10101, target_uid=10202,
            uri="content://com.example.app.fp/files/token",
            mode="r",
            real_path="/data/data/com.example.app/files/token.txt"),
    )
    findings = await ContentProviderUriExposureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Read Across UID" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_same_uid_open_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("provider.uri_opened",
            caller_uid=10202, target_uid=10202,
            uri="content://com.example.app.fp/files/x",
            mode="rw",
            real_path="/data/data/com.example.app/files/x"),
    )
    findings = await ContentProviderUriExposureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_public_path_is_ignored(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("provider.uri_opened",
            caller_uid=10101, target_uid=10202,
            uri="content://media/external/files/123",
            mode="r",
            real_path="/storage/emulated/0/Download/report.pdf"),
    )
    findings = await ContentProviderUriExposureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_cursor_path_leak_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("provider.query_returned",
            caller_uid=10101, target_uid=10202,
            uri="content://com.example.app.fp/index",
            exposed_paths=[
                "/data/data/com.example.app/databases/main.db",
                "/storage/emulated/0/Download/public.pdf",
            ]),
    )
    findings = await ContentProviderUriExposureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    # public.pdf must have been filtered out
    sample = findings[0].evidence["samples"][0]
    assert all("/data/data/" in p for p in sample["exposed_paths"])


@pytest.mark.asyncio
async def test_data_user_paths_are_recognized(ctx, memory):
    """Multi-user / direct-boot variants of the private dir."""
    ctx.sources["frida"] = _capture(
        _ev("provider.uri_opened",
            caller_uid=10101, target_uid=10202,
            uri="content://com.example.app.fp/files/x",
            mode="r",
            real_path="/data/user/0/com.example.app/files/x.txt"),
        _ev("provider.uri_opened",
            caller_uid=10101, target_uid=10202,
            uri="content://com.example.app.fp/files/y",
            mode="r",
            real_path="/data/user_de/0/com.example.app/files/y.txt"),
    )
    findings = await ContentProviderUriExposureAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].evidence["occurrence_count"] == 2
