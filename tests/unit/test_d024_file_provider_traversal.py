"""Unit tests for D_024 FileProviderTraversalAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import FileProviderTraversalAgent
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
    agent = FileProviderTraversalAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_symlink_escape_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("file_provider.uri_minted",
            authority="com.example.app.fp",
            input_path="/data/data/com.example.app/cache/share.tmp",
            canonical_path="/data/data/com.victim.app/databases/secrets.db",
            is_symlink=True),
    )
    findings = await FileProviderTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Symlink Escape" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_traversal_still_inside_root_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("file_provider.uri_minted",
            authority="com.example.app.fp",
            input_path="/data/data/com.example.app/files/share/../private/token",
            canonical_path="/data/data/com.example.app/files/private/token",
            is_symlink=False,
            caller_controlled_segments=True),
    )
    findings = await FileProviderTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Traversal" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_internal_symlink_no_traversal_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("file_provider.uri_minted",
            authority="com.example.app.fp",
            input_path="/data/data/com.example.app/cache/link",
            canonical_path="/data/data/com.example.app/files/payload.bin",
            is_symlink=True),
    )
    findings = await FileProviderTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Inside App Dir" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_benign_call_produces_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("file_provider.uri_minted",
            authority="com.example.app.fp",
            input_path="/data/data/com.example.app/cache/share.pdf",
            canonical_path="/data/data/com.example.app/cache/share.pdf",
            is_symlink=False),
    )
    findings = await FileProviderTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_dotdot_in_input_path_alone_triggers_traversal(ctx, memory):
    """Even without the explicit flag, '..' segments are detected."""
    ctx.sources["frida"] = _capture(
        _ev("file_provider.uri_minted",
            authority="com.example.app.fp",
            input_path="/data/data/com.example.app/files/a/../b/x",
            canonical_path="/data/data/com.example.app/files/b/x",
            is_symlink=False),
    )
    findings = await FileProviderTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_external_scoped_storage_is_app_dir(ctx, memory):
    """Files under /Android/data/<pkg>/ are 'the app's own data'."""
    ctx.sources["frida"] = _capture(
        _ev("file_provider.uri_minted",
            authority="com.example.app.fp",
            input_path="/storage/emulated/0/Android/data/com.example.app/files/x",
            canonical_path="/storage/emulated/0/Android/data/com.example.app/files/x",
            is_symlink=False),
    )
    findings = await FileProviderTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    # No symlink, no traversal, no escape — benign.
    assert findings == []
