"""Unit tests for D_027 ZipPathTraversalAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.dynamic import ZipPathTraversalAgent
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
    agent = ZipPathTraversalAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_confirmed_escape_is_critical(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="../../etc/passwd_clone", source="ZipInputStream"),
        _ev("zip.entry_extracted",
            entry_name="../../etc/passwd_clone",
            target_path="/data/data/com.example.app/cache/extract/"
                        "../../etc/passwd_clone",
            canonical_path="/etc/passwd_clone",
            intended_dir="/data/data/com.example.app/cache/extract",
            escaped_intended_dir=True),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    severities = {f.severity for f in findings}
    assert Severity.CRITICAL in severities


@pytest.mark.asyncio
async def test_traversal_entry_accepted_but_unconfirmed_is_high(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="../config/settings.json", source="ZipInputStream"),
        _ev("zip.entry_extracted",
            entry_name="../config/settings.json",
            target_path="/data/data/com.example.app/files/settings.json",
            canonical_path="/data/data/com.example.app/files/settings.json",
            intended_dir="",
            escaped_intended_dir=False),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities
    assert Severity.CRITICAL not in severities


@pytest.mark.asyncio
async def test_traversal_entry_observed_only_is_medium(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="../boot.img", source="ZipInputStream"),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Observed" in findings[0].vuln_class


@pytest.mark.asyncio
async def test_absolute_path_entry_is_flagged(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="/sdcard/Download/payload.dex",
            source="ZipInputStream"),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_clean_entries_produce_no_finding(ctx, memory):
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="META-INF/MANIFEST.MF", source="ZipInputStream"),
        _ev("zip.entry_observed",
            name="assets/config.json", source="ZipInputStream"),
        _ev("zip.entry_extracted",
            entry_name="META-INF/MANIFEST.MF",
            target_path="/data/data/com.example.app/files/MANIFEST.MF",
            canonical_path="/data/data/com.example.app/files/MANIFEST.MF",
            intended_dir="/data/data/com.example.app/files",
            escaped_intended_dir=False),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_backslash_traversal_entry_is_flagged(ctx, memory):
    """Windows-style separators in ZIP entries are equally suspect."""
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            source="ZipInputStream"),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_unrelated_extraction_does_not_promote_observation(ctx, memory):
    """Observed traversal entry stays MEDIUM unless its own name is extracted."""
    ctx.sources["frida"] = _capture(
        _ev("zip.entry_observed",
            name="../escape.bin", source="ZipInputStream"),
        _ev("zip.entry_extracted",
            entry_name="assets/safe.txt",
            target_path="/data/data/com.example.app/files/safe.txt",
            canonical_path="/data/data/com.example.app/files/safe.txt",
            intended_dir="/data/data/com.example.app/files",
            escaped_intended_dir=False),
    )
    findings = await ZipPathTraversalAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
