"""Unit tests for Sprint 2b: tool wrappers + orchestrator.

All external subprocess calls are mocked so tests run offline and fast.
The real APK integration test lives in tests/integration/.

NOTE (Sprint 7.6.1): JadxRunner.decompile() now returns ToolResult instead
of raising. Tests updated accordingly. JadxRunner.__init__ also no longer
raises when the binary is missing — it defers the error until decompile().
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.core.finding import BountyScope
from sentinel.core.orchestrator import Orchestrator, OrchestratorError
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.tools.apktool import ApktoolError, ApktoolRunner
from sentinel.tools.jadx import JadxRunner
from sentinel.tools.manifest import ManifestError, ManifestParser

# ---------- Fixtures ----------

def _make_fake_apk(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return path


def _make_context(tmp_path: Path) -> ScanContext:
    apk = _make_fake_apk(tmp_path / "test.apk")
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ---------- JadxRunner ----------
# JadxRunner is now crash-proof: returns ToolResult instead of raising.

def test_jadx_init_without_binary_does_not_raise(monkeypatch):
    """Constructor no longer raises — error is deferred to decompile()."""
    monkeypatch.setattr("shutil.which", lambda x: None)
    runner = JadxRunner()
    assert runner._jadx_missing_reason is not None
    assert "not found" in runner._jadx_missing_reason


@pytest.mark.asyncio
async def test_jadx_decompile_fails_without_binary(monkeypatch, tmp_path):
    """When jadx binary is missing, decompile() returns failure ToolResult."""
    monkeypatch.setattr("shutil.which", lambda x: None)
    runner = JadxRunner()
    apk = _make_fake_apk(tmp_path / "a.apk")
    result = await runner.decompile(apk, tmp_path / "out")
    assert result.success is False
    assert result.error is not None
    assert "not found" in result.error


def test_jadx_init_with_custom_path(tmp_path):
    fake_jadx = tmp_path / "jadx"
    fake_jadx.touch()
    runner = JadxRunner(jadx_path=str(fake_jadx))
    assert runner._jadx_path == str(fake_jadx)


@pytest.mark.asyncio
async def test_jadx_rejects_missing_apk(tmp_path):
    """Missing APK returns failed ToolResult, not a raised exception."""
    fake_jadx = tmp_path / "jadx"
    fake_jadx.touch()
    runner = JadxRunner(jadx_path=str(fake_jadx))
    result = await runner.decompile(tmp_path / "missing.apk", tmp_path / "out")
    assert result.success is False
    assert result.error is not None
    assert "not found" in result.error


@pytest.mark.asyncio
async def test_jadx_successful_run(tmp_path):
    """Successful decompile produces ToolResult.success=True with JadxResult data."""
    fake_jadx = tmp_path / "jadx"
    fake_jadx.touch()
    apk = _make_fake_apk(tmp_path / "a.apk")
    output_dir = tmp_path / "out"

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))

    async def fake_create_subprocess_exec(*args, **kwargs):
        sources = output_dir / "sources"
        sources.mkdir(parents=True, exist_ok=True)
        (sources / "Main.java").write_text("public class Main {}")
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec):
        runner = JadxRunner(jadx_path=str(fake_jadx))
        result = await runner.decompile(apk, output_dir)

    assert result.success is True
    assert result.data is not None
    assert result.data.java_file_count == 1
    assert result.data.exit_code == 0
    assert result.duration_seconds >= 0


# ---------- ApktoolRunner ----------

def test_apktool_init_without_binary(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: None)
    with pytest.raises(ApktoolError, match="not found"):
        ApktoolRunner()


@pytest.mark.asyncio
async def test_apktool_successful_run(tmp_path):
    fake_apktool = tmp_path / "apktool"
    fake_apktool.touch()
    apk = _make_fake_apk(tmp_path / "a.apk")
    output_dir = tmp_path / "out"

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))

    async def fake_exec(*args, **kwargs):
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "AndroidManifest.xml").write_text("<manifest/>")
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        runner = ApktoolRunner(apktool_path=str(fake_apktool))
        result = await runner.decode(apk, output_dir)

    assert result.manifest_path is not None
    assert result.exit_code == 0


# ---------- ManifestParser ----------

def test_manifest_parser_missing_apk(tmp_path):
    parser = ManifestParser()
    with pytest.raises(ManifestError, match="not found"):
        parser.parse(tmp_path / "nope.apk")


# ---------- Orchestrator ----------

@pytest.mark.asyncio
async def test_orchestrator_phase0_hashes_apk(tmp_path, memory):
    ctx = _make_context(tmp_path)
    orch = Orchestrator(context=ctx, memory=memory)

    # Mock phases 1 and 2 so we only run phase 0.
    # Note: _phase1_recon now takes scan_result arg — AsyncMock handles any args.
    with patch.object(orch, "_phase1_recon", new=AsyncMock(return_value=None)), \
         patch.object(orch, "_phase2_agents", new=AsyncMock(return_value=[])):
        result = await orch.run()

    assert result.status == "completed"
    assert ctx.apk_sha256 != ""
    assert ctx.apk_size_bytes > 0


@pytest.mark.asyncio
async def test_orchestrator_emits_phase_events(tmp_path, memory):
    ctx = _make_context(tmp_path)
    orch = Orchestrator(context=ctx, memory=memory)

    with patch.object(orch, "_phase1_recon", new=AsyncMock(return_value=None)), \
         patch.object(orch, "_phase2_agents", new=AsyncMock(return_value=[])):
        await orch.run()

    events = await memory.poll_events(ctx.session_id)
    event_types = {e["event_type"] for e in events}
    assert "scan.started" in event_types
    assert "scan.completed" in event_types
    assert "phase.started" in event_types
    assert "phase.completed" in event_types


@pytest.mark.asyncio
async def test_orchestrator_records_phase_timings(tmp_path, memory):
    ctx = _make_context(tmp_path)
    orch = Orchestrator(context=ctx, memory=memory)

    with patch.object(orch, "_phase1_recon", new=AsyncMock(return_value=None)), \
         patch.object(orch, "_phase2_agents", new=AsyncMock(return_value=[])):
        result = await orch.run()

    assert "phase0" in result.phase_timings
    assert "phase1" in result.phase_timings
    assert "phase2" in result.phase_timings


@pytest.mark.asyncio
async def test_orchestrator_handles_failure_gracefully(tmp_path, memory):
    """When Phase 1 raises OrchestratorError (e.g. APK gone), scan fails cleanly."""
    ctx = _make_context(tmp_path)
    orch = Orchestrator(context=ctx, memory=memory)

    with patch.object(orch, "_phase1_recon",
                      new=AsyncMock(side_effect=OrchestratorError("mock failure"))):
        result = await orch.run()

    assert result.status == "failed"
    assert "mock failure" in (result.error or "")
