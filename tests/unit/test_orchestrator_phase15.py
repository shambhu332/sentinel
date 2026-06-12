"""Unit tests for Phase 1.5 (Profiler + AST cache wiring)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.ast_cache import AstCache
from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


def _make_apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _make_ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=_make_apk(tmp_path / "test.apk"),
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )


class _NoopAgent(BaseAgent):
    AGENT_ID = "X_001"
    VULN_CLASS = "noop"

    async def is_applicable(self) -> bool:
        return True

    async def analyze(self) -> list[Finding]:
        return []


class _TaintAgent(_NoopAgent):
    AGENT_ID = "TAINT_001"


class _NativeOnlyAgent(_NoopAgent):
    AGENT_ID = "NL_001"


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


@pytest.mark.asyncio
async def test_phase15_attaches_ast_cache(tmp_path, memory):
    ctx = _make_ctx(tmp_path)
    orch = Orchestrator(context=ctx, memory=memory, agents=[_NoopAgent])

    # Stub the profiler to return one INFO finding and set a benign profile.
    async def fake_run(self):  # noqa: ARG001
        ctx.app_profile = {
            "frameworks": [],
            "native_libs_info": {"count": 5},
            "api_types": [],
        }
        return []

    with patch(
        "sentinel.core.orchestrator.ProfilerAgent.run",
        new=fake_run,
    ):
        result = await orch._phase15_profile(_StubScanResult())

    assert ctx.ast_cache is not None
    assert isinstance(ctx.ast_cache, AstCache)
    assert result == []


@pytest.mark.asyncio
async def test_phase15_drops_taint_on_flutter(tmp_path, memory):
    ctx = _make_ctx(tmp_path)
    orch = Orchestrator(
        context=ctx, memory=memory,
        agents=[_NoopAgent, _TaintAgent, _NativeOnlyAgent],
    )

    async def fake_run(self):  # noqa: ARG001
        ctx.app_profile = {
            "frameworks": ["Flutter"],
            "native_libs_info": {"count": 3},
            "api_types": [],
        }
        return []

    with patch(
        "sentinel.core.orchestrator.ProfilerAgent.run",
        new=fake_run,
    ):
        await orch._phase15_profile(_StubScanResult())

    remaining = {cls.AGENT_ID for cls in orch._agents}
    assert "TAINT_001" not in remaining  # dropped: hybrid framework
    assert "NL_001" in remaining        # kept: native libs present
    assert "X_001" in remaining


@pytest.mark.asyncio
async def test_phase15_drops_native_when_no_so(tmp_path, memory):
    ctx = _make_ctx(tmp_path)
    orch = Orchestrator(
        context=ctx, memory=memory,
        agents=[_NoopAgent, _TaintAgent, _NativeOnlyAgent],
    )

    async def fake_run(self):  # noqa: ARG001
        ctx.app_profile = {
            "frameworks": [],
            "native_libs_info": {"count": 0},
            "api_types": [],
        }
        return []

    with patch(
        "sentinel.core.orchestrator.ProfilerAgent.run",
        new=fake_run,
    ):
        await orch._phase15_profile(_StubScanResult())

    remaining = {cls.AGENT_ID for cls in orch._agents}
    assert "NL_001" not in remaining   # dropped: no native libs
    assert "TAINT_001" in remaining    # kept: pure-Java app


@pytest.mark.asyncio
async def test_phase15_profiler_failure_keeps_all_agents(tmp_path, memory):
    ctx = _make_ctx(tmp_path)
    orch = Orchestrator(
        context=ctx, memory=memory,
        agents=[_NoopAgent, _TaintAgent, _NativeOnlyAgent],
    )

    with patch(
        "sentinel.core.orchestrator.ProfilerAgent.run",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        sr = _StubScanResult()
        await orch._phase15_profile(sr)

    # All agents preserved when profiler explodes.
    assert len(orch._agents) == 3
    assert any("profiler failed" in w for w in sr.warnings)


class _StubScanResult:
    def __init__(self) -> None:
        self.warnings: list[str] = []
