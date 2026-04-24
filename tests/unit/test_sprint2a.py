"""Unit tests for Sprint 2a: memory bus + BaseAgent + TEST_001."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.agents.base import BaseAgent
from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory, create_memory

# ---------- Helpers ----------

def _make_context(tmp_path: Path, scope: BountyScope | None = None) -> ScanContext:
    apk = tmp_path / "test.apk"
    apk.write_bytes(b"PK\x03\x04fake apk")
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "workspace",
        scope=scope or BountyScope(),
    )


@pytest.fixture
async def memory(tmp_path):
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ---------- Memory factory ----------

def test_create_memory_lightweight(tmp_path):
    m = create_memory("lightweight", data_dir=tmp_path)
    assert isinstance(m, LightweightMemory)


def test_create_memory_invalid():
    with pytest.raises(ValueError):
        create_memory("nonexistent")


# ---------- LightweightMemory: Events ----------

@pytest.mark.asyncio
async def test_publish_and_poll_events(memory):
    await memory.publish_event("sess1", "test.event", {"k": "v"})
    events = await memory.poll_events("sess1")
    assert len(events) == 1
    assert events[0]["event_type"] == "test.event"
    assert events[0]["payload"] == {"k": "v"}


@pytest.mark.asyncio
async def test_poll_events_isolates_sessions(memory):
    await memory.publish_event("sess_a", "e", {})
    await memory.publish_event("sess_b", "e", {})
    assert len(await memory.poll_events("sess_a")) == 1
    assert len(await memory.poll_events("sess_b")) == 1


@pytest.mark.asyncio
async def test_poll_events_filter_type(memory):
    await memory.publish_event("s", "type_a", {})
    await memory.publish_event("s", "type_b", {})
    filtered = await memory.poll_events("s", event_type="type_a")
    assert len(filtered) == 1
    assert filtered[0]["event_type"] == "type_a"


# ---------- LightweightMemory: Findings ----------

@pytest.mark.asyncio
async def test_save_and_get_finding(memory):
    f = Finding(
        agent_id="F_001", vuln_class="Firebase", severity=Severity.CRITICAL,
        confidence=0.95, recommendation="fix", session_id="abcd1234efgh5678",
        evidence={"project": "test"},
    )
    await memory.save_finding(f)
    retrieved = await memory.get_finding("abcd1234efgh5678", f.finding_id)
    assert retrieved is not None
    assert retrieved.agent_id == "F_001"


@pytest.mark.asyncio
async def test_get_findings_severity_filter(memory):
    sid = "testsess12345678"
    for sev in [Severity.LOW, Severity.HIGH, Severity.CRITICAL]:
        f = Finding(
            agent_id="A_001", vuln_class="x", severity=sev,
            confidence=0.5, recommendation="x", session_id=sid,
            evidence={"sev": sev.value},
        )
        await memory.save_finding(f)
    high_and_above = await memory.get_findings(sid, min_severity="High")
    assert len(high_and_above) == 2
    severities = {f.severity for f in high_and_above}
    assert Severity.LOW not in severities


# ---------- LightweightMemory: Graph ----------

@pytest.mark.asyncio
async def test_graph_nodes_and_edges(memory):
    await memory.add_graph_node("s1", "a", "finding", {"agent": "A_001"})
    await memory.add_graph_node("s1", "b", "finding", {"agent": "B_001"})
    await memory.add_graph_edge("s1", "a", "b", "enables", {})
    paths = await memory.find_paths("s1", "a", "b")
    assert paths == [["a", "b"]]


@pytest.mark.asyncio
async def test_graph_multi_hop_path(memory):
    for n in ["x", "y", "z"]:
        await memory.add_graph_node("s", n, "step", {})
    await memory.add_graph_edge("s", "x", "y", "leads_to", {})
    await memory.add_graph_edge("s", "y", "z", "leads_to", {})
    paths = await memory.find_paths("s", "x", "z", max_length=3)
    assert paths == [["x", "y", "z"]]


@pytest.mark.asyncio
async def test_graph_no_path(memory):
    await memory.add_graph_node("s", "a", "x", {})
    await memory.add_graph_node("s", "b", "x", {})
    paths = await memory.find_paths("s", "a", "b")
    assert paths == []


# ---------- LightweightMemory: Health ----------

@pytest.mark.asyncio
async def test_health_check(memory):
    h = await memory.health_check()
    assert h["tier1"] is True
    assert h["tier3"] is True


# ---------- BaseAgent ----------

@pytest.mark.asyncio
async def test_base_agent_rejects_invalid_id(tmp_path, memory):
    class BadAgent(BaseAgent):
        AGENT_ID = "not-valid"
        VULN_CLASS = "x"

        async def is_applicable(self):
            return True

        async def analyze(self):
            return []

    with pytest.raises(Exception, match="Invalid AGENT_ID"):
        BadAgent(context=_make_context(tmp_path), memory=memory)


@pytest.mark.asyncio
async def test_base_agent_skip_when_not_applicable(tmp_path, memory):
    class SkippyAgent(BaseAgent):
        AGENT_ID = "A_001"
        VULN_CLASS = "Test"

        async def is_applicable(self):
            return False

        async def analyze(self):
            raise Exception("should not be called")

    agent = SkippyAgent(context=_make_context(tmp_path), memory=memory)
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_base_agent_isolates_errors(tmp_path, memory):
    class BrokenAgent(BaseAgent):
        AGENT_ID = "A_002"
        VULN_CLASS = "Test"

        async def is_applicable(self):
            return True

        async def analyze(self):
            raise RuntimeError("boom")

    agent = BrokenAgent(context=_make_context(tmp_path), memory=memory)
    # Does not raise — errors are isolated per agent
    findings = await agent.run()
    assert findings == []


@pytest.mark.asyncio
async def test_base_agent_scope_filter(tmp_path, memory):
    scope = BountyScope(in_scope_packages=["com.allowed.app"])
    ctx = _make_context(tmp_path, scope=scope)

    class FilterAgent(BaseAgent):
        AGENT_ID = "A_003"
        VULN_CLASS = "Test"

        async def is_applicable(self):
            return True

        async def analyze(self):
            return [
                self._make_finding(
                    vuln_class="Test", severity=Severity.HIGH, confidence=0.9,
                    recommendation="fix", evidence={"package": "com.allowed.app"},
                ),
                self._make_finding(
                    vuln_class="Test", severity=Severity.HIGH, confidence=0.9,
                    recommendation="fix", evidence={"package": "com.blocked.app"},
                ),
            ]

    agent = FilterAgent(context=ctx, memory=memory)
    findings = await agent.run()
    # Only the in-scope finding survives
    assert len(findings) == 1
    assert findings[0].evidence["package"] == "com.allowed.app"


# ---------- TEST_001 ----------

@pytest.mark.asyncio
async def test_test_agent_runs_and_emits_finding(tmp_path, memory):
    ctx = _make_context(tmp_path)
    agent = PipelineSmokeTestAgent(context=ctx, memory=memory)
    findings = await agent.run()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "TEST_001"
    assert f.severity == Severity.INFO


@pytest.mark.asyncio
async def test_test_agent_persists_via_memory(tmp_path, memory):
    ctx = _make_context(tmp_path)
    agent = PipelineSmokeTestAgent(context=ctx, memory=memory)
    await agent.run()
    stored = await memory.get_findings(ctx.session_id)
    assert len(stored) == 1
    assert stored[0].agent_id == "TEST_001"


@pytest.mark.asyncio
async def test_test_agent_emits_lifecycle_events(tmp_path, memory):
    ctx = _make_context(tmp_path)
    agent = PipelineSmokeTestAgent(context=ctx, memory=memory)
    await agent.run()
    events = await memory.poll_events(ctx.session_id)
    event_types = {e["event_type"] for e in events}
    assert "agent.started" in event_types
    assert "agent.completed" in event_types
    assert "finding.emitted" in event_types
