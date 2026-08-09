"""Unit tests for ProductionMemory Tier 1 (Redis Streams + Hash).

Uses fakeredis so the tests run offline. The same test would pass
against a real Redis 7 — fakeredis implements XADD / XRANGE / HSET
faithfully for our usage.
"""
from __future__ import annotations

import pytest

from sentinel.core.finding import Finding, Severity
from sentinel.memory.interface import MemoryError
from sentinel.memory.production import ProductionMemory


def _finding(sid: str, agent_id: str = "A_004", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        agent_id=agent_id,
        vuln_class="Hardcoded Secret",
        severity=severity,
        confidence=0.9,
        recommendation="rotate the key",
        session_id=sid,
        evidence={"file": "x.java", "marker": agent_id},
    )


@pytest.fixture
async def memory():
    fakeredis = pytest.importorskip("fakeredis")
    m = ProductionMemory(redis_url="redis://localhost:6379")
    # Swap the connect step for a fakeredis client.
    m._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield m
    await m.close()


@pytest.mark.asyncio
async def test_connect_without_redis_package_raises(monkeypatch):
    """If redis isn't installed, connect() must fail loudly, not silently."""
    import sys
    monkeypatch.setitem(sys.modules, "redis.asyncio", None)
    m = ProductionMemory()
    with pytest.raises(MemoryError):
        await m.connect()


@pytest.mark.asyncio
async def test_publish_and_poll_events_roundtrip(memory):
    await memory.publish_event("sess_abcd1234", "agent.started", {"agent_id": "A_004"})
    await memory.publish_event("sess_abcd1234", "finding.emitted", {"sev": "High"})

    events = await memory.poll_events("sess_abcd1234")
    assert len(events) == 2
    assert events[0]["event_type"] == "agent.started"
    assert events[0]["payload"] == {"agent_id": "A_004"}
    assert events[1]["event_type"] == "finding.emitted"


@pytest.mark.asyncio
async def test_poll_events_type_filter(memory):
    await memory.publish_event("s1abcdef", "agent.started", {})
    await memory.publish_event("s1abcdef", "finding.emitted", {})
    await memory.publish_event("s1abcdef", "agent.completed", {})

    filtered = await memory.poll_events("s1abcdef", event_type="finding.emitted")
    assert len(filtered) == 1
    assert filtered[0]["event_type"] == "finding.emitted"


@pytest.mark.asyncio
async def test_save_and_get_findings_preserves_order_and_dedupes(memory):
    sid = "sess_findings1"
    f1 = _finding(sid, agent_id="A_004")
    f2 = _finding(sid, agent_id="N_001")
    f3 = _finding(sid, agent_id="C_006")

    await memory.save_finding(f1)
    await memory.save_finding(f2)
    await memory.save_finding(f3)
    # Re-save f2 — idempotent in the hash, but the order list dedupes
    await memory.save_finding(f2)

    findings = await memory.get_findings(sid)
    agent_ids = [f.agent_id for f in findings]
    assert agent_ids == ["A_004", "N_001", "C_006"]


@pytest.mark.asyncio
async def test_get_finding_by_id_returns_round_trip(memory):
    sid = "sess_byid"
    f = _finding(sid, agent_id="LOGIC_001")
    await memory.save_finding(f)

    fetched = await memory.get_finding(sid, f.finding_id)
    assert fetched is not None
    assert fetched.agent_id == "LOGIC_001"
    assert fetched.vuln_class == "Hardcoded Secret"
    assert fetched.evidence["marker"] == "LOGIC_001"


@pytest.mark.asyncio
async def test_get_findings_min_severity_filter(memory):
    sid = "sess_filter"
    await memory.save_finding(_finding(sid, "A_001", Severity.INFO))
    await memory.save_finding(_finding(sid, "A_002", Severity.LOW))
    await memory.save_finding(_finding(sid, "A_003", Severity.HIGH))
    await memory.save_finding(_finding(sid, "A_004", Severity.CRITICAL))

    high = await memory.get_findings(sid, min_severity="High")
    assert [f.agent_id for f in high] == ["A_003", "A_004"]


@pytest.mark.asyncio
async def test_get_finding_missing_returns_none(memory):
    assert await memory.get_finding("nosession", "missing0123") is None


@pytest.mark.asyncio
async def test_tier2_tier3_degrade_gracefully(memory):
    # Tier 2/3 are not yet implemented in ProductionMemory — they log a
    # warning and return empty results instead of raising, so a missing
    # vector/graph backend never kills a scan.
    await memory.add_embedding("s", "f", "t", {})          # must not raise
    assert await memory.search_similar("q") == []
    await memory.add_graph_node("s", "n", "t", {})         # must not raise
    await memory.add_graph_edge("s", "a", "b", "e", {})    # must not raise
    assert await memory.find_paths("s", "a", "b") == []


@pytest.mark.asyncio
async def test_unconnected_operations_raise_memory_error():
    m = ProductionMemory()
    with pytest.raises(MemoryError):
        await m.publish_event("sess_unconnec", "e", {})
    with pytest.raises(MemoryError):
        await m.save_finding(_finding("sess_unconnec"))


@pytest.mark.asyncio
async def test_health_check_tier1_only(memory):
    h = await memory.health_check()
    assert h == {"tier1": True, "tier2": False, "tier3": False}
