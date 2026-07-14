"""Tests for CompositeMemory async T2/T3 outbox behavior."""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import pytest

from sentinel.core.finding import Finding, Severity
from sentinel.memory.composite import CompositeMemory


class _T1Memory:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def publish_event(
        self,
        session_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        pass

    async def poll_events(
        self,
        session_id: str,
        since: datetime | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        return []

    async def save_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    async def get_findings(
        self,
        session_id: str,
        min_severity: str | None = None,
    ) -> list[Finding]:
        return list(self.findings)

    async def get_finding(
        self,
        session_id: str,
        finding_id: str,
    ) -> Finding | None:
        return next((f for f in self.findings if f.finding_id == finding_id), None)

    async def add_embedding(
        self,
        session_id: str,
        finding_id: str,
        text: str,
        metadata: dict[str, Any],
    ) -> None:
        pass

    async def search_similar(
        self,
        query_text: str,
        session_id: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        return []

    async def add_graph_node(
        self,
        session_id: str,
        node_id: str,
        node_type: str,
        attrs: dict[str, Any],
    ) -> None:
        pass

    async def add_graph_edge(
        self,
        session_id: str,
        src: str,
        dst: str,
        edge_type: str,
        attrs: dict[str, Any],
    ) -> None:
        pass

    async def find_paths(
        self,
        session_id: str,
        src: str,
        dst: str,
        max_length: int = 5,
    ) -> list[list[str]]:
        return []

    async def health_check(self) -> dict[str, bool]:
        return {"tier1": True}


class _BlockingT2:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.embeddings: list[tuple[str, str, str, dict[str, Any]]] = []

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def add_embedding(
        self,
        session_id: str,
        finding_id: str,
        text: str,
        metadata: dict[str, Any],
    ) -> None:
        self.started.set()
        await self.release.wait()
        self.embeddings.append((session_id, finding_id, text, metadata))

    async def search_similar(
        self,
        query_text: str,
        session_id: str | None = None,
        limit: int = 10,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return []

    async def health_check(self) -> dict[str, bool]:
        return {"tier2": True}


class _T3Memory:
    def __init__(self) -> None:
        self.nodes: list[tuple[str, str, str, dict[str, Any]]] = []

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def add_graph_node(
        self,
        session_id: str,
        node_id: str,
        node_type: str,
        attrs: dict[str, Any],
    ) -> None:
        self.nodes.append((session_id, node_id, node_type, attrs))

    async def add_graph_edge(
        self,
        session_id: str,
        src: str,
        dst: str,
        edge_type: str,
        attrs: dict[str, Any],
    ) -> None:
        pass

    async def find_paths(
        self,
        session_id: str,
        src: str,
        dst: str,
        max_length: int = 5,
        tenant_id: str | None = None,
    ) -> list[list[str]]:
        return []

    async def health_check(self) -> dict[str, bool]:
        return {"tier3": True}


def _finding() -> Finding:
    return Finding(
        session_id="outbox01",
        agent_id="A_004",
        vuln_class="Hardcoded Secret",
        severity=Severity.HIGH,
        confidence=0.9,
        evidence={"package": "com.example.app", "file": "res/values/strings.xml"},
        recommendation="Remove the secret.",
    )


@pytest.mark.asyncio
async def test_save_finding_writes_t1_sync_and_mirrors_t2_t3_async():
    t1 = _T1Memory()
    t2 = _BlockingT2()
    t3 = _T3Memory()
    memory = CompositeMemory(tenant_id="tenant-a", t1=t1, t2=t2, t3=t3)

    await memory.connect()
    await asyncio.wait_for(memory.save_finding(_finding()), timeout=0.1)

    assert len(t1.findings) == 1
    assert t1.findings[0].dynamic_target is None

    await asyncio.wait_for(t2.started.wait(), timeout=1.0)
    assert t2.embeddings == []

    t2.release.set()
    await memory.close()

    assert len(t2.embeddings) == 1
    assert t2.embeddings[0][3]["tenant_id"] == "tenant-a"
    assert t2.embeddings[0][3]["agent_id"] == "A_004"
    assert len(t3.nodes) == 1
    assert t3.nodes[0][2] == "finding"
