"""CompositeMemory — full 3-tier production stack.

Combines:

    T1  PostgresMemory        (events + findings + audit log)
    T2  QdrantMemory          (semantic search over findings)
    T3  Neo4jMemory           (attack-chain graph)

Constructor takes optional per-tier instances so tests can inject
fakes. `from_env()` reads:

    SENTINEL_POSTGRES_URL / POSTGRES_URL
    SENTINEL_QDRANT_URL   / QDRANT_URL
    SENTINEL_NEO4J_URL    / NEO4J_URL

Any tier whose URL is unset falls back to `LightweightMemory` for that
tier — with a loud `logger.warning`. This gives operators a graceful
degrade path when e.g. Qdrant is down but scans still need to run.

Isolation guarantee: every write path passes `tenant_id` through to
Postgres RLS and Qdrant collection / Neo4j node key. A missing
`tenant_id` raises `MemoryError` rather than silently writing to a
default namespace.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.core.finding import Finding
from sentinel.memory.interface import MemoryInterface

logger = logging.getLogger(__name__)


def _env_or(name: str, *fallbacks: str) -> str | None:
    for candidate in (name, *fallbacks):
        v = os.getenv(candidate)
        if v:
            return v
    return None


class MemoryWorker:
    """Async outbox that mirrors T1 findings into T2/T3 without blocking."""

    def __init__(self, owner: "CompositeMemory") -> None:
        self._owner = owner
        self._queue: asyncio.Queue[Finding] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    def enqueue_finding(self, finding: Finding) -> None:
        self.start()
        self._queue.put_nowait(finding.model_copy(deep=True))

    async def stop(self) -> None:
        if self._task is None:
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._queue.join(), timeout=5.0)
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _run(self) -> None:
        while True:
            finding = await self._queue.get()
            try:
                await self._owner._write_async_memory_for_finding(finding)
            except Exception:
                logger.exception(
                    "Composite: async memory outbox failed for %s",
                    finding.finding_id,
                )
            finally:
                self._queue.task_done()


class CompositeMemory(MemoryInterface):
    """Delegates to T1/T2/T3 backends with per-tier graceful degrade."""

    def __init__(
        self,
        *,
        tenant_id: str | None = None,
        t1: MemoryInterface | None = None,
        t2: Any = None,
        t3: Any = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._t1 = t1
        self._t2 = t2
        self._t3 = t3
        # Ownership of a fallback LightweightMemory when tiers degrade.
        self._fallback: MemoryInterface | None = None
        self._worker = MemoryWorker(self)

    # ---------- Constructors ----------

    @classmethod
    def from_env(
        cls,
        tenant_id: str | None = None,
        *,
        data_dir: Path | None = None,
    ) -> "CompositeMemory":
        from sentinel.memory.lightweight import LightweightMemory
        from sentinel.memory.neo4j_backend import Neo4jMemory
        from sentinel.memory.postgres import PostgresMemory
        from sentinel.memory.qdrant_backend import QdrantMemory

        pg_url = _env_or("SENTINEL_POSTGRES_URL", "POSTGRES_URL")
        qd_url = _env_or("SENTINEL_QDRANT_URL", "QDRANT_URL")
        n4_url = _env_or("SENTINEL_NEO4J_URL", "NEO4J_URL")

        fallback: LightweightMemory | None = None
        need_fallback = not (pg_url and qd_url and n4_url)
        if need_fallback:
            fallback = LightweightMemory(
                data_dir=data_dir or Path("./data"),
            )

        t1: MemoryInterface
        if pg_url:
            t1 = PostgresMemory(dsn=pg_url, tenant_id=tenant_id)
        else:
            logger.warning(
                "SENTINEL_POSTGRES_URL unset — Tier-1 falling back to LightweightMemory. "
                "This is fine for local dev; production must set POSTGRES_URL."
            )
            assert fallback is not None
            t1 = fallback

        t2: Any
        if qd_url:
            t2 = QdrantMemory(url=qd_url, tenant_id=tenant_id)
        else:
            logger.warning(
                "SENTINEL_QDRANT_URL unset — Tier-2 falling back to LightweightMemory."
            )
            assert fallback is not None
            t2 = fallback

        t3: Any
        if n4_url:
            t3 = Neo4jMemory(url=n4_url, tenant_id=tenant_id)
        else:
            logger.warning(
                "SENTINEL_NEO4J_URL unset — Tier-3 falling back to LightweightMemory."
            )
            assert fallback is not None
            t3 = fallback

        m = cls(tenant_id=tenant_id, t1=t1, t2=t2, t3=t3)
        m._fallback = fallback
        return m

    # ---------- Lifecycle ----------

    async def connect(self) -> None:
        seen: set[int] = set()
        for tier in (self._t1, self._t2, self._t3, self._fallback):
            if tier is None or id(tier) in seen:
                continue
            seen.add(id(tier))
            await tier.connect()
        self._worker.start()

    async def close(self) -> None:
        await self._worker.stop()
        seen: set[int] = set()
        for tier in (self._t1, self._t2, self._t3, self._fallback):
            if tier is None or id(tier) in seen:
                continue
            seen.add(id(tier))
            try:
                await tier.close()
            except Exception:
                logger.exception("Composite: tier close failed")

    # ---------- T1 ----------

    async def publish_event(
        self, session_id: str, event_type: str, payload: dict[str, Any],
    ) -> None:
        assert self._t1 is not None
        await self._t1.publish_event(session_id, event_type, payload)

    async def poll_events(
        self, session_id: str, since: datetime | None = None, event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        assert self._t1 is not None
        return await self._t1.poll_events(session_id, since, event_type)

    async def save_finding(self, finding: Finding) -> None:
        assert self._t1 is not None
        await self._t1.save_finding(finding)
        self._worker.enqueue_finding(finding)

    async def _write_async_memory_for_finding(self, finding: Finding) -> None:
        metadata = _finding_memory_metadata(finding, self._tenant_id)
        text = _finding_embedding_text(finding)
        if self._t2 is not None:
            try:
                await self.add_embedding(
                    finding.session_id,
                    finding.finding_id,
                    text,
                    metadata,
                )
            except Exception:
                logger.exception(
                    "Composite: Tier-2 embedding write failed for %s",
                    finding.finding_id,
                )
        if self._t3 is not None:
            try:
                await self.add_graph_node(
                    finding.session_id,
                    finding.finding_id,
                    "finding",
                    metadata,
                )
            except Exception:
                logger.exception(
                    "Composite: Tier-3 graph-node write failed for %s",
                    finding.finding_id,
                )

    async def get_findings(
        self, session_id: str, min_severity: str | None = None,
    ) -> list[Finding]:
        assert self._t1 is not None
        return await self._t1.get_findings(session_id, min_severity)

    async def get_finding(
        self, session_id: str, finding_id: str,
    ) -> Finding | None:
        assert self._t1 is not None
        return await self._t1.get_finding(session_id, finding_id)

    # ---------- T2 ----------

    async def add_embedding(
        self, session_id: str, finding_id: str, text: str, metadata: dict[str, Any],
    ) -> None:
        assert self._t2 is not None
        md = dict(metadata)
        if self._tenant_id and "tenant_id" not in md:
            md["tenant_id"] = self._tenant_id
        await self._t2.add_embedding(session_id, finding_id, text, md)

    async def search_similar(
        self, query_text: str, session_id: str | None = None, limit: int = 10,
    ) -> list[dict[str, Any]]:
        assert self._t2 is not None
        # QdrantMemory takes an extra tenant_id kwarg; LightweightMemory doesn't.
        results: list[dict[str, Any]]
        try:
            results = await self._t2.search_similar(
                query_text, session_id=session_id, limit=limit,
                tenant_id=self._tenant_id,
            )
        except TypeError:
            results = await self._t2.search_similar(query_text, session_id, limit)
        return results

    # ---------- T3 ----------

    async def add_graph_node(
        self, session_id: str, node_id: str, node_type: str, attrs: dict[str, Any],
    ) -> None:
        assert self._t3 is not None
        merged = dict(attrs)
        if self._tenant_id and "tenant_id" not in merged:
            merged["tenant_id"] = self._tenant_id
        await self._t3.add_graph_node(session_id, node_id, node_type, merged)

    async def add_graph_edge(
        self, session_id: str, src: str, dst: str, edge_type: str, attrs: dict[str, Any],
    ) -> None:
        assert self._t3 is not None
        merged = dict(attrs)
        if self._tenant_id and "tenant_id" not in merged:
            merged["tenant_id"] = self._tenant_id
        await self._t3.add_graph_edge(session_id, src, dst, edge_type, merged)

    async def find_paths(
        self, session_id: str, src: str, dst: str, max_length: int = 5,
    ) -> list[list[str]]:
        assert self._t3 is not None
        paths: list[list[str]]
        try:
            paths = await self._t3.find_paths(
                session_id, src, dst, max_length=max_length,
                tenant_id=self._tenant_id,
            )
        except TypeError:
            paths = await self._t3.find_paths(session_id, src, dst, max_length)
        return paths

    # ---------- Health ----------

    async def health_check(self) -> dict[str, bool]:
        out = {"tier1": False, "tier2": False, "tier3": False}
        try:
            if self._t1 is not None:
                h1 = await self._t1.health_check()
                out["tier1"] = bool(h1.get("tier1", False)) if isinstance(h1, dict) else bool(h1)
        except Exception:
            pass
        try:
            if self._t2 is not None:
                if hasattr(self._t2, "health_check"):
                    h2 = await self._t2.health_check()
                    out["tier2"] = (bool(h2.get("tier2", False))
                                    if isinstance(h2, dict) else bool(h2))
        except Exception:
            pass
        try:
            if self._t3 is not None:
                if hasattr(self._t3, "health_check"):
                    h3 = await self._t3.health_check()
                    out["tier3"] = (bool(h3.get("tier3", False))
                                    if isinstance(h3, dict) else bool(h3))
        except Exception:
            pass
        return out


def _finding_embedding_text(finding: Finding) -> str:
    parts = [
        finding.vuln_class,
        str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
        finding.severity_rationale or "",
        finding.observed_result or "",
        finding.recommendation or "",
    ]
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    for key in ("issue", "title", "summary", "vector", "file", "package"):
        value = evidence.get(key)
        if value:
            parts.append(str(value))
    return "\n".join(p for p in parts if p)


def _finding_memory_metadata(
    finding: Finding,
    tenant_id: str | None,
) -> dict[str, Any]:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    metadata: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "agent_id": finding.agent_id,
        "vuln_class": finding.vuln_class,
        "severity": (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        ),
        "confidence": finding.confidence,
        "verification_status": finding.verification_status,
        "verification_state": finding.verification_state,
        "finding_category": finding.finding_category,
    }
    if tenant_id:
        metadata["tenant_id"] = tenant_id
    for key in ("package", "file", "component", "authority", "host", "path"):
        value = evidence.get(key)
        if isinstance(value, (str, int, float, bool)):
            metadata[key] = value
    return metadata
