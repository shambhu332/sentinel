"""ProductionMemory — multi-process backend for SaaS deployment.

Tier 1: Redis (events + finding cache)
Tier 2: Qdrant (vector DB)
Tier 3: Neo4j (graph DB)

Requires external services. Start with `docker-compose up redis qdrant neo4j`.
Stub implementation for Sprint 2a — full wiring in Sprint 11 (when deployment starts).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sentinel.core.finding import Finding
from sentinel.memory.interface import MemoryError, MemoryInterface

logger = logging.getLogger(__name__)


class ProductionMemory(MemoryInterface):
    """Placeholder for multi-user deployment backend.

    NOT YET IMPLEMENTED. Interface matches LightweightMemory exactly so agents
    don't change when you migrate from local dev to production SaaS.
    Full implementation arrives in Sprint 11 (post-beta deployment phase).
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        qdrant_url: str = "http://localhost:6333",
        neo4j_url: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "sentineldev",
    ) -> None:
        self._redis_url = redis_url
        self._qdrant_url = qdrant_url
        self._neo4j_url = neo4j_url
        self._neo4j_user = neo4j_user
        self._neo4j_password = neo4j_password
        self._redis: Any = None
        self._qdrant: Any = None
        self._neo4j: Any = None

    async def connect(self) -> None:
        raise MemoryError(
            "ProductionMemory not implemented yet. Use LightweightMemory for now. "
            "Full implementation scheduled for Sprint 11."
        )

    async def close(self) -> None:
        pass

    async def publish_event(self, session_id: str, event_type: str, payload: dict[str, Any]) -> None:
        raise MemoryError("ProductionMemory not implemented")

    async def poll_events(
        self, session_id: str, since: datetime | None = None, event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        raise MemoryError("ProductionMemory not implemented")

    async def save_finding(self, finding: Finding) -> None:
        raise MemoryError("ProductionMemory not implemented")

    async def get_findings(
        self, session_id: str, min_severity: str | None = None,
    ) -> list[Finding]:
        raise MemoryError("ProductionMemory not implemented")

    async def get_finding(self, session_id: str, finding_id: str) -> Finding | None:
        raise MemoryError("ProductionMemory not implemented")

    async def add_embedding(
        self, session_id: str, finding_id: str, text: str, metadata: dict[str, Any],
    ) -> None:
        raise MemoryError("ProductionMemory not implemented")

    async def search_similar(
        self, query_text: str, session_id: str | None = None, limit: int = 10,
    ) -> list[dict[str, Any]]:
        raise MemoryError("ProductionMemory not implemented")

    async def add_graph_node(
        self, session_id: str, node_id: str, node_type: str, attrs: dict[str, Any],
    ) -> None:
        raise MemoryError("ProductionMemory not implemented")

    async def add_graph_edge(
        self, session_id: str, src: str, dst: str, edge_type: str, attrs: dict[str, Any],
    ) -> None:
        raise MemoryError("ProductionMemory not implemented")

    async def find_paths(
        self, session_id: str, src: str, dst: str, max_length: int = 5,
    ) -> list[list[str]]:
        raise MemoryError("ProductionMemory not implemented")

    async def health_check(self) -> dict[str, bool]:
        return {"tier1": False, "tier2": False, "tier3": False}
