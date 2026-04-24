"""MemoryInterface — abstract base for all memory backends.

Two implementations:
    - LightweightMemory (SQLite + ChromaDB + NetworkX) — solo deployment
    - ProductionMemory (Redis + Qdrant + Neo4j) — multi-user SaaS deployment

Agents depend only on this interface, never the concrete backend.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from sentinel.core.finding import Finding


class MemoryInterface(ABC):
    """Unified memory abstraction across all three tiers.

    Tier 1 (Working Memory): event bus + finding store — fast, transient
    Tier 2 (Semantic Memory): vector search — cross-scan similarity
    Tier 3 (Knowledge Graph): relationships — chain detection
    """

    # ---- Lifecycle ----

    @abstractmethod
    async def connect(self) -> None:
        """Open connections, create tables/collections if missing."""

    @abstractmethod
    async def close(self) -> None:
        """Release all resources."""

    # ---- Tier 1: Events ----

    @abstractmethod
    async def publish_event(self, session_id: str, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an inter-agent event. Triggers subscribers."""

    @abstractmethod
    async def poll_events(
        self, session_id: str, since: datetime | None = None, event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Poll events for a session, optionally filtered by type."""

    # ---- Tier 1: Findings ----

    @abstractmethod
    async def save_finding(self, finding: Finding) -> None:
        """Persist a finding. Idempotent on finding_id."""

    @abstractmethod
    async def get_findings(
        self, session_id: str, min_severity: str | None = None,
    ) -> list[Finding]:
        """Retrieve all findings for a session."""

    @abstractmethod
    async def get_finding(self, session_id: str, finding_id: str) -> Finding | None:
        """Retrieve a single finding by its stable ID."""

    # ---- Tier 2: Semantic ----

    @abstractmethod
    async def add_embedding(
        self, session_id: str, finding_id: str, text: str, metadata: dict[str, Any],
    ) -> None:
        """Index a finding's text for semantic search."""

    @abstractmethod
    async def search_similar(
        self, query_text: str, session_id: str | None = None, limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return similar findings with distance scores."""

    # ---- Tier 3: Graph ----

    @abstractmethod
    async def add_graph_node(
        self, session_id: str, node_id: str, node_type: str, attrs: dict[str, Any],
    ) -> None:
        """Add a node to the knowledge graph."""

    @abstractmethod
    async def add_graph_edge(
        self, session_id: str, src: str, dst: str, edge_type: str, attrs: dict[str, Any],
    ) -> None:
        """Add a directed edge between two nodes."""

    @abstractmethod
    async def find_paths(
        self, session_id: str, src: str, dst: str, max_length: int = 5,
    ) -> list[list[str]]:
        """Find all simple paths from src to dst. Used for chain detection."""

    # ---- Health ----

    @abstractmethod
    async def health_check(self) -> dict[str, bool]:
        """Return {tier1: bool, tier2: bool, tier3: bool}."""


class MemoryError(Exception):
    """Base error for memory operations."""
