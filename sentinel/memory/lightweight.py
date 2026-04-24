"""LightweightMemory — zero-dependency backend for solo deployment.

Tier 1: SQLite (events + findings)
Tier 2: ChromaDB (local persistent mode) for embeddings
Tier 3: NetworkX (in-memory DiGraph, persisted to JSON)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import networkx as nx

from sentinel.core.finding import Finding, Severity
from sentinel.memory.interface import MemoryError, MemoryInterface

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class LightweightMemory(MemoryInterface):
    """Single-process memory using SQLite + Chroma + NetworkX."""

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir.expanduser().resolve()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / "sentinel.db"
        self._chroma_path = self._data_dir / "chroma"
        self._graph_dir = self._data_dir / "graphs"
        self._graph_dir.mkdir(exist_ok=True)

        self._db: aiosqlite.Connection | None = None
        self._chroma_client: Any = None
        self._chroma_collection: Any = None
        self._graphs: dict[str, nx.DiGraph] = {}

    # ---------- Lifecycle ----------

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")

        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(session_id, event_type);

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (session_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(session_id, severity);
        """)
        await self._db.commit()

        # ChromaDB — lazy import so it only loads if actually used
        try:
            import chromadb
            self._chroma_client = chromadb.PersistentClient(path=str(self._chroma_path))
            self._chroma_collection = self._chroma_client.get_or_create_collection(
                name="sentinel_findings",
                metadata={"hnsw:space": "cosine"},
            )
        except Exception as e:
            logger.warning("ChromaDB unavailable, semantic search disabled: %s", e)
            self._chroma_client = None

        logger.info("LightweightMemory connected at %s", self._data_dir)

    async def close(self) -> None:
        # Persist graphs before closing
        for session_id, graph in self._graphs.items():
            self._persist_graph(session_id, graph)
        self._graphs.clear()

        if self._db:
            await self._db.close()
            self._db = None

    # ---------- Tier 1: Events ----------

    async def publish_event(
        self, session_id: str, event_type: str, payload: dict[str, Any],
    ) -> None:
        if self._db is None:
            raise MemoryError("not connected")
        await self._db.execute(
            "INSERT INTO events (session_id, event_type, payload, created_at) VALUES (?, ?, ?, ?)",
            (session_id, event_type, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )
        await self._db.commit()

    async def poll_events(
        self, session_id: str, since: datetime | None = None, event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if self._db is None:
            raise MemoryError("not connected")
        query = "SELECT id, event_type, payload, created_at FROM events WHERE session_id = ?"
        params: list[Any] = [session_id]
        if since:
            query += " AND created_at > ?"
            params.append(since.isoformat())
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        query += " ORDER BY created_at ASC"

        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0], "event_type": r[1],
                "payload": json.loads(r[2]), "created_at": r[3],
            }
            for r in rows
        ]

    # ---------- Tier 1: Findings ----------

    async def save_finding(self, finding: Finding) -> None:
        if self._db is None:
            raise MemoryError("not connected")
        await self._db.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id, session_id, agent_id, severity, confidence, data, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.finding_id, finding.session_id, finding.agent_id,
                finding.severity.value, finding.confidence,
                finding.model_dump_json(),
                finding.created_at.isoformat(),
            ),
        )
        await self._db.commit()

    async def get_findings(
        self, session_id: str, min_severity: str | None = None,
    ) -> list[Finding]:
        if self._db is None:
            raise MemoryError("not connected")
        query = "SELECT data FROM findings WHERE session_id = ?"
        params: list[Any] = [session_id]
        if min_severity:
            min_rank = SEVERITY_ORDER.get(Severity(min_severity), 0)
            allowed = [s.value for s, r in SEVERITY_ORDER.items() if r >= min_rank]
            placeholders = ",".join("?" * len(allowed))
            query += f" AND severity IN ({placeholders})"
            params.extend(allowed)
        query += " ORDER BY created_at ASC"

        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()
        return [Finding.model_validate_json(r[0]) for r in rows]

    async def get_finding(self, session_id: str, finding_id: str) -> Finding | None:
        if self._db is None:
            raise MemoryError("not connected")
        cursor = await self._db.execute(
            "SELECT data FROM findings WHERE session_id = ? AND finding_id = ?",
            (session_id, finding_id),
        )
        row = await cursor.fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    # ---------- Tier 2: Semantic ----------

    async def add_embedding(
        self, session_id: str, finding_id: str, text: str, metadata: dict[str, Any],
    ) -> None:
        if self._chroma_collection is None:
            return
        meta = {**metadata, "session_id": session_id, "finding_id": finding_id}
        self._chroma_collection.upsert(
            ids=[f"{session_id}:{finding_id}"],
            documents=[text[:8000]],
            metadatas=[meta],
        )

    async def search_similar(
        self, query_text: str, session_id: str | None = None, limit: int = 10,
    ) -> list[dict[str, Any]]:
        if self._chroma_collection is None:
            return []
        where = {"session_id": session_id} if session_id else None
        results = self._chroma_collection.query(
            query_texts=[query_text[:8000]],
            n_results=min(limit, 100),
            where=where,
        )
        if not results or not results.get("ids"):
            return []
        out = []
        ids = results["ids"][0] or []
        docs = results["documents"][0] or []
        metas = results["metadatas"][0] or []
        dists = results["distances"][0] or []
        for i, _id in enumerate(ids):
            out.append({
                "id": _id, "document": docs[i] if i < len(docs) else "",
                "metadata": metas[i] if i < len(metas) else {},
                "distance": dists[i] if i < len(dists) else 1.0,
            })
        return out

    # ---------- Tier 3: Graph ----------

    def _get_graph(self, session_id: str) -> nx.DiGraph:
        if session_id not in self._graphs:
            # Try to load from disk
            graph_file = self._graph_dir / f"{session_id}.json"
            if graph_file.exists():
                try:
                    data = json.loads(graph_file.read_text())
                    self._graphs[session_id] = nx.node_link_graph(data, directed=True, edges="edges")
                except Exception as e:
                    logger.warning("Could not load graph for %s: %s", session_id, e)
                    self._graphs[session_id] = nx.DiGraph()
            else:
                self._graphs[session_id] = nx.DiGraph()
        return self._graphs[session_id]

    def _persist_graph(self, session_id: str, graph: nx.DiGraph) -> None:
        graph_file = self._graph_dir / f"{session_id}.json"
        try:
            data = nx.node_link_data(graph, edges="edges")
            graph_file.write_text(json.dumps(data))
        except Exception as e:
            logger.warning("Could not persist graph for %s: %s", session_id, e)

    async def add_graph_node(
        self, session_id: str, node_id: str, node_type: str, attrs: dict[str, Any],
    ) -> None:
        g = self._get_graph(session_id)
        g.add_node(node_id, node_type=node_type, **attrs)

    async def add_graph_edge(
        self, session_id: str, src: str, dst: str, edge_type: str, attrs: dict[str, Any],
    ) -> None:
        g = self._get_graph(session_id)
        if src not in g:
            g.add_node(src)
        if dst not in g:
            g.add_node(dst)
        g.add_edge(src, dst, edge_type=edge_type, **attrs)

    async def find_paths(
        self, session_id: str, src: str, dst: str, max_length: int = 5,
    ) -> list[list[str]]:
        g = self._get_graph(session_id)
        if src not in g or dst not in g:
            return []
        try:
            return [p for p in nx.all_simple_paths(g, src, dst, cutoff=max_length)]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    # ---------- Health ----------

    async def health_check(self) -> dict[str, bool]:
        tier1 = self._db is not None
        tier2 = self._chroma_collection is not None
        tier3 = True  # NetworkX is always available
        return {"tier1": tier1, "tier2": tier2, "tier3": tier3}
