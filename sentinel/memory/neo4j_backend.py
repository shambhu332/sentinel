"""Neo4jMemory — Tier-3 graph backend.

Phase 1.2 of the production-hardening plan.

Design notes:

* Nodes are labelled `Finding` and keyed on `(tenant_id, node_id)` via
  a merged uniqueness constraint. Tenant is baked into the key so a
  Cypher query cannot accidentally cross tenants — the constraint
  ensures parity nodes with the same `node_id` but different tenants
  coexist without conflict.
* Edges are typed via the `RELATES_TO` relationship with a `type`
  property (`same-host`, `secret-leaks-into`, `token-authorises`).
  Using a single relationship type + property lets us keep index
  storage small; the type property is indexed for range queries.
* `find_paths` uses Cypher variable-length shortest-path patterns with
  `allShortestPaths()` bounded by `max_length`. Cycle-free by
  construction.
* Auth reads from env: `NEO4J_URL`, `NEO4J_USER`, `NEO4J_PASSWORD`
  with docker-compose defaults.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from sentinel.memory.interface import MemoryError

logger = logging.getLogger(__name__)


def _url_from_env() -> str:
    return (
        os.getenv("SENTINEL_NEO4J_URL")
        or os.getenv("NEO4J_URL")
        or "bolt://localhost:7687"
    )


def _auth_from_env() -> tuple[str, str]:
    user = os.getenv("SENTINEL_NEO4J_USER") or os.getenv("NEO4J_USER") or "neo4j"
    pw = (
        os.getenv("SENTINEL_NEO4J_PASSWORD")
        or os.getenv("NEO4J_PASSWORD")
        or "sentineldev"
    )
    return user, pw


class Neo4jMemory:
    """Async Neo4j-backed graph store scoped by tenant.

    Tier-3 only. Compose with `PostgresMemory` and `QdrantMemory` via
    `CompositeMemory`.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        user: str | None = None,
        password: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        self._url = url or _url_from_env()
        env_user, env_pw = _auth_from_env()
        self._user = user or env_user
        self._password = password or env_pw
        self._tenant_id = tenant_id
        self._driver: Any = None

    # ---------- Lifecycle ----------

    async def connect(self) -> None:
        try:
            from neo4j import AsyncGraphDatabase  # type: ignore[import-not-found]
        except ImportError as e:
            raise MemoryError(
                "neo4j driver not installed. Run: poetry install"
            ) from e

        try:
            self._driver = AsyncGraphDatabase.driver(
                self._url, auth=(self._user, self._password),
            )
            await self._driver.verify_connectivity()
        except Exception as e:
            raise MemoryError(f"Neo4j connect failed at {self._url}: {e}") from e

        await self._ensure_constraints()
        logger.info("Neo4jMemory: connected to %s", self._url)

    async def close(self) -> None:
        if self._driver is not None:
            try:
                await self._driver.close()
            except Exception:
                logger.exception("Neo4j close failed")
            self._driver = None

    async def _ensure_constraints(self) -> None:
        async with self._driver.session() as session:
            await session.run(
                "CREATE CONSTRAINT finding_key IF NOT EXISTS "
                "FOR (n:Finding) REQUIRE (n.tenant_id, n.node_id) IS UNIQUE"
            )
            await session.run(
                "CREATE INDEX finding_session IF NOT EXISTS "
                "FOR (n:Finding) ON (n.tenant_id, n.session_id)"
            )
            await session.run(
                "CREATE INDEX relates_type IF NOT EXISTS "
                "FOR ()-[r:RELATES_TO]-() ON (r.type, r.tenant_id)"
            )

    # ---------- Tier 3 API ----------

    async def add_graph_node(
        self,
        session_id: str,
        node_id: str,
        node_type: str,
        attrs: dict[str, Any],
    ) -> None:
        self._require_driver()
        tenant_id = attrs.get("tenant_id") or self._tenant_id
        if not tenant_id:
            raise MemoryError("Neo4jMemory requires a tenant_id.")
        clean_attrs = {k: v for k, v in attrs.items() if k != "tenant_id"}
        async with self._driver.session() as session:
            await session.run(
                """
                MERGE (n:Finding {tenant_id: $tenant_id, node_id: $node_id})
                SET n.session_id = $session_id,
                    n.node_type  = $node_type,
                    n += $attrs
                """,
                tenant_id=tenant_id,
                node_id=node_id,
                session_id=session_id,
                node_type=node_type,
                attrs=clean_attrs,
            )

    async def add_graph_edge(
        self,
        session_id: str,
        src: str,
        dst: str,
        edge_type: str,
        attrs: dict[str, Any],
    ) -> None:
        self._require_driver()
        tenant_id = attrs.get("tenant_id") or self._tenant_id
        if not tenant_id:
            raise MemoryError("Neo4jMemory requires a tenant_id.")
        clean_attrs = {k: v for k, v in attrs.items() if k != "tenant_id"}
        async with self._driver.session() as session:
            await session.run(
                """
                MATCH (a:Finding {tenant_id: $tenant_id, node_id: $src})
                MATCH (b:Finding {tenant_id: $tenant_id, node_id: $dst})
                MERGE (a)-[r:RELATES_TO {tenant_id: $tenant_id, type: $edge_type}]->(b)
                SET r.session_id = $session_id,
                    r += $attrs
                """,
                tenant_id=tenant_id,
                src=src, dst=dst,
                edge_type=edge_type,
                session_id=session_id,
                attrs=clean_attrs,
            )

    async def find_paths(
        self,
        session_id: str,
        src: str,
        dst: str,
        max_length: int = 5,
        tenant_id: str | None = None,
    ) -> list[list[str]]:
        self._require_driver()
        tid = tenant_id or self._tenant_id
        if not tid:
            raise MemoryError("Neo4jMemory.find_paths requires a tenant_id.")
        # Cypher variable-length pattern; bounded to prevent runaway.
        cypher = (
            f"MATCH (a:Finding {{tenant_id: $tenant_id, node_id: $src}}), "
            f"      (b:Finding {{tenant_id: $tenant_id, node_id: $dst}}), "
            f"      p = allShortestPaths((a)-[:RELATES_TO*..{max_length}]-(b)) "
            f"RETURN [n IN nodes(p) | n.node_id] AS path"
        )
        async with self._driver.session() as session:
            result = await session.run(cypher, tenant_id=tid, src=src, dst=dst)
            paths: list[list[str]] = []
            async for record in result:
                paths.append(list(record["path"]))
        return paths

    # ---------- Health ----------

    async def health_check(self) -> bool:
        if self._driver is None:
            return False
        try:
            await self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def _require_driver(self) -> None:
        if self._driver is None:
            raise MemoryError(
                "Neo4jMemory not connected. Call await memory.connect() first."
            )
