"""ProductionMemory — multi-process backend for SaaS deployment.

Tier 1 (events + findings): **Redis Streams + Hashes** — implemented.
Tier 2 (semantic search):   Qdrant / pgvector — not implemented (TODO).
Tier 3 (graph):             Neo4j / pgvector + recursive CTE — not implemented (TODO).

The Tier 1 implementation is real and ready to back the orchestrator
event bus today. Tier 2/3 raise `NotImplementedError` rather than
silently no-oping — agents that need them must run against
LightweightMemory or wait for the Sprint 11 wiring.

Key design choices for Tier 1:

* **Events** go to a Redis Stream `sentinel:events:{session_id}`. Streams
  give us replayable, ordered, fan-out-friendly delivery with built-in
  XPENDING / consumer-group semantics — exactly what the orchestrator's
  "agent.started / finding.emitted / phase.completed" wire needs.
* **Findings** go to a Redis Hash `sentinel:findings:{session_id}` keyed
  by `finding_id`, with the serialised JSON as the value. Idempotent
  by finding_id (HSET overwrites). A parallel Set
  `sentinel:findings:{session_id}:ids` keeps insertion order cheap.
* **No Lua / no transactions.** Every operation is one HSET, one XADD,
  or one XREAD. Keeps the implementation auditable and avoids the
  Redis-Lua-version hell when the runtime is Elasticache vs. Upstash
  vs. self-hosted.
* **Connection lifecycle:** `connect()` pings the server fail-fast;
  `close()` runs the redis-py async close cleanly. No silent
  reconnection — failures bubble up so the scheduler can retry
  with backoff.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sentinel.core.finding import Finding, Severity
from sentinel.memory.interface import MemoryError, MemoryInterface

logger = logging.getLogger(__name__)

# Redis key prefixes — single source of truth so renames stay grep-able
_K_EVENTS = "sentinel:events"          # stream per session
_K_FINDINGS = "sentinel:findings"      # hash per session, field=finding_id
_K_FINDING_ORDER = "sentinel:findings.order"  # list per session

# Stream cap — keep the last N events per session so a long-running
# pentest doesn't fill memory. XADD with MAXLEN ~ N approximate trim.
_STREAM_MAXLEN = 10_000

# Severity rank for `min_severity` filter
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ProductionMemory(MemoryInterface):
    """Redis-backed multi-process memory for the SaaS deployment.

    Tier 2/3 are explicit `NotImplementedError`s rather than silent
    no-ops. Callers that need semantic search or graph paths should
    run against `LightweightMemory` until the production Qdrant /
    Neo4j wiring lands.
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

    # ---------- Lifecycle ----------

    async def connect(self) -> None:
        try:
            import redis.asyncio as redis_async
        except ImportError as e:
            raise MemoryError(
                "redis package not installed. Install with: "
                "pip install 'sentinel[production]' (or: pip install redis>=5)"
            ) from e

        self._redis = redis_async.from_url(
            self._redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        try:
            pong = await self._redis.ping()
        except Exception as e:  # noqa: BLE001 - want to wrap any redis error
            raise MemoryError(
                f"Redis ping failed at {self._redis_url}: {e}"
            ) from e
        if pong is not True:
            raise MemoryError(f"Unexpected Redis ping response: {pong!r}")
        logger.info("ProductionMemory: connected to Redis at %s", self._redis_url)

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:  # noqa: BLE001
                logger.exception("Redis close failed")
            self._redis = None

    # ---------- Tier 1: Events (Redis Streams) ----------

    async def publish_event(
        self, session_id: str, event_type: str, payload: dict[str, Any],
    ) -> None:
        self._require_redis()
        stream_key = f"{_K_EVENTS}:{session_id}"
        # XADD field/value: keep all primitive fields top-level for cheap
        # XREAD parsing; payload itself goes in as JSON in one field.
        fields = {
            "event_type": event_type,
            "ts": datetime.now(timezone.utc).isoformat(),
            "payload": json.dumps(payload, default=str),
        }
        try:
            await self._redis.xadd(
                stream_key, fields,
                maxlen=_STREAM_MAXLEN, approximate=True,
            )
        except Exception as e:  # noqa: BLE001
            raise MemoryError(f"XADD failed for {stream_key}: {e}") from e

    async def poll_events(
        self,
        session_id: str,
        since: datetime | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        self._require_redis()
        stream_key = f"{_K_EVENTS}:{session_id}"
        # Stream IDs in redis are millisecond-prefixed, so we can use
        # the `since` epoch-ms directly as the read marker.
        if since is None:
            start_id = "0"
        else:
            start_id = f"{int(since.timestamp() * 1000)}-0"
        try:
            raw = await self._redis.xrange(stream_key, min=start_id, max="+")
        except Exception as e:  # noqa: BLE001
            raise MemoryError(f"XRANGE failed for {stream_key}: {e}") from e

        out: list[dict[str, Any]] = []
        for stream_id, fields in raw:
            etype = fields.get("event_type", "")
            if event_type is not None and etype != event_type:
                continue
            payload_raw = fields.get("payload", "{}")
            try:
                payload = json.loads(payload_raw)
            except json.JSONDecodeError:
                payload = {"_raw": payload_raw}
            out.append({
                "stream_id": stream_id,
                "event_type": etype,
                "ts": fields.get("ts"),
                "payload": payload,
            })
        return out

    # ---------- Tier 1: Findings (Redis Hash + List) ----------

    async def save_finding(self, finding: Finding) -> None:
        self._require_redis()
        sid = finding.session_id
        fid = finding.finding_id
        hash_key = f"{_K_FINDINGS}:{sid}"
        order_key = f"{_K_FINDING_ORDER}:{sid}"

        # Pydantic v2 .model_dump_json keeps the same envelope agents
        # already speak everywhere else in the stack.
        try:
            body = finding.model_dump_json()
        except Exception as e:  # noqa: BLE001
            raise MemoryError(f"Finding serialisation failed: {e}") from e

        # HSET is idempotent: re-saving the same finding_id overwrites
        # the body without altering insertion order. LPUSH+SADD pattern
        # is overkill — a list with RPUSH is fine, dedup is the hash.
        try:
            pipe = self._redis.pipeline(transaction=False)
            pipe.hset(hash_key, fid, body)
            pipe.rpush(order_key, fid)
            await pipe.execute()
        except Exception as e:  # noqa: BLE001
            raise MemoryError(f"save_finding failed for {fid}: {e}") from e

    async def get_findings(
        self, session_id: str, min_severity: str | None = None,
    ) -> list[Finding]:
        self._require_redis()
        hash_key = f"{_K_FINDINGS}:{session_id}"
        order_key = f"{_K_FINDING_ORDER}:{session_id}"

        try:
            order = await self._redis.lrange(order_key, 0, -1)
            if not order:
                return []
            # Dedupe order list (rpush may have repeated same fid on overwrite)
            seen: set[str] = set()
            unique_order = [x for x in order if not (x in seen or seen.add(x))]
            bodies = await self._redis.hmget(hash_key, unique_order)
        except Exception as e:  # noqa: BLE001
            raise MemoryError(f"get_findings failed: {e}") from e

        floor = _SEVERITY_RANK.get(Severity(min_severity)) if min_severity else None
        out: list[Finding] = []
        for body in bodies:
            if body is None:
                continue
            try:
                f = Finding.model_validate_json(body)
            except Exception:  # noqa: BLE001
                logger.warning("Skipping unparseable finding body")
                continue
            if floor is not None and _SEVERITY_RANK[f.severity] < floor:
                continue
            out.append(f)
        return out

    async def get_finding(
        self, session_id: str, finding_id: str,
    ) -> Finding | None:
        self._require_redis()
        hash_key = f"{_K_FINDINGS}:{session_id}"
        try:
            body = await self._redis.hget(hash_key, finding_id)
        except Exception as e:  # noqa: BLE001
            raise MemoryError(f"get_finding failed: {e}") from e
        if body is None:
            return None
        try:
            return Finding.model_validate_json(body)
        except Exception:  # noqa: BLE001
            return None

    # ---------- Tier 2 / Tier 3 — not yet implemented ----------

    async def add_embedding(
        self, session_id: str, finding_id: str, text: str, metadata: dict[str, Any],
    ) -> None:
        raise NotImplementedError(
            "Tier 2 (Qdrant / pgvector) not yet implemented — "
            "use LightweightMemory for semantic search."
        )

    async def search_similar(
        self, query_text: str, session_id: str | None = None, limit: int = 10,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError(
            "Tier 2 (Qdrant / pgvector) not yet implemented — "
            "use LightweightMemory for semantic search."
        )

    async def add_graph_node(
        self, session_id: str, node_id: str, node_type: str, attrs: dict[str, Any],
    ) -> None:
        raise NotImplementedError(
            "Tier 3 (Neo4j) not yet implemented — "
            "use LightweightMemory for graph operations."
        )

    async def add_graph_edge(
        self, session_id: str, src: str, dst: str, edge_type: str, attrs: dict[str, Any],
    ) -> None:
        raise NotImplementedError(
            "Tier 3 (Neo4j) not yet implemented — "
            "use LightweightMemory for graph operations."
        )

    async def find_paths(
        self, session_id: str, src: str, dst: str, max_length: int = 5,
    ) -> list[list[str]]:
        raise NotImplementedError(
            "Tier 3 (Neo4j) not yet implemented — "
            "use LightweightMemory for graph operations."
        )

    # ---------- Health ----------

    async def health_check(self) -> dict[str, bool]:
        tier1 = False
        if self._redis is not None:
            try:
                tier1 = await self._redis.ping() is True
            except Exception:  # noqa: BLE001
                tier1 = False
        return {"tier1": tier1, "tier2": False, "tier3": False}

    # ---------- Helpers ----------

    def _require_redis(self) -> None:
        if self._redis is None:
            raise MemoryError(
                "ProductionMemory not connected. Call await memory.connect() first."
            )
