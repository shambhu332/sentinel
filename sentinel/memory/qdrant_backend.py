"""QdrantMemory — Tier-2 semantic search backend.

Phase 1.2 of the production-hardening plan.

Design notes:

* One collection per tenant, named `sentinel_{tenant_id}`. `session_id`
  lives in each point's payload so we can filter within a collection
  without proliferating collections. Cross-tenant search is impossible
  by construction — collections are the isolation boundary.
* Embeddings come from `sentinel.memory.embedding.get_default_embedder`
  (default: `sentence-transformers/all-MiniLM-L6-v2`, 384-d). No cloud
  calls for embeddings — enforces the "code never leaves the machine"
  promise.
* When `SENTINEL_EMBEDDER=null` we use a hash-derived pseudo-embedding
  so tests / offline flows exercise Qdrant round-trip without pulling
  ~90 MB of weights.
* No transactional guarantees across collections. Qdrant is a search
  index, not a source of truth; Postgres (T1) owns the finding record.
"""
from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from sentinel.memory.embedding import Embedder, get_default_embedder
from sentinel.memory.interface import MemoryError

logger = logging.getLogger(__name__)


def _url_from_env() -> str:
    return (
        os.getenv("SENTINEL_QDRANT_URL")
        or os.getenv("QDRANT_URL")
        or "http://localhost:6333"
    )


class QdrantMemory:
    """Async Qdrant-backed vector store scoped by tenant.

    Tier-2 only. Compose with `PostgresMemory` (T1) and `Neo4jMemory`
    (T3) via `CompositeMemory` for a full stack.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        tenant_id: str | None = None,
        embedder: Embedder | None = None,
    ) -> None:
        self._url = url or _url_from_env()
        self._tenant_id = tenant_id
        self._embedder: Embedder | None = embedder
        self._client: Any = None

    # ---------- Lifecycle ----------

    async def connect(self) -> None:
        try:
            from qdrant_client import AsyncQdrantClient  # type: ignore[import-not-found]
        except ImportError as e:
            raise MemoryError(
                "qdrant-client not installed. Run: poetry install"
            ) from e

        try:
            self._client = AsyncQdrantClient(url=self._url)
            # First call opens the connection lazily; force a probe.
            await self._client.get_collections()
        except Exception as e:
            raise MemoryError(f"Qdrant connect failed at {self._url}: {e}") from e

        if self._embedder is None:
            self._embedder = get_default_embedder()
        logger.info("QdrantMemory: connected to %s", self._url)

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                logger.exception("Qdrant close failed")
            self._client = None

    # ---------- Collection management ----------

    def _collection_name(self, tenant_id: str | None = None) -> str:
        tid = tenant_id or self._tenant_id
        if not tid:
            raise MemoryError(
                "QdrantMemory requires a tenant_id (constructor or per-call)."
            )
        # Collections are the tenant isolation boundary. Slug the UUID
        # to survive Qdrant's naming constraints.
        safe = tid.replace("-", "").lower()
        return f"sentinel_{safe}"

    async def _ensure_collection(self, tenant_id: str | None) -> str:
        from qdrant_client.http import models as qm  # type: ignore[import-not-found]

        assert self._client is not None and self._embedder is not None
        name = self._collection_name(tenant_id)
        try:
            existing = await self._client.get_collections()
            names = {c.name for c in existing.collections}
        except Exception as e:
            raise MemoryError(f"Qdrant list collections failed: {e}") from e
        if name not in names:
            await self._client.create_collection(
                collection_name=name,
                vectors_config=qm.VectorParams(
                    size=self._embedder.dim,
                    distance=qm.Distance.COSINE,
                ),
            )
        return name

    # ---------- Tier 2 API ----------

    async def add_embedding(
        self,
        session_id: str,
        finding_id: str,
        text: str,
        metadata: dict[str, Any],
    ) -> None:
        self._require_client()
        tenant_id = metadata.get("tenant_id") or self._tenant_id
        collection = await self._ensure_collection(tenant_id)
        assert self._embedder is not None
        [vec] = self._embedder.encode([text])
        from qdrant_client.http import models as qm

        # UUIDv5 the finding_id so re-adds are idempotent.
        point_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{session_id}:{finding_id}"))
        payload = {
            "session_id": session_id,
            "finding_id": finding_id,
            "text": text[:2000],
            **{k: v for k, v in metadata.items() if k != "tenant_id"},
        }
        try:
            await self._client.upsert(
                collection_name=collection,
                points=[qm.PointStruct(id=point_id, vector=vec, payload=payload)],
            )
        except Exception as e:
            raise MemoryError(f"Qdrant upsert failed: {e}") from e

    async def search_similar(
        self,
        query_text: str,
        session_id: str | None = None,
        limit: int = 10,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self._require_client()
        assert self._embedder is not None
        collection = self._collection_name(tenant_id)
        [vec] = self._embedder.encode([query_text])
        from qdrant_client.http import models as qm

        flt: Any = None
        if session_id is not None:
            flt = qm.Filter(
                must=[qm.FieldCondition(
                    key="session_id",
                    match=qm.MatchValue(value=session_id),
                )]
            )
        try:
            hits = await self._client.search(
                collection_name=collection,
                query_vector=vec,
                limit=limit,
                query_filter=flt,
            )
        except Exception as e:
            raise MemoryError(f"Qdrant search failed: {e}") from e

        return [
            {
                "finding_id": h.payload.get("finding_id"),
                "session_id": h.payload.get("session_id"),
                "score": float(h.score),
                "text": h.payload.get("text"),
                "metadata": {k: v for k, v in h.payload.items()
                             if k not in {"finding_id", "session_id", "text"}},
            }
            for h in hits
        ]

    # ---------- Health ----------

    async def health_check(self) -> bool:
        if self._client is None:
            return False
        try:
            await self._client.get_collections()
            return True
        except Exception:
            return False

    def _require_client(self) -> None:
        if self._client is None:
            raise MemoryError(
                "QdrantMemory not connected. Call await memory.connect() first."
            )
