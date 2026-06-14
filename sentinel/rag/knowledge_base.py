"""ChromaDB-backed knowledge base for SENTINEL's RAG layer.

The ``KnowledgeBase`` wraps a single ChromaDB collection. It is
deliberately decoupled from ``LightweightMemory`` (which stores
findings) so the RAG corpus can be rebuilt without touching scan
history and vice versa. They share the underlying
``chromadb.PersistentClient`` only by path convention.

The class supports two embedder paths:

* **Default** — ChromaDB's built-in embedder
  (``sentence-transformers/all-MiniLM-L6-v2``). Runs on CPU, no
  network call, no API key required.
* **In-memory test mode** — when the constructor is given
  ``persist_path=None`` the corpus lives in a transient
  ``EphemeralClient``. Unit tests use this; production paths set
  ``persist_path`` to ``<workspace>/data/rag``.

The class is lazily-initialized: importing the module is cheap, and
ChromaDB only loads when ``connect()`` is awaited. That keeps
``poetry run sentinel --help`` fast.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "sentinel_knowledge"


class KnowledgeBaseError(RuntimeError):
    """Raised when the knowledge base cannot satisfy a request."""


class KnowledgeBase:
    """Thin ChromaDB wrapper holding the RAG corpus.

    Instances are async-compatible only at the public API; ChromaDB
    itself is synchronous, so under the hood we just call into it
    directly. The async signatures exist for symmetry with the rest of
    SENTINEL's memory layer.
    """

    def __init__(self, persist_path: Path | None = None) -> None:
        self._persist_path = persist_path
        self._client: Any = None
        self._collection: Any = None

    # ---------- lifecycle ----------

    async def connect(self) -> None:
        """Open the ChromaDB collection.

        Idempotent — calling ``connect`` twice is a no-op after the
        first successful call.
        """
        if self._collection is not None:
            return
        try:
            import chromadb
        except ImportError as exc:  # pragma: no cover - dep is declared
            raise KnowledgeBaseError(
                "chromadb is required for the RAG knowledge base — "
                "install with `poetry install` and retry."
            ) from exc

        if self._persist_path is None:
            self._client = chromadb.EphemeralClient()
        else:
            self._persist_path.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=str(self._persist_path),
            )

        self._collection = self._client.get_or_create_collection(
            name=_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "KnowledgeBase connected (path=%s, count=%d)",
            self._persist_path or "<ephemeral>",
            self._collection.count(),
        )

    async def close(self) -> None:
        """Drop references to the underlying ChromaDB handles."""
        self._collection = None
        self._client = None

    # ---------- corpus management ----------

    async def upsert(
        self,
        ids: list[str],
        texts: list[str],
        metadatas: list[dict[str, Any]],
    ) -> None:
        """Insert or update a batch of passages.

        ``ids`` must be unique within the collection; passing an id
        that already exists overwrites the previous entry. We use
        ``upsert`` rather than ``add`` so ``sentinel rag build`` is
        safely re-runnable.
        """
        self._require_collection()
        if not (len(ids) == len(texts) == len(metadatas)):
            raise KnowledgeBaseError(
                "ids / texts / metadatas length mismatch",
            )
        if not ids:
            return
        self._collection.upsert(ids=ids, documents=texts, metadatas=metadatas)

    async def query(
        self,
        text: str,
        top_k: int = 4,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve the top-K passages by similarity to ``text``.

        Returns a list of dicts shaped:
            ``{"id": str, "document": str, "metadata": dict, "score": float}``

        Score is ``1 - distance`` so higher is better. If the
        collection is empty an empty list is returned; the caller is
        responsible for handling the "no knowledge available" case.
        """
        self._require_collection()
        if self._collection.count() == 0:
            return []
        kwargs: dict[str, Any] = {
            "query_texts": [text],
            "n_results": top_k,
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where
        result = self._collection.query(**kwargs)

        # Chroma returns parallel lists wrapped one extra layer because
        # we passed a single query. Flatten that here.
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]

        out: list[dict[str, Any]] = []
        for i, doc, meta, dist in zip(ids, docs, metas, dists, strict=False):
            out.append({
                "id": i,
                "document": doc,
                "metadata": meta or {},
                "score": max(0.0, 1.0 - float(dist)),
            })
        return out

    async def count(self) -> int:
        """Return the number of passages in the collection."""
        self._require_collection()
        return self._collection.count()

    async def clear(self) -> None:
        """Drop every passage. Used by ``sentinel rag build --rebuild``."""
        self._require_collection()
        if self._client is None:
            return
        try:
            self._client.delete_collection(_COLLECTION_NAME)
        except Exception:  # noqa: BLE001 - chroma raises an undocumented error
            pass
        self._collection = self._client.get_or_create_collection(
            name=_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    # ---------- internal ----------

    def _require_collection(self) -> None:
        if self._collection is None:
            raise KnowledgeBaseError(
                "KnowledgeBase not connected — call ``await kb.connect()``",
            )

    # ---------- helpers ----------

    @staticmethod
    def default_persist_path(workspace: Path) -> Path:
        """Return the canonical on-disk location for a given workspace."""
        return workspace / "data" / "rag"

    @staticmethod
    def chunk(records: Iterable[Any], size: int = 64) -> Iterable[list[Any]]:
        """Group an iterable into fixed-size batches for upsert calls."""
        batch: list[Any] = []
        for r in records:
            batch.append(r)
            if len(batch) >= size:
                yield batch
                batch = []
        if batch:
            yield batch
