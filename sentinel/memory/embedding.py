"""Local embedding provider for Tier-2 semantic search.

**We never send code snippets to a cloud LLM for embeddings.** The
provider loads `sentence-transformers/all-MiniLM-L6-v2` once per
process (~90 MB CPU model, 384-d output) and reuses it. If the model
weights aren't cached, first call downloads them; subsequent calls
are millisecond-latency CPU inference.

For CI / test runs without the model available, `NullEmbedder` returns
a deterministic sha256-derived pseudo-embedding so tests can exercise
Qdrant round-trip logic without pulling ~90 MB of weights.
"""
from __future__ import annotations

import hashlib
import logging
import os
import struct
from typing import Protocol

logger = logging.getLogger(__name__)


class Embedder(Protocol):
    """Structural type — anything with `encode` and `dim` is an embedder."""

    dim: int

    def encode(self, texts: list[str]) -> list[list[float]]: ...


class SentenceTransformerEmbedder:
    """Wraps sentence-transformers/all-MiniLM-L6-v2 (384-d)."""

    dim: int = 384

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ) -> None:
        self._model_name = model_name
        self._model: object | None = None

    def _lazy_load(self) -> object:
        if self._model is None:
            try:
                # Import inline — sentence-transformers is optional at import
                # time so unit tests / --private paths can run without it.
                from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]
            except ImportError as e:
                raise RuntimeError(
                    "sentence-transformers not installed; run `poetry install`"
                ) from e
            self._model = SentenceTransformer(self._model_name)
        return self._model

    def encode(self, texts: list[str]) -> list[list[float]]:
        model = self._lazy_load()
        # normalize=True → cosine similarity via dot-product.
        vecs = model.encode(  # type: ignore[attr-defined]
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return [list(map(float, v)) for v in vecs]


class NullEmbedder:
    """Deterministic hash-based pseudo-embedding for tests / offline runs.

    Not semantically meaningful. Enables Qdrant integration tests to
    round-trip without pulling ~90 MB of model weights.
    """

    dim: int = 32

    def encode(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for t in texts:
            h = hashlib.sha256(t.encode("utf-8")).digest()
            # 32 bytes → 8 float32 values → repeat to reach `dim`.
            floats = list(struct.unpack("8f", h))
            vec = (floats * ((self.dim // len(floats)) + 1))[: self.dim]
            # L2 normalize so cosine == dot-product.
            norm = sum(x * x for x in vec) ** 0.5 or 1.0
            out.append([x / norm for x in vec])
        return out


def get_default_embedder() -> Embedder:
    """Factory — env-overridable so tests can force `NullEmbedder`."""
    if os.getenv("SENTINEL_EMBEDDER") == "null":
        logger.info("Using NullEmbedder (SENTINEL_EMBEDDER=null)")
        return NullEmbedder()
    return SentenceTransformerEmbedder()
