"""Unit tests for Phase 1.2 memory tier additions (no server needed)."""
from __future__ import annotations

import pytest

from sentinel.memory import (
    CompositeMemory,
    LightweightMemory,
    Neo4jMemory,
    PostgresMemory,
    QdrantMemory,
    create_memory,
)
from sentinel.memory.embedding import NullEmbedder, get_default_embedder
from sentinel.memory.interface import MemoryError


class TestEmbedding:
    def test_null_embedder_dim_and_shape(self):
        e = NullEmbedder()
        vecs = e.encode(["hello", "world"])
        assert len(vecs) == 2
        assert all(len(v) == e.dim for v in vecs)

    def test_null_embedder_is_deterministic(self):
        e = NullEmbedder()
        assert e.encode(["same"]) == e.encode(["same"])

    def test_null_embedder_l2_normalized(self):
        e = NullEmbedder()
        [v] = e.encode(["a"])
        norm = sum(x * x for x in v) ** 0.5
        assert 0.99 < norm < 1.01

    def test_env_forces_null(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_EMBEDDER", "null")
        assert isinstance(get_default_embedder(), NullEmbedder)


class TestBackendImports:
    def test_qdrant_import(self):
        q = QdrantMemory(url="http://localhost:6333", tenant_id="t")
        assert q is not None

    def test_neo4j_import(self):
        n = Neo4jMemory(url="bolt://localhost:7687", tenant_id="t")
        assert n is not None

    def test_qdrant_operations_before_connect_raise(self):
        q = QdrantMemory(tenant_id="t")
        with pytest.raises(MemoryError, match="not connected"):
            # Sync call to _require_client is fine — it's not async.
            q._require_client()

    def test_neo4j_operations_before_connect_raise(self):
        n = Neo4jMemory(tenant_id="t")
        with pytest.raises(MemoryError, match="not connected"):
            n._require_driver()

    def test_qdrant_requires_tenant(self):
        q = QdrantMemory()
        with pytest.raises(MemoryError, match="tenant_id"):
            q._collection_name(None)


class TestCompositeFallback:
    """CompositeMemory.from_env falls back to LightweightMemory when
    any of the URL env vars are unset."""

    def test_all_env_unset_falls_back_to_lightweight(self, monkeypatch, tmp_path):
        for var in [
            "SENTINEL_POSTGRES_URL", "POSTGRES_URL",
            "SENTINEL_QDRANT_URL",   "QDRANT_URL",
            "SENTINEL_NEO4J_URL",    "NEO4J_URL",
        ]:
            monkeypatch.delenv(var, raising=False)

        m = CompositeMemory.from_env(tenant_id="t1", data_dir=tmp_path)
        # All three tiers share the same LightweightMemory fallback.
        assert isinstance(m._t1, LightweightMemory)
        assert m._t1 is m._t2
        assert m._t1 is m._t3

    def test_only_postgres_configured(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINEL_POSTGRES_URL",
                           "postgresql://u:p@localhost:5432/sentinel")
        for var in ["QDRANT_URL", "SENTINEL_QDRANT_URL",
                    "NEO4J_URL", "SENTINEL_NEO4J_URL"]:
            monkeypatch.delenv(var, raising=False)

        m = CompositeMemory.from_env(tenant_id="t1", data_dir=tmp_path)
        assert isinstance(m._t1, PostgresMemory)
        assert isinstance(m._t2, LightweightMemory)
        assert isinstance(m._t3, LightweightMemory)


class TestFactory:
    def test_factory_creates_composite(self, monkeypatch, tmp_path):
        for var in [
            "SENTINEL_POSTGRES_URL", "POSTGRES_URL",
            "SENTINEL_QDRANT_URL",   "QDRANT_URL",
            "SENTINEL_NEO4J_URL",    "NEO4J_URL",
        ]:
            monkeypatch.delenv(var, raising=False)
        m = create_memory(
            "composite",
            tenant_id="t1",
            data_dir=tmp_path,
        )
        assert isinstance(m, CompositeMemory)
