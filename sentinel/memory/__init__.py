"""Memory bus — three-tier shared state for agents.

Backends:
    * `lightweight`   — SQLite + Chroma + NetworkX, single-process dev default
    * `postgres`      — Postgres T1 only (Phase 1.1).
    * `qdrant`        — Qdrant T2 only (Phase 1.2), local sentence-transformers.
    * `neo4j`         — Neo4j T3 only (Phase 1.2).
    * `composite`     — Full T1+T2+T3 stack (Postgres+Qdrant+Neo4j) with
                        per-tier graceful degrade to LightweightMemory when
                        the corresponding URL env var is unset.
    * `production`    — Legacy Redis Streams T1 backend; retained for callers
                        that need Redis fan-out. New code should prefer
                        `composite`.
"""
from typing import Any

from sentinel.memory.composite import CompositeMemory
from sentinel.memory.interface import MemoryError, MemoryInterface
from sentinel.memory.lightweight import LightweightMemory
from sentinel.memory.neo4j_backend import Neo4jMemory
from sentinel.memory.postgres import PostgresMemory
from sentinel.memory.production import ProductionMemory
from sentinel.memory.qdrant_backend import QdrantMemory


def create_memory(backend: str = "lightweight", **kwargs: Any) -> MemoryInterface:
    """Factory — returns the right backend based on config."""
    if backend == "lightweight":
        from pathlib import Path
        data_dir = kwargs.get("data_dir", Path("./data"))
        return LightweightMemory(data_dir=Path(data_dir))
    if backend == "postgres":
        return PostgresMemory(**kwargs)
    if backend == "composite":
        return CompositeMemory.from_env(**kwargs)
    if backend == "production":
        return ProductionMemory(**kwargs)
    raise ValueError(f"Unknown memory backend: {backend}")


__all__ = [
    "CompositeMemory",
    "LightweightMemory",
    "MemoryError",
    "MemoryInterface",
    "Neo4jMemory",
    "PostgresMemory",
    "ProductionMemory",
    "QdrantMemory",
    "create_memory",
]
