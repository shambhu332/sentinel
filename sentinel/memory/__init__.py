"""Memory bus — three-tier shared state for agents."""
from sentinel.memory.interface import MemoryError, MemoryInterface
from sentinel.memory.lightweight import LightweightMemory
from sentinel.memory.production import ProductionMemory


def create_memory(backend: str = "lightweight", **kwargs) -> MemoryInterface:
    """Factory — returns the right backend based on config."""
    if backend == "lightweight":
        from pathlib import Path
        data_dir = kwargs.get("data_dir", Path("./data"))
        return LightweightMemory(data_dir=Path(data_dir))
    if backend == "production":
        return ProductionMemory(**kwargs)
    raise ValueError(f"Unknown memory backend: {backend}")


__all__ = [
    "LightweightMemory",
    "MemoryError",
    "MemoryInterface",
    "ProductionMemory",
    "create_memory",
]
