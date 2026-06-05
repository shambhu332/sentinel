"""Correlation module — Phase 7 exploit chain detection."""
from sentinel.correlation.models import (
    CHAIN_PATTERNS,
    ChainFinding,
    ChainPattern,
    ChainType,
)

__all__ = ["ChainPattern", "ChainFinding", "ChainType", "CHAIN_PATTERNS"]
