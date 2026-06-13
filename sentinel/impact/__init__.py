"""Economic-impact scoring for findings (IMPACT_001)."""
from sentinel.impact.calculator import (
    EconomicCalculator,
    ImpactResult,
    attach_impact,
    default_calculator,
    score,
)

__all__ = [
    "EconomicCalculator",
    "ImpactResult",
    "attach_impact",
    "default_calculator",
    "score",
]
