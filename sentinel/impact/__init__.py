"""Economic-impact scoring for findings (IMPACT_001)."""
from sentinel.impact.calculator import (
    EconomicCalculator,
    ImpactResult,
    attach_impact,
    default_calculator,
    extract_hvt_endpoints_from_strings_xml,
    score,
)

__all__ = [
    "EconomicCalculator",
    "ImpactResult",
    "attach_impact",
    "default_calculator",
    "extract_hvt_endpoints_from_strings_xml",
    "score",
]
