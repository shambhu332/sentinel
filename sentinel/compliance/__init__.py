"""Compliance citation mapping.

Loads the curated YAML and exposes `cite(finding) -> list[Citation]`
for downstream report renderers. Stateless and import-cheap.
"""
from sentinel.compliance.mapper import (
    Citation,
    ComplianceMapper,
    cite,
    default_mapper,
)

__all__ = ["Citation", "ComplianceMapper", "cite", "default_mapper"]
