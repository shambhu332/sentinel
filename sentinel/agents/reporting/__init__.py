"""Reporting agents — generate professional VAPT reports."""
from __future__ import annotations

__all__ = ["ReportGeneratorAgent"]

try:
    from .r001_report_agent import ReportGeneratorAgent
except ImportError:
    pass
