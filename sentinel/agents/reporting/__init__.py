"""Reporting agents — generate professional VAPT reports."""
from __future__ import annotations

from sentinel.agents.reporting.builder import build_coverage, build_report_data
from sentinel.agents.reporting.models import (
    FindingSection,
    ReferenceBlock,
    ReportData,
    RiskScore,
)
from sentinel.agents.reporting.r001_report_agent import ReportGeneratorAgent
from sentinel.agents.reporting.templates import render_html, render_markdown

__all__ = [
    "FindingSection",
    "ReferenceBlock",
    "ReportData",
    "ReportGeneratorAgent",
    "RiskScore",
    "build_coverage",
    "build_report_data",
    "render_html",
    "render_markdown",
]
