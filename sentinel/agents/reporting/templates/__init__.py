"""Renderers for the VAPT report (markdown + HTML)."""
from sentinel.agents.reporting.templates.html import render_html
from sentinel.agents.reporting.templates.markdown import render_markdown

__all__ = ["render_html", "render_markdown"]
