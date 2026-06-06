"""HTML renderer for the VAPT report.

Single-file, self-contained HTML — embedded CSS, no external assets,
no JavaScript. The output is intended to be openable directly from
disk and printable via the browser's "Print to PDF" workflow without
any additional tooling.
"""
from __future__ import annotations

import html
import json
from typing import Iterable

from sentinel.agents.reporting.models import (
    FindingSection,
    ReferenceBlock,
    ReportData,
)
from sentinel.agents.reporting.templates.markdown import _clean_evidence
from sentinel.core.finding import Severity


_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


_CSS = """\
:root {
  --bg: #070A12;
  --surface: #0E1322;
  --surface-2: #141B2E;
  --border: #1F2940;
  --text: #E6EAF2;
  --text-dim: #9CA8C0;
  --accent-1: #7C3AED;
  --accent-2: #22D3EE;
  --sev-critical: #EF4444;
  --sev-high: #F97316;
  --sev-medium: #FBBF24;
  --sev-low: #3B82F6;
  --sev-info: #6B7280;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
}
.page { max-width: 960px; margin: 0 auto; padding: 48px 32px; }
header.hero {
  border-radius: 14px;
  padding: 32px;
  margin-bottom: 32px;
  background: linear-gradient(135deg, rgba(124,58,237,.15), rgba(34,211,238,.10));
  border: 1px solid var(--border);
}
header.hero h1 {
  margin: 0 0 8px 0;
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.01em;
}
header.hero .meta {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  color: var(--text-dim);
}
section { margin-bottom: 32px; }
section h2 {
  font-size: 20px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin-bottom: 16px;
}
.risk {
  display: flex; gap: 24px; align-items: center;
  padding: 16px; border-radius: 10px;
  background: var(--surface); border: 1px solid var(--border);
}
.risk .score {
  font-family: 'JetBrains Mono', monospace;
  font-size: 36px; font-weight: 700;
  background: linear-gradient(135deg, var(--accent-1), var(--accent-2));
  -webkit-background-clip: text; background-clip: text;
  color: transparent;
}
.risk .band {
  font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--text-dim);
}
.sev-table { width: 100%; border-collapse: collapse; margin-top: 12px; }
.sev-table th, .sev-table td {
  padding: 8px 12px; text-align: left;
  border-bottom: 1px solid var(--border);
}
.sev-table th { color: var(--text-dim); font-weight: 600; font-size: 12px;
  text-transform: uppercase; letter-spacing: 0.06em; }
.sev-table td.count { font-family: 'JetBrains Mono', monospace;
  text-align: right; }
.badge {
  display: inline-block;
  padding: 2px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em;
}
.badge.Critical { background: rgba(239,68,68,.15); color: var(--sev-critical); }
.badge.High { background: rgba(249,115,22,.15); color: var(--sev-high); }
.badge.Medium { background: rgba(251,191,36,.15); color: var(--sev-medium); }
.badge.Low { background: rgba(59,130,246,.15); color: var(--sev-low); }
.badge.Info { background: rgba(107,114,128,.15); color: var(--sev-info); }
.finding {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 16px;
}
.finding header.fhead {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 12px;
}
.finding h3 { margin: 0; font-size: 16px; }
.finding dl {
  display: grid; grid-template-columns: 130px 1fr; gap: 4px 16px;
  margin: 0 0 12px 0; font-size: 14px;
}
.finding dt { color: var(--text-dim); }
.finding dd { margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 13px; }
.finding .triage {
  border-left: 3px solid var(--accent-2);
  padding: 8px 12px;
  background: rgba(34,211,238,.05);
  font-style: italic;
  color: var(--text-dim);
  margin: 8px 0;
}
.finding .mapping {
  background: var(--surface-2);
  padding: 12px; border-radius: 8px;
  margin: 12px 0;
}
.finding .mapping h4 {
  margin: 0 0 8px 0; font-size: 12px;
  text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--text-dim);
}
.finding .mapping ul { margin: 0; padding-left: 20px; font-size: 13px; }
.finding pre {
  background: #0A0E1A;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  overflow-x: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  line-height: 1.5;
}
.finding .reco {
  margin-top: 12px;
  padding: 12px;
  border-radius: 8px;
  background: rgba(124,58,237,.08);
  border: 1px solid rgba(124,58,237,.25);
}
table.references { width: 100%; border-collapse: collapse; }
table.references th, table.references td {
  padding: 8px 12px; text-align: left;
  border-bottom: 1px solid var(--border); font-size: 13px;
}
table.references th { color: var(--text-dim); }
table.references td.cid { font-family: 'JetBrains Mono', monospace; }
footer {
  color: var(--text-dim); font-size: 12px;
  border-top: 1px solid var(--border); padding-top: 16px;
}
@media print {
  body { background: white; color: black; }
  .badge { border: 1px solid currentColor; }
  header.hero, .finding, .risk { background: white; border-color: #ccc; }
  .finding pre { background: #f5f5f5; border-color: #ddd; }
}
"""


def render_html(data: ReportData) -> str:
    """Render ``ReportData`` as a single self-contained HTML document."""
    parts: list[str] = []
    parts.append(_doc_head(data))
    parts.append('<body><div class="page">')
    parts.append(_hero(data))
    parts.append(_summary_section(data))
    parts.append(_findings_section(data))
    parts.append(_references_section(data.references))
    parts.append(_footer(data))
    parts.append("</div></body></html>")
    return "".join(parts)


# ---------- sections ----------


def _doc_head(data: ReportData) -> str:
    title = html.escape(f"VAPT Report — {data.package}")
    return (
        "<!doctype html><html lang='en'><head>"
        f"<meta charset='utf-8'><title>{title}</title>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<style>{_CSS}</style></head>"
    )


def _hero(data: ReportData) -> str:
    return (
        "<header class='hero'>"
        f"<h1>{html.escape(data.package)}</h1>"
        "<div class='meta'>"
        f"version {html.escape(data.version)} · "
        f"session {html.escape(data.session_id)} · "
        f"generated {data.generated_at.isoformat(timespec='seconds')}"
        "</div></header>"
    )


def _summary_section(data: ReportData) -> str:
    rows = "".join(
        f"<tr><td><span class='badge {sev}'>{sev}</span></td>"
        f"<td class='count'>{data.severity_counts.get(sev, 0)}</td></tr>"
        for sev in ("Critical", "High", "Medium", "Low", "Info")
    )
    band = html.escape(data.risk.band.upper())
    summary = html.escape(data.risk.summary)
    return (
        "<section><h2>Executive Summary</h2>"
        "<div class='risk'>"
        f"<div><div class='score'>{data.risk.score}</div>"
        f"<div class='band'>{band}</div></div>"
        f"<div>{summary}</div>"
        "</div>"
        "<table class='sev-table'>"
        "<thead><tr><th>Severity</th><th>Count</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</section>"
    )


def _findings_section(data: ReportData) -> str:
    if not data.sections:
        return "<section><h2>Findings</h2><p>No findings.</p></section>"
    parts = ["<section><h2>Findings</h2>"]
    for severity in (
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        Severity.LOW, Severity.INFO,
    ):
        bucket = data.by_severity(severity)
        if not bucket:
            continue
        parts.append(
            f"<h3>{_SEVERITY_LABEL[severity]} "
            f"<span class='badge {_SEVERITY_LABEL[severity]}'>"
            f"{len(bucket)}</span></h3>",
        )
        for s in bucket:
            parts.append(_finding_card(s))
    parts.append("</section>")
    return "".join(parts)


def _finding_card(section: FindingSection) -> str:
    f = section.finding
    sev_label = _SEVERITY_LABEL[f.severity]
    head = (
        "<header class='fhead'>"
        f"<h3>{html.escape(f.vuln_class)}</h3>"
        f"<span class='badge {sev_label}'>{sev_label}</span>"
        "</header>"
    )
    meta = (
        "<dl>"
        f"<dt>Agent</dt><dd>{html.escape(f.agent_id)}</dd>"
        f"<dt>Confidence</dt><dd>{f.confidence:.0%}</dd>"
        f"<dt>OWASP</dt><dd>{html.escape(f.owasp or '—')}</dd>"
        f"<dt>MASVS</dt><dd>{html.escape(f.masvs or '—')}</dd>"
        f"<dt>CVSS</dt><dd>{html.escape(f.cvss_vector or 'n/a')}</dd>"
        "</dl>"
    )
    triage = ""
    if section.triage_explanation:
        triage = (
            "<div class='triage'>"
            f"{html.escape(section.triage_explanation)}"
            "</div>"
        )
    mapping = ""
    if section.rag_mapping:
        items = "".join(
            f"<li><code>{html.escape(cid)}</code> — "
            f"{html.escape(title)}</li>"
            for cid, title in sorted(section.rag_mapping.items())
        )
        mapping = (
            "<div class='mapping'>"
            "<h4>Standards mapping (retrieved)</h4>"
            f"<ul>{items}</ul>"
            "</div>"
        )
    evidence = (
        "<pre>" + html.escape(
            json.dumps(_clean_evidence(f.evidence), indent=2, sort_keys=True),
        ) + "</pre>"
    )
    reco = (
        "<div class='reco'><strong>Recommendation:</strong><br>"
        f"{html.escape(f.recommendation)}</div>"
    )
    return (
        "<article class='finding'>"
        f"{head}{meta}{triage}{mapping}{evidence}{reco}"
        "</article>"
    )


def _references_section(refs: Iterable[ReferenceBlock]) -> str:
    refs = list(refs)
    if not refs:
        return ""
    rows = "".join(
        f"<tr><td>{html.escape(r.source)}</td>"
        f"<td class='cid'>{html.escape(r.control_id)}</td>"
        f"<td>{html.escape(r.title)}</td></tr>"
        for r in refs
    )
    return (
        "<section><h2>Standards Cited</h2>"
        "<table class='references'>"
        "<thead><tr><th>Source</th><th>Control</th><th>Title</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</section>"
    )


def _footer(data: ReportData) -> str:
    return (
        "<footer>"
        f"<div>APK SHA-256: <code>{html.escape(data.apk_sha256 or 'n/a')}</code></div>"
        "<div>Generated by SENTINEL v0.1.0 — confidential, "
        "for the engagement requester only.</div>"
        "</footer>"
    )
