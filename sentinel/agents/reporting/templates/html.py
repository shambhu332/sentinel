"""HTML renderer for the VAPT report — advisory-style.

Each finding is rendered as its own numbered advisory (F1, F2, …)
inside one bound document so it reads like a Bishop-Fox / NCC bundle:

    Cover page
    Table of Contents
    F1 / F2 / … advisories, each with the canonical sections
        1 Summary
        2 Affected Components
        3 Evidence in the APK
        4 Steps to Reproduce
        5 Proof of Concept
        6 Impact
        7 Suggested Fix
        8 References
    Appendix

Page headers and footers (CSS @page) carry the engagement name and a
``CONFIDENTIAL`` marker on every page. The whole document is a single
self-contained HTML file — no external assets — ready for
``Print → Save as PDF``.

Prose lives on ``FindingSection.narrative`` (populated by
``sentinel.agents.reporting.enrich``). When the narrative dict is
absent the template degrades gracefully to evidence-only output.
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
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

_SEVERITY_ORDER = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    Severity.LOW, Severity.INFO,
)


_CSS = """\
@page {
  size: A4;
  margin: 22mm 18mm 22mm 18mm;
  @top-left {
    content: "CONFIDENTIAL";
    font-family: 'EB Garamond', Georgia, serif;
    font-size: 9pt;
    letter-spacing: 0.18em;
    color: #6B7280;
  }
  @top-right {
    content: string(doc-target);
    font-family: 'EB Garamond', Georgia, serif;
    font-size: 9pt;
    letter-spacing: 0.06em;
    color: #6B7280;
  }
  @bottom-center {
    content: "Page " counter(page) " of " counter(pages);
    font-family: 'EB Garamond', Georgia, serif;
    font-size: 9pt;
    color: #6B7280;
  }
}
:root {
  --ink: #0E1320;
  --ink-soft: #2C3650;
  --ink-dim: #6B7280;
  --rule: #C7CDDB;
  --rule-soft: #E5E7EB;
  --brand: #0B1B3F;
  --brand-2: #B91C1C;
  --sev-critical: #B91C1C;
  --sev-high: #C2410C;
  --sev-medium: #B45309;
  --sev-low: #1D4ED8;
  --sev-info: #475569;
  --paper: #FFFFFF;
  --code-bg: #F6F2EA;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: 'EB Garamond', 'Source Serif Pro', Georgia, 'Times New Roman', serif;
  font-size: 11.5pt;
  line-height: 1.55;
  string-set: doc-target attr(data-empty);
}
.doc { max-width: 800px; margin: 0 auto; padding: 32px 28px; }
h1, h2, h3, h4, h5 {
  font-family: 'EB Garamond', Georgia, serif;
  color: var(--ink);
  font-weight: 700;
  letter-spacing: -0.005em;
}
p { margin: 0 0 10px 0; text-align: justify; }
code, pre, .mono {
  font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
}

/* ---------------- Cover page ---------------- */
.cover {
  string-set: doc-target attr(data-target);
  min-height: 95vh;
  padding: 32px 36px;
  display: flex; flex-direction: column;
  justify-content: space-between;
  border: 2px solid var(--brand);
  page-break-after: always;
}
.cover-banner {
  border-bottom: 2px solid var(--brand);
  padding-bottom: 16px;
  display: flex; align-items: center; justify-content: space-between;
}
.cover-banner .left {
  display: flex; align-items: center; gap: 14px;
}
.cover-banner .shield { width: 36px; height: 36px; }
.cover-banner .wordmark {
  font-size: 14pt; font-weight: 700;
  letter-spacing: 0.20em;
  color: var(--brand);
}
.cover-banner .classification {
  font-family: 'EB Garamond', Georgia, serif;
  font-size: 10pt; font-weight: 700;
  letter-spacing: 0.20em;
  color: var(--brand-2);
}
.cover-title {
  text-align: center;
  margin-top: 14vh;
}
.cover-title .eyebrow {
  font-size: 10pt; font-weight: 600;
  letter-spacing: 0.30em; text-transform: uppercase;
  color: var(--ink-dim);
  margin-bottom: 18px;
}
.cover-title h1 {
  font-size: 30pt; font-weight: 700;
  margin: 0 0 8px 0;
  line-height: 1.15;
}
.cover-title h2 {
  font-size: 17pt; font-weight: 500;
  margin: 0; color: var(--ink-soft);
  font-style: italic;
}
.cover-meta {
  border-top: 1px solid var(--rule);
  padding-top: 18px;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px 28px;
  font-size: 11pt;
}
.cover-meta .row {
  display: flex; justify-content: space-between;
  border-bottom: 1px dotted var(--rule);
  padding: 6px 0;
}
.cover-meta .key {
  color: var(--ink-dim);
  letter-spacing: 0.08em; text-transform: uppercase;
  font-size: 9.5pt;
}
.cover-meta .val {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10pt;
  color: var(--ink);
}

/* ---------------- Table of contents ---------------- */
.toc {
  page-break-after: always;
}
.toc h2 {
  font-size: 22pt;
  border-bottom: 1px solid var(--rule);
  padding-bottom: 8px;
  margin-bottom: 16px;
}
.toc ul {
  list-style: none; padding: 0; margin: 0;
}
.toc li {
  display: flex; justify-content: space-between;
  align-items: baseline;
  padding: 6px 0;
  font-size: 12pt;
  border-bottom: 1px dotted var(--rule-soft);
}
.toc li .lbl { flex: 1; }
.toc li .num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5pt;
  color: var(--ink-dim);
}
.toc .grp-title {
  margin-top: 14px;
  margin-bottom: 6px;
  font-size: 10pt; font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--brand);
}

/* ---------------- Advisory ---------------- */
.advisory {
  page-break-before: always;
  page-break-inside: auto;
  padding-top: 4px;
}
.advisory .masthead {
  border: 2px solid var(--brand);
  padding: 20px 22px 18px;
  margin-bottom: 22px;
}
.advisory .masthead .head-row {
  display: flex; justify-content: space-between;
  align-items: flex-start;
  border-bottom: 1px solid var(--rule);
  padding-bottom: 12px; margin-bottom: 12px;
}
.advisory .masthead .head-row .left {
  display: flex; align-items: center; gap: 16px;
}
.advisory .masthead .head-row .findingId {
  display: inline-block;
  background: var(--brand);
  color: white;
  padding: 6px 14px;
  font-size: 16pt; font-weight: 700;
  letter-spacing: 0.04em;
  font-family: 'JetBrains Mono', monospace;
}
.advisory .masthead .head-row .label {
  font-size: 9pt; font-weight: 600;
  letter-spacing: 0.24em; color: var(--ink-dim);
  text-transform: uppercase;
}
.advisory .masthead .head-row .classification {
  font-size: 9pt; font-weight: 700;
  letter-spacing: 0.22em;
  color: var(--brand-2);
  text-transform: uppercase;
}
.advisory .masthead h1 {
  font-size: 19pt;
  line-height: 1.25;
  margin: 0 0 14px 0;
}
.advisory .masthead .meta-grid {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 4px 18px;
  font-size: 10.5pt;
}
.advisory .masthead .meta-grid dt {
  color: var(--ink-dim);
  font-weight: 600;
  font-size: 9.5pt;
  letter-spacing: 0.04em;
}
.advisory .masthead .meta-grid dd {
  margin: 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10pt;
  word-break: break-word;
}
.sev-chip {
  display: inline-block;
  padding: 2px 9px;
  font-family: 'EB Garamond', Georgia, serif;
  font-size: 10pt; font-weight: 700;
  letter-spacing: 0.16em;
  color: white;
}
.sev-chip.CRITICAL { background: var(--sev-critical); }
.sev-chip.HIGH     { background: var(--sev-high); }
.sev-chip.MEDIUM   { background: var(--sev-medium); }
.sev-chip.LOW      { background: var(--sev-low); }
.sev-chip.INFO     { background: var(--sev-info); }

.advisory .sec {
  margin: 18px 0 14px 0;
  page-break-inside: avoid;
}
.advisory .sec > h2 {
  font-size: 14pt;
  font-weight: 700;
  margin: 0 0 8px 0;
  letter-spacing: 0.005em;
}
.advisory .sec > h2 .nm {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11pt;
  color: var(--ink-dim);
  margin-right: 6px;
}
.advisory .sec > h3 {
  font-size: 12pt;
  font-weight: 700;
  margin: 12px 0 6px 0;
}
.advisory .sec > h3 .nm {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5pt;
  color: var(--ink-dim);
  margin-right: 4px;
}
.advisory ul, .advisory ol {
  margin: 4px 0 12px 0;
  padding-left: 22px;
}
.advisory li {
  margin-bottom: 4px;
  line-height: 1.5;
}
.advisory ul.bullet-tight li { margin-bottom: 2px; }

pre.code {
  background: var(--code-bg);
  border-left: 3px solid var(--brand);
  padding: 10px 14px;
  margin: 6px 0 12px 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10pt;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  page-break-inside: avoid;
}
pre.evidence {
  background: #F8FAFC;
  border: 1px solid var(--rule);
  padding: 10px 14px;
  margin: 6px 0 12px 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 9.5pt;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre-wrap;
  page-break-inside: avoid;
}
.ref-list {
  list-style: disc;
  padding-left: 22px;
}
.ref-list li { margin-bottom: 4px; }
.ref-list a {
  color: var(--brand);
  text-decoration: none;
  word-break: break-all;
}
.ref-list .lbl { font-weight: 600; }

/* ---------------- Executive summary ---------------- */
.exec {
  page-break-after: always;
}
.exec h2 {
  font-size: 22pt;
  border-bottom: 1px solid var(--rule);
  padding-bottom: 8px;
  margin-bottom: 14px;
}
.exec .risk {
  display: grid;
  grid-template-columns: 150px 1fr;
  gap: 22px;
  align-items: center;
  border: 1px solid var(--rule);
  border-left: 4px solid var(--brand-2);
  padding: 18px 20px;
  margin-bottom: 16px;
}
.exec .risk.band-low      { border-left-color: var(--sev-low); }
.exec .risk.band-moderate { border-left-color: var(--sev-medium); }
.exec .risk.band-elevated, .exec .risk.band-high { border-left-color: var(--sev-high); }
.exec .risk.band-critical { border-left-color: var(--sev-critical); }
.exec .risk .num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 44pt; font-weight: 700;
  line-height: 1;
}
.exec .risk .scale { color: var(--ink-dim); font-size: 11pt; }
.exec .risk .band {
  margin-top: 4px;
  display: inline-block;
  padding: 3px 10px;
  font-size: 9pt; font-weight: 700;
  letter-spacing: 0.16em;
  color: white;
  background: var(--brand-2);
}
.exec .risk.band-low      .band { background: var(--sev-low); }
.exec .risk.band-moderate .band { background: var(--sev-medium); }
.exec .risk.band-elevated .band, .exec .risk.band-high .band { background: var(--sev-high); }
.exec .risk.band-critical .band { background: var(--sev-critical); }
.exec .stats {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 6px; margin-top: 8px;
}
.exec .stat {
  border: 1px solid var(--rule);
  padding: 10px 8px;
  text-align: center;
}
.exec .stat .label {
  font-size: 8.5pt; letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--ink-dim);
}
.exec .stat .num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 18pt; font-weight: 700;
}
.exec .stat.crit .num { color: var(--sev-critical); }
.exec .stat.high .num { color: var(--sev-high); }
.exec .stat.med  .num { color: var(--sev-medium); }
.exec .stat.low  .num { color: var(--sev-low); }
.exec .stat.info .num { color: var(--sev-info); }
.exec .method-grid {
  display: grid; grid-template-columns: 1fr 1fr;
  gap: 12px; margin-top: 16px;
}
.exec .method-grid .col {
  border: 1px solid var(--rule);
  padding: 12px 16px;
}
.exec .method-grid h4 {
  margin: 0 0 6px 0; font-size: 11pt;
  color: var(--brand);
}
.exec .method-grid ul { margin: 0; padding-left: 18px; }
.exec .method-grid li {
  margin-bottom: 3px; font-size: 10.5pt;
  color: var(--ink-soft);
}

/* ---------------- Appendix ---------------- */
.appendix { page-break-before: always; }
.appendix h2 {
  font-size: 22pt;
  border-bottom: 1px solid var(--rule);
  padding-bottom: 8px;
  margin-bottom: 16px;
}
table.tbl {
  width: 100%; border-collapse: collapse;
  font-size: 10.5pt;
  margin-bottom: 14px;
}
table.tbl th, table.tbl td {
  text-align: left; padding: 6px 10px;
  border-bottom: 1px solid var(--rule);
}
table.tbl th {
  font-size: 9.5pt;
  letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--ink-dim);
  background: var(--rule-soft);
}
table.tbl td.mono { font-family: 'JetBrains Mono', monospace; font-size: 9.5pt; }

.muted { color: var(--ink-dim); }

@media screen {
  body { background: #ECEEF3; }
  .doc { background: white; box-shadow: 0 4px 20px rgba(15,23,42,.08); margin-top: 12px; margin-bottom: 12px; }
}
"""


_SHIELD_SVG = (
    "<svg class='shield' viewBox='0 0 48 48' fill='none' "
    "xmlns='http://www.w3.org/2000/svg'>"
    "<defs><linearGradient id='sg' x1='0' y1='0' x2='1' y2='1'>"
    "<stop offset='0%' stop-color='#0B1B3F'/>"
    "<stop offset='100%' stop-color='#1D4ED8'/>"
    "</linearGradient></defs>"
    "<path d='M24 3 L42 10 V24 C42 34 33 42 24 45 C15 42 6 34 6 24 V10 Z' "
    "fill='url(#sg)'/>"
    "<path d='M17 24 L22 29 L32 19' stroke='white' stroke-width='3' "
    "stroke-linecap='round' stroke-linejoin='round' fill='none'/>"
    "</svg>"
)


def render_html(data: ReportData) -> str:
    """Render ``ReportData`` as a single self-contained advisory bundle."""
    parts: list[str] = []
    parts.append(_doc_head(data))
    parts.append(f"<body data-target='{html.escape(data.package)}'>")
    parts.append("<div class='doc'>")
    parts.append(_cover(data))
    parts.append(_toc(data))
    parts.append(_executive_summary(data))
    for idx, section in enumerate(_order_sections(data), start=1):
        parts.append(_advisory(section, idx, data))
    parts.append(_appendix(data))
    parts.append("</div>")
    parts.append("</body></html>")
    return "".join(parts)


# ---------- ordering ----------


def _order_sections(data: ReportData) -> list[FindingSection]:
    """Severity-descending, deterministic ordering for F1, F2, …"""
    out: list[FindingSection] = []
    for severity in _SEVERITY_ORDER:
        out.extend(data.by_severity(severity))
    return out


# ---------- head / cover / TOC ----------


def _doc_head(data: ReportData) -> str:
    title = html.escape(f"Security Assessment — {data.package}")
    return (
        "<!doctype html><html lang='en'><head>"
        f"<meta charset='utf-8'><title>{title}</title>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link href='https://fonts.googleapis.com/css2?"
        "family=EB+Garamond:ital,wght@0,400;0,600;0,700;1,400&amp;"
        "family=JetBrains+Mono:wght@400;600&amp;display=swap' rel='stylesheet'>"
        f"<style>{_CSS}</style></head>"
    )


def _cover(data: ReportData) -> str:
    return (
        f"<section class='cover' data-target='{html.escape(data.package)}'>"
        "<div class='cover-banner'>"
        "<div class='left'>"
        f"{_SHIELD_SVG}"
        "<div class='wordmark'>SENTINEL</div>"
        "</div>"
        "<div class='classification'>CONFIDENTIAL · STRICTLY PRIVATE</div>"
        "</div>"
        "<div class='cover-title'>"
        "<div class='eyebrow'>Confidential Security Advisory Bundle</div>"
        "<h1>Mobile Application Security Assessment</h1>"
        f"<h2>{html.escape(data.package)}</h2>"
        "</div>"
        "<div class='cover-meta'>"
        f"<div class='row'><span class='key'>Target</span>"
        f"<span class='val'>{html.escape(data.package)}</span></div>"
        f"<div class='row'><span class='key'>Version</span>"
        f"<span class='val'>{html.escape(data.version)}</span></div>"
        f"<div class='row'><span class='key'>Engagement</span>"
        f"<span class='val'>{html.escape(data.session_id)}</span></div>"
        f"<div class='row'><span class='key'>Report Date</span>"
        f"<span class='val'>"
        f"{html.escape(data.generated_at.strftime('%B %d, %Y'))}</span></div>"
        "<div class='row'><span class='key'>Author</span>"
        "<span class='val'>SENTINEL Engine v0.1.0</span></div>"
        "<div class='row'><span class='key'>Methodology</span>"
        "<span class='val'>SAST · DAST · RAG</span></div>"
        f"<div class='row'><span class='key'>APK SHA-256</span>"
        f"<span class='val'>"
        f"{html.escape((data.apk_sha256 or 'n/a')[:32])}…</span></div>"
        "<div class='row'><span class='key'>Classification</span>"
        "<span class='val'>CONFIDENTIAL</span></div>"
        "</div>"
        "<div style='text-align:center; font-size: 10pt;"
        " letter-spacing: 0.30em; color: var(--ink-dim); margin-top: 18px;'>"
        "INDEPENDENT SECURITY RESEARCH · STATIC + DYNAMIC APK ANALYSIS"
        "</div>"
        "</section>"
    )


def _toc(data: ReportData) -> str:
    sections = _order_sections(data)
    items: list[str] = []
    items.append(
        "<li><span class='lbl'>Executive Summary</span>"
        "<span class='num'>3</span></li>"
    )
    for idx, s in enumerate(sections, start=1):
        title = html.escape(s.finding.vuln_class)
        sev = _SEVERITY_LABEL[s.finding.severity]
        items.append(
            f"<li><span class='lbl'>F{idx}. {title} "
            f"<span class='muted'>({sev})</span></span>"
            f"<span class='num'>—</span></li>"
        )
    items.append(
        "<li><span class='lbl'>Appendix</span>"
        "<span class='num'>—</span></li>"
    )
    return (
        "<section class='toc'>"
        "<h2>Table of Contents</h2>"
        "<div class='grp-title'>Bundle</div>"
        f"<ul>{''.join(items)}</ul>"
        "</section>"
    )


# ---------- executive summary ----------


def _executive_summary(data: ReportData) -> str:
    band_key = (data.risk.band or "low").lower()
    sev = data.severity_counts or {}
    total = sum(sev.get(k, 0) for k in
                ("Critical", "High", "Medium", "Low", "Info"))
    crit = sev.get("Critical", 0)
    high = sev.get("High", 0)
    if crit:
        prose = (
            f"SENTINEL performed automated static and dynamic analysis "
            f"against <strong>{html.escape(data.package)}</strong> and "
            f"identified <strong>{crit} critical</strong> and "
            f"<strong>{high} high-severity</strong> vulnerabilities. "
            "Each is enumerated as a numbered advisory in the chapters "
            "that follow, with reproduction steps, attacker capability, "
            "and a code-level remediation. Immediate remediation of "
            "the critical findings is recommended before the next "
            "production release."
        )
    elif high:
        prose = (
            f"SENTINEL identified <strong>{high} high-severity</strong> "
            f"vulnerabilities in <strong>{html.escape(data.package)}</strong>. "
            "Each is enumerated as a numbered advisory in the chapters "
            "that follow. Near-term remediation is recommended."
        )
    else:
        prose = (
            f"SENTINEL identified no critical or high-severity "
            f"vulnerabilities in <strong>{html.escape(data.package)}</strong>. "
            "Medium and low-severity findings, where present, are "
            "enumerated for completeness."
        )
    return (
        "<section class='exec'>"
        "<h2>Executive Summary</h2>"
        f"<div class='risk band-{html.escape(band_key)}'>"
        "<div style='text-align:center;'>"
        f"<div class='num'>{data.risk.score}</div>"
        "<div class='scale'>/ 100</div>"
        f"<div class='band'>{html.escape(band_key.upper())} RISK</div>"
        "</div>"
        f"<p style='margin:0; font-size: 12pt;'>{prose}</p>"
        "</div>"
        "<div class='stats'>"
        f"<div class='stat'><div class='label'>Total</div>"
        f"<div class='num'>{total}</div></div>"
        f"<div class='stat crit'><div class='label'>Critical</div>"
        f"<div class='num'>{sev.get('Critical', 0)}</div></div>"
        f"<div class='stat high'><div class='label'>High</div>"
        f"<div class='num'>{sev.get('High', 0)}</div></div>"
        f"<div class='stat med'><div class='label'>Medium</div>"
        f"<div class='num'>{sev.get('Medium', 0)}</div></div>"
        f"<div class='stat low'><div class='label'>Low</div>"
        f"<div class='num'>{sev.get('Low', 0)}</div></div>"
        f"<div class='stat info'><div class='label'>Info</div>"
        f"<div class='num'>{sev.get('Info', 0)}</div></div>"
        "</div>"
        "<div class='method-grid'>"
        "<div class='col'>"
        "<h4>Scope</h4>"
        "<ul>"
        f"<li>Package: <code>{html.escape(data.package)}</code></li>"
        f"<li>Version: <code>{html.escape(data.version)}</code></li>"
        f"<li>APK size: {data.apk_size_bytes:,} bytes</li>"
        f"<li>Engagement: <code>{html.escape(data.session_id)}</code></li>"
        "</ul></div>"
        "<div class='col'>"
        "<h4>Methodology</h4>"
        "<ul>"
        "<li>OWASP Mobile Top 10 (M1–M10)</li>"
        "<li>OWASP MASVS Level 2 verification</li>"
        "<li>Static Analysis — bytecode + manifest</li>"
        "<li>Dynamic Analysis — Frida instrumentation</li>"
        "<li>RAG triage against CVE / CWE corpus</li>"
        "</ul></div></div>"
        "</section>"
    )


# ---------- advisory ----------


def _advisory(section: FindingSection, idx: int, data: ReportData) -> str:
    f = section.finding
    sev_label = _SEVERITY_LABEL[f.severity]
    narrative = section.narrative or {}

    masthead = _advisory_masthead(section, idx, data, sev_label)

    sec1 = _section_block(
        1, "Summary",
        f"<p>{html.escape(narrative.get('summary') or section.triage_explanation or f.vuln_class)}</p>",
    )
    sec2 = _section_block(2, "Affected Components", _affected_html(section))
    sec3 = _section_block(
        3, "Evidence in the APK", _evidence_html(section),
    )
    sec4 = _section_block(
        4, "Steps to Reproduce", _repro_html(narrative),
    )
    sec5 = _section_block(
        5, "Proof of Concept", _poc_html(section),
    )
    sec6 = _section_block(
        6, "Impact",
        _bullet_list(narrative.get("impact_bullets") or [
            "The scanner observed a security-relevant pattern; "
            "impact requires manual triage."
        ]),
    )
    sec7 = _section_block(
        7, "Suggested Fix",
        _bullet_list(
            narrative.get("fix_bullets") or [f.recommendation or ""],
        ),
    )
    sec8 = _section_block(8, "References", _refs_html(section))

    return (
        f"<section class='advisory'>"
        f"{masthead}"
        f"{sec1}{sec2}{sec3}{sec4}{sec5}{sec6}{sec7}{sec8}"
        "</section>"
    )


def _advisory_masthead(
    section: FindingSection, idx: int, data: ReportData, sev_label: str,
) -> str:
    f = section.finding
    return (
        "<div class='masthead'>"
        "<div class='head-row'>"
        "<div class='left'>"
        f"<div class='findingId'>F{idx}</div>"
        "<div class='label'>FINDING</div>"
        "</div>"
        "<div class='classification'>CONFIDENTIAL</div>"
        "</div>"
        f"<h1>{html.escape(f.vuln_class)}</h1>"
        "<dl class='meta-grid'>"
        f"<dt>Severity</dt><dd><span class='sev-chip {sev_label}'>"
        f"{sev_label}</span></dd>"
        f"<dt>CVSS Vector</dt><dd>{html.escape(f.cvss_vector or 'n/a')}</dd>"
        f"<dt>OWASP</dt><dd>{html.escape(f.owasp or '—')}</dd>"
        f"<dt>MASVS</dt><dd>{html.escape(f.masvs or '—')}</dd>"
        f"<dt>Target</dt>"
        f"<dd>{html.escape(data.package)} "
        f"<span class='muted'>v{html.escape(data.version)}</span></dd>"
        f"<dt>Report Date</dt>"
        f"<dd>{html.escape(data.generated_at.strftime('%B %d, %Y'))}</dd>"
        "<dt>Status</dt><dd>Confirmed "
        "<span class='muted'>(validated against decompiled APK)</span></dd>"
        f"<dt>Discovered By</dt><dd>{html.escape(f.agent_id)} · "
        f"{f.confidence:.0%} confidence</dd>"
        "</dl>"
        "</div>"
    )


def _section_block(num: int, title: str, body: str) -> str:
    return (
        "<div class='sec'>"
        f"<h2><span class='nm'>{num}</span>{html.escape(title)}</h2>"
        f"{body}"
        "</div>"
    )


def _affected_html(section: FindingSection) -> str:
    items = list(section.narrative.get("affected_components") or [])
    if not items and isinstance(section.finding.evidence, dict):
        ev = section.finding.evidence
        for k in ("file", "files", "activity", "component", "class",
                  "manifest", "smali", "path", "location"):
            v = ev.get(k)
            if isinstance(v, str):
                items.append(v)
            elif isinstance(v, list):
                items.extend(str(x) for x in v if x)
    if not items:
        return "<p class='muted'>None enumerated by the scanner.</p>"
    return _bullet_list(items)


def _evidence_html(section: FindingSection) -> str:
    notes = section.narrative.get("evidence_notes") or ""
    ev = section.finding.evidence
    body: list[str] = []
    if notes:
        body.append(f"<p>{html.escape(notes)}</p>")
    if isinstance(ev, dict) and ev:
        body.append(
            "<pre class='evidence'>"
            + html.escape(json.dumps(
                _clean_evidence(ev), indent=2, sort_keys=True,
            ))
            + "</pre>"
        )
    else:
        body.append("<p class='muted'>No structured evidence captured.</p>")
    return "".join(body)


def _repro_html(narrative: dict) -> str:
    steps = list(narrative.get("repro_steps") or [])
    if not steps:
        return "<p class='muted'>Reproduction recipe not available.</p>"
    return (
        "<ol>"
        + "".join(f"<li>{_inline_md(s)}</li>" for s in steps)
        + "</ol>"
    )


def _poc_html(section: FindingSection) -> str:
    poc = (section.narrative.get("poc_snippet") or "").strip()
    ev = section.finding.evidence if isinstance(
        section.finding.evidence, dict,
    ) else {}
    if not poc:
        poc = str(
            ev.get("poc_command")
            or ev.get("poc_url")
            or ev.get("exploit_command")
            or "",
        ).strip()
    if not poc:
        return (
            "<p class='muted'>No safe, generic PoC snippet is "
            "appropriate for this finding without manual triage.</p>"
        )
    return f"<pre class='code'>{html.escape(poc)}</pre>"


def _refs_html(section: FindingSection) -> str:
    refs = list(section.narrative.get("references") or [])
    # Always include RAG-mapped standards when available.
    for cid, title in (section.rag_mapping or {}).items():
        refs.append({
            "label": f"{cid} — {title}",
            "url": "https://mas.owasp.org/MASVS/",
        })
    if not refs:
        return "<p class='muted'>No external references attached.</p>"
    items = "".join(
        f"<li><span class='lbl'>{html.escape(r['label'])}:</span> "
        f"<a href='{html.escape(r['url'])}'>{html.escape(r['url'])}</a></li>"
        for r in refs
    )
    return f"<ul class='ref-list'>{items}</ul>"


# ---------- helpers ----------


def _bullet_list(items: Iterable[str]) -> str:
    items = [str(i) for i in items if str(i).strip()]
    if not items:
        return "<p class='muted'>—</p>"
    return (
        "<ul class='bullet-tight'>"
        + "".join(f"<li>{_inline_md(s)}</li>" for s in items)
        + "</ul>"
    )


def _inline_md(text: str) -> str:
    """Render minimal inline markdown — backticks → <code>."""
    out: list[str] = []
    i = 0
    text = str(text)
    while i < len(text):
        if text[i] == "`":
            end = text.find("`", i + 1)
            if end == -1:
                out.append(html.escape(text[i:]))
                break
            out.append("<code>")
            out.append(html.escape(text[i + 1:end]))
            out.append("</code>")
            i = end + 1
        else:
            out.append(html.escape(text[i]))
            i += 1
    return "".join(out)


# ---------- appendix ----------


def _appendix(data: ReportData) -> str:
    agents = sorted({s.finding.agent_id for s in data.sections})
    agent_rows = "".join(
        f"<tr><td class='mono'>{html.escape(a)}</td>"
        f"<td>{sum(1 for s in data.sections if s.finding.agent_id == a)}"
        "</td></tr>"
        for a in agents
    ) or (
        "<tr><td colspan='2' class='muted'>No agents reported findings.</td></tr>"
    )
    refs_table = _references_table(data.references)
    return (
        "<section class='appendix'>"
        "<h2>Appendix</h2>"
        "<h3 style='margin-top:0;'>Tool Versioning</h3>"
        "<table class='tbl'>"
        "<thead><tr><th>Component</th><th>Version</th></tr></thead>"
        "<tbody>"
        "<tr><td>SENTINEL Engine</td><td class='mono'>v0.1.0</td></tr>"
        "<tr><td>Report Format</td><td class='mono'>VAPT-2026.06</td></tr>"
        "<tr><td>Standards Corpus</td>"
        "<td class='mono'>MASVS-2.0 / OWASP-MOBILE-2024</td></tr>"
        "</tbody></table>"
        "<h3>Contributing Agents</h3>"
        "<table class='tbl'>"
        "<thead><tr><th>Agent ID</th><th>Findings</th></tr></thead>"
        f"<tbody>{agent_rows}</tbody></table>"
        f"{refs_table}"
        "<p class='muted' style='margin-top:24px; font-size: 10pt;'>"
        "This document was produced by an automated security analysis "
        "engine. Findings should be triaged by a human reviewer before "
        "external disclosure. Distribution is restricted to the "
        "engagement requester."
        "</p>"
        "</section>"
    )


def _references_table(refs: Iterable[ReferenceBlock]) -> str:
    refs = list(refs)
    if not refs:
        return ""
    rows = "".join(
        f"<tr><td>{html.escape(r.source)}</td>"
        f"<td class='mono'>{html.escape(r.control_id)}</td>"
        f"<td>{html.escape(r.title)}</td></tr>"
        for r in refs
    )
    return (
        "<h3>Standards Cited</h3>"
        "<table class='tbl'>"
        "<thead><tr><th>Source</th><th>Control</th><th>Title</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )
