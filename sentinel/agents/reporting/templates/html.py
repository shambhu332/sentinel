"""HTML renderer for the VAPT report.

Single-file, self-contained HTML — embedded CSS, no external assets,
no JavaScript. Structured to match a top-tier-consultancy VAPT
deliverable (NCC / Bishop Fox style):

    1. Cover page         — target, classification, author, date
    2. Executive summary  — risk badge, prose, severity stats
    3. Scope & methodology
    4. Findings           — grouped by severity, each with CVSS,
                            threat-intelligence box, PoC box (when
                            verified exploitable), impact, remediation
    5. Appendix           — tool versioning, agent catalogue summary

The output is intended to be openable directly from disk and printable
via the browser's "Print to PDF" workflow without any additional
tooling.
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

_SEVERITY_ORDER = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    Severity.LOW, Severity.INFO,
)

_BAND_LABEL = {
    "critical": "CRITICAL RISK",
    "high":     "HIGH RISK",
    "elevated": "ELEVATED RISK",
    "moderate": "MODERATE RISK",
    "low":      "LOW RISK",
}

_CSS = """\
:root {
  --bg: #FFFFFF;
  --paper: #FFFFFF;
  --ink: #0B1220;
  --ink-soft: #3B475C;
  --ink-dim: #6B7A93;
  --rule: #D7DEEA;
  --rule-soft: #ECEFF5;
  --brand-1: #1E3A8A;
  --brand-2: #0EA5E9;
  --sev-critical: #B91C1C;
  --sev-high: #C2410C;
  --sev-medium: #B45309;
  --sev-low: #1D4ED8;
  --sev-info: #475569;
  --bg-critical: #FEF2F2;
  --bg-high: #FFF7ED;
  --bg-medium: #FFFBEB;
  --bg-low: #EFF6FF;
  --bg-info: #F1F5F9;
  --bg-rag: #F0F9FF;
  --bg-poc: #FDF4FF;
  --bg-impact: #FEF2F2;
  --bg-reco: #ECFDF5;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 14px;
  line-height: 1.55;
}
.page { max-width: 880px; margin: 0 auto; padding: 56px 56px 32px; }

/* ---------- Cover ---------- */
.cover {
  min-height: 96vh;
  display: flex; flex-direction: column;
  justify-content: space-between;
  padding: 64px 56px;
  border-bottom: 2px solid var(--brand-1);
  background: linear-gradient(180deg, #FFFFFF 0%, #F8FAFF 100%);
  page-break-after: always;
}
.cover-brand {
  display: flex; align-items: center; gap: 14px;
}
.cover-brand .shield {
  width: 44px; height: 44px;
}
.cover-brand .wordmark {
  font-size: 20px; font-weight: 700;
  letter-spacing: 0.18em;
  color: var(--brand-1);
}
.cover-title {
  margin-top: 18vh;
}
.cover-title .eyebrow {
  font-size: 12px; font-weight: 600;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--ink-dim);
  margin-bottom: 12px;
}
.cover-title h1 {
  font-size: 40px; font-weight: 700;
  letter-spacing: -0.02em; line-height: 1.1;
  margin: 0 0 12px 0;
  color: var(--ink);
}
.cover-title .sub {
  font-size: 18px; color: var(--ink-soft);
  max-width: 600px;
}
.cover-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  border-top: 1px solid var(--rule);
}
.cover-meta dl {
  margin: 0; padding: 18px 0 0 0;
}
.cover-meta dt {
  font-size: 10px; font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink-dim);
  margin-bottom: 4px;
}
.cover-meta dd {
  margin: 0 0 18px 0;
  font-size: 14px;
  font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
  color: var(--ink);
}
.classification {
  display: inline-block;
  padding: 4px 10px;
  background: var(--sev-critical);
  color: white;
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.18em;
  border-radius: 3px;
}

/* ---------- Section frame ---------- */
section.s {
  padding-top: 16px;
  margin-bottom: 32px;
}
section.s > .label {
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--brand-1);
  margin-bottom: 6px;
}
section.s > h2 {
  font-size: 26px; font-weight: 700;
  margin: 0 0 18px 0;
  letter-spacing: -0.01em;
  border-bottom: 1px solid var(--rule);
  padding-bottom: 10px;
}

/* ---------- Executive summary ---------- */
.risk-card {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 28px;
  align-items: center;
  padding: 24px;
  border: 1px solid var(--rule);
  border-left: 4px solid var(--sev-critical);
  border-radius: 6px;
  background: var(--bg-critical);
  margin-bottom: 20px;
}
.risk-card.band-critical { border-left-color: var(--sev-critical); background: var(--bg-critical); }
.risk-card.band-high     { border-left-color: var(--sev-high);     background: var(--bg-high); }
.risk-card.band-elevated { border-left-color: var(--sev-high);     background: var(--bg-high); }
.risk-card.band-moderate { border-left-color: var(--sev-medium);   background: var(--bg-medium); }
.risk-card.band-low      { border-left-color: var(--sev-low);      background: var(--bg-low); }
.risk-badge {
  text-align: center;
}
.risk-badge .num {
  font-size: 64px; font-weight: 800;
  line-height: 1;
  font-family: 'JetBrains Mono', monospace;
  color: var(--ink);
}
.risk-badge .scale { color: var(--ink-dim); font-size: 14px; }
.risk-badge .band {
  margin-top: 8px;
  display: inline-block;
  padding: 4px 10px;
  border-radius: 3px;
  font-size: 11px; font-weight: 700;
  letter-spacing: 0.14em;
  color: white;
  background: var(--sev-critical);
}
.risk-card.band-high     .risk-badge .band,
.risk-card.band-elevated .risk-badge .band { background: var(--sev-high); }
.risk-card.band-moderate .risk-badge .band { background: var(--sev-medium); }
.risk-card.band-low      .risk-badge .band { background: var(--sev-low); }
.risk-prose { font-size: 15px; color: var(--ink); }
.risk-prose strong { color: var(--ink); }

.stats {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 8px;
  margin-top: 8px;
}
.stat {
  border: 1px solid var(--rule);
  border-radius: 6px;
  padding: 12px 10px;
  text-align: center;
  background: white;
}
.stat .label {
  font-size: 10px; font-weight: 600;
  letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--ink-dim);
  margin-bottom: 4px;
}
.stat .num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 22px; font-weight: 700;
  color: var(--ink);
}
.stat.crit .num { color: var(--sev-critical); }
.stat.high .num { color: var(--sev-high); }
.stat.med  .num { color: var(--sev-medium); }
.stat.low  .num { color: var(--sev-low); }
.stat.info .num { color: var(--sev-info); }

/* ---------- Methodology ---------- */
.method-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.method-grid .col {
  border: 1px solid var(--rule);
  border-radius: 6px;
  padding: 16px 18px;
}
.method-grid h4 {
  margin: 0 0 8px 0;
  font-size: 13px;
  color: var(--brand-1);
  letter-spacing: 0.04em;
}
.method-grid ul { margin: 0; padding-left: 18px; }
.method-grid li { margin-bottom: 4px; font-size: 13px; color: var(--ink-soft); }

/* ---------- Findings ---------- */
.sev-heading {
  display: flex; align-items: center; gap: 10px;
  margin-top: 24px; margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--rule);
}
.sev-heading h3 {
  margin: 0; font-size: 18px; font-weight: 700;
}
.sev-pill {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.12em; text-transform: uppercase;
  color: white;
}
.sev-pill.Critical { background: var(--sev-critical); }
.sev-pill.High     { background: var(--sev-high); }
.sev-pill.Medium   { background: var(--sev-medium); }
.sev-pill.Low      { background: var(--sev-low); }
.sev-pill.Info     { background: var(--sev-info); }
.sev-pill.outline {
  background: white;
  border: 1px solid currentColor;
}
.sev-pill.outline.Critical { color: var(--sev-critical); }
.sev-pill.outline.High     { color: var(--sev-high); }
.sev-pill.outline.Medium   { color: var(--sev-medium); }
.sev-pill.outline.Low      { color: var(--sev-low); }
.sev-pill.outline.Info     { color: var(--sev-info); }

.finding {
  border: 1px solid var(--rule);
  border-radius: 8px;
  margin-bottom: 18px;
  padding: 20px 22px;
  background: white;
  page-break-inside: avoid;
}
.finding.sev-Critical { border-left: 4px solid var(--sev-critical); }
.finding.sev-High     { border-left: 4px solid var(--sev-high); }
.finding.sev-Medium   { border-left: 4px solid var(--sev-medium); }
.finding.sev-Low      { border-left: 4px solid var(--sev-low); }
.finding.sev-Info     { border-left: 4px solid var(--sev-info); }

.finding-head {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 16px;
  margin-bottom: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--rule-soft);
}
.finding-head h4 {
  margin: 0 0 4px 0;
  font-size: 17px; font-weight: 700;
  letter-spacing: -0.005em;
  line-height: 1.3;
}
.finding-head .vid {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px; color: var(--ink-dim);
  letter-spacing: 0.04em;
}
.finding-meta {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px 14px;
  font-size: 13px;
  margin-bottom: 14px;
}
.finding-meta dt {
  color: var(--ink-dim);
  font-weight: 600;
  font-size: 11px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding-top: 2px;
}
.finding-meta dd {
  margin: 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12.5px;
  color: var(--ink);
  word-break: break-word;
}

.finding h5 {
  margin: 16px 0 6px 0;
  font-size: 11px; font-weight: 700;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink-dim);
}
.finding p { margin: 0 0 10px 0; font-size: 14px; color: var(--ink-soft); }

.box {
  border-radius: 6px;
  padding: 12px 14px;
  margin: 10px 0 16px 0;
  font-size: 13px;
}
.box .box-title {
  display: flex; align-items: center; gap: 8px;
  font-size: 10px; font-weight: 700;
  letter-spacing: 0.14em; text-transform: uppercase;
  margin-bottom: 8px;
}
.box .box-title .dot {
  width: 8px; height: 8px; border-radius: 50%;
  display: inline-block;
}
.box.intel { background: var(--bg-rag); border: 1px solid #BAE6FD; }
.box.intel .box-title { color: #0369A1; }
.box.intel .dot      { background: #0EA5E9; }
.box.poc   { background: var(--bg-poc);  border: 1px solid #F0ABFC; }
.box.poc   .box-title { color: #86198F; }
.box.poc   .dot      { background: #D946EF; }
.box.impact{ background: var(--bg-impact); border: 1px solid #FECACA; }
.box.impact .box-title { color: var(--sev-critical); }
.box.impact .dot      { background: var(--sev-critical); }
.box.reco  { background: var(--bg-reco); border: 1px solid #A7F3D0; }
.box.reco  .box-title { color: #047857; }
.box.reco  .dot      { background: #10B981; }
.box ul { margin: 0; padding-left: 18px; }
.box li { margin-bottom: 3px; font-size: 13px; }
.box code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  background: rgba(15, 23, 42, .06);
  padding: 1px 5px;
  border-radius: 3px;
}

pre.evidence {
  background: #0B1220;
  color: #E2E8F0;
  border-radius: 6px;
  padding: 12px 14px;
  overflow-x: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11.5px;
  line-height: 1.5;
  margin: 6px 0 14px;
}

/* ---------- Appendix ---------- */
table.tbl {
  width: 100%; border-collapse: collapse;
  font-size: 13px;
  margin-bottom: 16px;
}
table.tbl th, table.tbl td {
  text-align: left; padding: 8px 10px;
  border-bottom: 1px solid var(--rule);
}
table.tbl th {
  font-size: 11px; font-weight: 600;
  letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--ink-dim);
  background: var(--rule-soft);
}
table.tbl td.mono {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
}

footer.doc-footer {
  margin-top: 48px;
  padding-top: 18px;
  border-top: 1px solid var(--rule);
  color: var(--ink-dim);
  font-size: 11px;
}
footer.doc-footer .row {
  display: flex; justify-content: space-between;
  margin-bottom: 4px;
}

/* ---------- Print ---------- */
@media print {
  body { background: white; }
  .page { max-width: 100%; padding: 0 24px; }
  .cover { min-height: 95vh; padding: 32px; }
  .finding, .risk-card, .box { page-break-inside: avoid; }
  section.s { page-break-inside: avoid; }
  .sev-heading { page-break-after: avoid; }
  pre.evidence { background: #F1F5F9; color: #0B1220; border: 1px solid var(--rule); }
}
"""

_SHIELD_SVG = (
    "<svg class='shield' viewBox='0 0 48 48' fill='none' "
    "xmlns='http://www.w3.org/2000/svg'>"
    "<defs><linearGradient id='sg' x1='0' y1='0' x2='1' y2='1'>"
    "<stop offset='0%' stop-color='#1E3A8A'/>"
    "<stop offset='100%' stop-color='#0EA5E9'/>"
    "</linearGradient></defs>"
    "<path d='M24 3 L42 10 V24 C42 34 33 42 24 45 C15 42 6 34 6 24 V10 Z' "
    "fill='url(#sg)'/>"
    "<path d='M17 24 L22 29 L32 19' stroke='white' stroke-width='3' "
    "stroke-linecap='round' stroke-linejoin='round' fill='none'/>"
    "</svg>"
)


def render_html(data: ReportData) -> str:
    """Render ``ReportData`` as a single self-contained HTML document."""
    parts: list[str] = []
    parts.append(_doc_head(data))
    parts.append("<body>")
    parts.append(_cover(data))
    parts.append("<div class='page'>")
    parts.append(_executive_summary(data))
    parts.append(_scope_methodology(data))
    parts.append(_findings_section(data))
    parts.append(_appendix(data))
    parts.append("</div>")
    parts.append("</body></html>")
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


def _cover(data: ReportData) -> str:
    return (
        "<section class='cover'>"
        "<div class='cover-brand'>"
        f"{_SHIELD_SVG}"
        "<div class='wordmark'>SENTINEL</div>"
        "</div>"
        "<div class='cover-title'>"
        "<div class='eyebrow'>Vulnerability Assessment &amp; Penetration Test</div>"
        "<h1>Mobile Application Security Assessment</h1>"
        f"<div class='sub'>{html.escape(data.package)} "
        f"<span style='color:#94A3B8'>· version "
        f"{html.escape(data.version)}</span></div>"
        "</div>"
        "<div class='cover-meta'>"
        "<dl>"
        "<dt>Target</dt>"
        f"<dd>{html.escape(data.package)}</dd>"
        "<dt>Version</dt>"
        f"<dd>{html.escape(data.version)}</dd>"
        "<dt>Engagement</dt>"
        f"<dd>{html.escape(data.session_id)}</dd>"
        "</dl>"
        "<dl>"
        "<dt>Date Issued</dt>"
        f"<dd>{html.escape(data.generated_at.strftime('%B %d, %Y'))}</dd>"
        "<dt>Author</dt>"
        "<dd>SENTINEL Automated Engine v0.1.0</dd>"
        "<dt>Classification</dt>"
        "<dd><span class='classification'>"
        "CONFIDENTIAL · STRICTLY PRIVATE</span></dd>"
        "</dl>"
        "</div>"
        "</section>"
    )


def _executive_summary(data: ReportData) -> str:
    band_key = (data.risk.band or "low").lower()
    band_label = _BAND_LABEL.get(band_key, band_key.upper())
    sev = data.severity_counts or {}
    total = sum(sev.get(k, 0) for k in
                ("Critical", "High", "Medium", "Low", "Info"))
    crit = sev.get("Critical", 0)
    high = sev.get("High", 0)

    if crit:
        prose = (
            f"SENTINEL performed automated static and dynamic analysis of "
            f"<strong>{html.escape(data.package)}</strong> and identified "
            f"<strong>{crit} critical</strong> and <strong>{high} "
            f"high-severity</strong> vulnerabilities. Immediate remediation "
            f"of the critical findings is recommended before the next "
            f"production release."
        )
    elif high:
        prose = (
            f"SENTINEL performed automated static and dynamic analysis of "
            f"<strong>{html.escape(data.package)}</strong> and identified "
            f"<strong>{high} high-severity</strong> vulnerabilities. Near-"
            f"term remediation is recommended."
        )
    else:
        prose = (
            f"SENTINEL performed automated static and dynamic analysis of "
            f"<strong>{html.escape(data.package)}</strong> and identified "
            f"no critical or high-severity vulnerabilities. The application "
            f"presents a healthy security posture for its category."
        )
    return (
        "<section class='s'>"
        "<div class='label'>Section 01</div>"
        "<h2>Executive Summary</h2>"
        f"<div class='risk-card band-{html.escape(band_key)}'>"
        "<div class='risk-badge'>"
        f"<div class='num'>{data.risk.score}</div>"
        "<div class='scale'>/ 100</div>"
        f"<div class='band'>{html.escape(band_label)}</div>"
        "</div>"
        f"<div class='risk-prose'>{prose}</div>"
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
        "</section>"
    )


def _scope_methodology(data: ReportData) -> str:
    return (
        "<section class='s'>"
        "<div class='label'>Section 02</div>"
        "<h2>Scope &amp; Methodology</h2>"
        "<div class='method-grid'>"
        "<div class='col'>"
        "<h4>In-Scope</h4>"
        "<ul>"
        f"<li>Package: <code>{html.escape(data.package)}</code></li>"
        f"<li>Version: <code>{html.escape(data.version)}</code></li>"
        f"<li>APK SHA-256: <code>"
        f"{html.escape((data.apk_sha256 or '—')[:32])}…</code></li>"
        f"<li>APK Size: {data.apk_size_bytes:,} bytes</li>"
        "</ul>"
        "</div>"
        "<div class='col'>"
        "<h4>Methodology</h4>"
        "<ul>"
        "<li>OWASP Mobile Top 10 (M1–M10)</li>"
        "<li>OWASP MASVS Level 2 verification</li>"
        "<li>Static Analysis (SAST) — bytecode + manifest</li>"
        "<li>Dynamic Analysis (DAST) — Frida instrumentation</li>"
        "<li>RAG-augmented triage against CVE / CWE corpus</li>"
        "<li>Exploit verification on a subset of findings</li>"
        "</ul>"
        "</div>"
        "</div>"
        "</section>"
    )


def _findings_section(data: ReportData) -> str:
    if not data.sections:
        return (
            "<section class='s'>"
            "<div class='label'>Section 03</div>"
            "<h2>Technical Findings</h2>"
            "<p style='color:var(--ink-dim)'>No findings identified.</p>"
            "</section>"
        )
    parts = [
        "<section class='s'>"
        "<div class='label'>Section 03</div>"
        "<h2>Technical Findings</h2>"
    ]
    for severity in _SEVERITY_ORDER:
        bucket = data.by_severity(severity)
        if not bucket:
            continue
        sev_label = _SEVERITY_LABEL[severity]
        parts.append(
            "<div class='sev-heading'>"
            f"<h3>{sev_label} Findings</h3>"
            f"<span class='sev-pill {sev_label}'>{len(bucket)}</span>"
            "</div>",
        )
        for s in bucket:
            parts.append(_finding_card(s))
    parts.append("</section>")
    return "".join(parts)


def _finding_card(section: FindingSection) -> str:
    f = section.finding
    sev_label = _SEVERITY_LABEL[f.severity]
    evidence = f.evidence or {}

    head = (
        "<div class='finding-head'>"
        "<div>"
        f"<h4>{html.escape(f.vuln_class)}</h4>"
        f"<div class='vid'>{html.escape(f.agent_id)}"
        f" · confidence {f.confidence:.0%}</div>"
        "</div>"
        f"<span class='sev-pill {sev_label}'>{sev_label}</span>"
        "</div>"
    )

    meta = (
        "<dl class='finding-meta'>"
        f"<dt>CVSS</dt><dd>{html.escape(f.cvss_vector or 'n/a')}</dd>"
        f"<dt>OWASP</dt><dd>{html.escape(f.owasp or '—')}</dd>"
        f"<dt>MASVS</dt><dd>{html.escape(f.masvs or '—')}</dd>"
        f"<dt>Discovered By</dt><dd>{html.escape(f.agent_id)}</dd>"
        "</dl>"
    )

    desc_text = (
        section.triage_explanation
        or (evidence.get("issue") if isinstance(evidence, dict) else None)
        or f.vuln_class
    )
    description = (
        "<h5>Description</h5>"
        f"<p>{html.escape(str(desc_text))}</p>"
    )

    intel = _threat_intel_box(section)
    poc = _poc_box(evidence)
    impact = _impact_box(evidence, f.severity)
    evidence_block = (
        "<h5>Evidence</h5>"
        "<pre class='evidence'>"
        + html.escape(json.dumps(
            _clean_evidence(evidence) if isinstance(evidence, dict) else {},
            indent=2, sort_keys=True,
        ))
        + "</pre>"
    )
    reco = (
        "<div class='box reco'>"
        "<div class='box-title'><span class='dot'></span>Remediation</div>"
        f"<div>{html.escape(f.recommendation)}</div>"
        "</div>"
    )

    return (
        f"<article class='finding sev-{sev_label}'>"
        f"{head}{meta}{description}{intel}{poc}{impact}{evidence_block}{reco}"
        "</article>"
    )


def _threat_intel_box(section: FindingSection) -> str:
    mapping = section.rag_mapping or {}
    evidence = section.finding.evidence or {}
    cves: list[str] = []
    compliance: list[str] = []

    if isinstance(evidence, dict):
        raw_cves = evidence.get("cve_references") or evidence.get("cves") or []
        if isinstance(raw_cves, str):
            raw_cves = [raw_cves]
        cves = [str(c) for c in raw_cves if c]
        raw_comp = (
            evidence.get("compliance_violations")
            or evidence.get("compliance")
            or []
        )
        if isinstance(raw_comp, str):
            raw_comp = [raw_comp]
        compliance = [str(c) for c in raw_comp if c]

    if not (mapping or cves or compliance):
        return ""

    items: list[str] = []
    if cves:
        items.append(
            "<li><strong>CVE References:</strong> "
            + ", ".join(f"<code>{html.escape(c)}</code>" for c in cves)
            + "</li>"
        )
    if compliance:
        items.append(
            "<li><strong>Compliance:</strong> "
            + ", ".join(html.escape(c) for c in compliance)
            + "</li>"
        )
    if mapping:
        rows = "".join(
            f"<li><code>{html.escape(cid)}</code> — {html.escape(title)}</li>"
            for cid, title in sorted(mapping.items())
        )
        items.append(
            "<li><strong>Standards mapping:</strong>"
            f"<ul>{rows}</ul></li>"
        )
    return (
        "<div class='box intel'>"
        "<div class='box-title'>"
        "<span class='dot'></span>Threat Intelligence (RAG)"
        "</div>"
        f"<ul>{''.join(items)}</ul>"
        "</div>"
    )


def _poc_box(evidence: dict) -> str:
    if not isinstance(evidence, dict):
        return ""
    status_val = str(
        evidence.get("exploit_status")
        or evidence.get("verification_status")
        or "",
    ).upper()
    if status_val != "EXPLOITABLE":
        return ""
    items: list[str] = []
    poc_url = evidence.get("poc_url") or evidence.get("exploit_url")
    if poc_url:
        items.append(
            f"<li><strong>PoC URL:</strong> "
            f"<code>{html.escape(str(poc_url))}</code></li>"
        )
    cmd = evidence.get("poc_command") or evidence.get("exploit_command")
    if cmd:
        items.append(
            f"<li><strong>Command:</strong> "
            f"<code>{html.escape(str(cmd))}</code></li>"
        )
    frida_log = evidence.get("frida_log") or evidence.get("dynamic_log")
    if frida_log:
        items.append(
            "<li><strong>Frida confirmation:</strong> "
            f"<code>{html.escape(str(frida_log)[:200])}</code></li>"
        )
    if not items:
        items.append("<li>Exploit verified by dynamic analysis.</li>")
    return (
        "<div class='box poc'>"
        "<div class='box-title'>"
        "<span class='dot'></span>Proof of Concept — VERIFIED EXPLOITABLE"
        "</div>"
        f"<ul>{''.join(items)}</ul>"
        "</div>"
    )


def _impact_box(evidence: dict, severity: Severity) -> str:
    text = None
    if isinstance(evidence, dict):
        text = evidence.get("impact") or evidence.get("attacker_capability")
    if not text:
        defaults = {
            Severity.CRITICAL: (
                "An attacker can fully compromise the affected component, "
                "potentially leading to account takeover, credential theft, "
                "or unauthorised access to user data."
            ),
            Severity.HIGH: (
                "An attacker can extract sensitive data or bypass a "
                "security control, materially weakening the application's "
                "trust boundary."
            ),
            Severity.MEDIUM: (
                "An attacker can degrade the application's defence-in-depth "
                "or gather reconnaissance useful in a larger chain."
            ),
            Severity.LOW: (
                "Low-impact misconfiguration that improves the attacker's "
                "knowledge but does not directly compromise the user."
            ),
            Severity.INFO: (
                "Informational observation with no direct attacker capability."
            ),
        }
        text = defaults.get(severity, "")
    if not text:
        return ""
    return (
        "<div class='box impact'>"
        "<div class='box-title'>"
        "<span class='dot'></span>Impact"
        "</div>"
        f"<div>{html.escape(str(text))}</div>"
        "</div>"
    )


def _appendix(data: ReportData) -> str:
    agents = sorted({s.finding.agent_id for s in data.sections})
    agent_rows = "".join(
        f"<tr><td class='mono'>{html.escape(a)}</td>"
        f"<td>{sum(1 for s in data.sections if s.finding.agent_id == a)}"
        "</td></tr>"
        for a in agents
    ) or (
        "<tr><td colspan='2' style='color:var(--ink-dim)'>"
        "No agents reported findings.</td></tr>"
    )
    refs_table = _references_table(data.references)
    return (
        "<section class='s'>"
        "<div class='label'>Appendix</div>"
        "<h2>Appendix</h2>"
        "<h5 style='margin-top:0'>Tool Versioning</h5>"
        "<table class='tbl'>"
        "<thead><tr><th>Component</th><th>Version</th></tr></thead>"
        "<tbody>"
        "<tr><td>SENTINEL Engine</td><td class='mono'>v0.1.0</td></tr>"
        "<tr><td>Report Format</td><td class='mono'>VAPT-2026.06</td></tr>"
        "<tr><td>Standards Corpus</td>"
        "<td class='mono'>MASVS-2.0 / OWASP-MOBILE-2024</td></tr>"
        "</tbody></table>"
        "<h5>Contributing Agents</h5>"
        "<table class='tbl'>"
        "<thead><tr><th>Agent ID</th><th>Findings</th></tr></thead>"
        f"<tbody>{agent_rows}</tbody></table>"
        f"{refs_table}"
        f"{_doc_footer(data)}"
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
        "<h5>Standards Cited</h5>"
        "<table class='tbl'>"
        "<thead><tr><th>Source</th><th>Control</th><th>Title</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _doc_footer(data: ReportData) -> str:
    return (
        "<footer class='doc-footer'>"
        f"<div class='row'><span>APK SHA-256</span>"
        f"<span class='mono'>{html.escape(data.apk_sha256 or 'n/a')}</span></div>"
        f"<div class='row'><span>Generated</span>"
        f"<span>{html.escape(data.generated_at.isoformat(timespec='seconds'))}"
        "</span></div>"
        "<div class='row'><span>SENTINEL Automated Engine v0.1.0</span>"
        "<span>CONFIDENTIAL · STRICTLY PRIVATE</span></div>"
        "</footer>"
    )
