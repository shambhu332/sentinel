"""SARIF v2.1.0 exporter.

SARIF is the format GitHub Code Scanning, Azure DevOps, and most major
SAST aggregators consume. Shipping it lets SENTINEL findings flow
straight into the security tab of any GitHub repo whose CI pipeline
calls our CLI — no sales motion, no integration code on their side.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

The renderer is intentionally narrow:

* One ``run`` per scan, one ``tool`` (SENTINEL).
* One ``result`` per Finding, with ``ruleId`` = AGENT_ID and
  ``level`` mapped from Severity.
* Locations carry the decompiled file:line where available; falls
  back to the APK basename so result aggregation still groups
  correctly.
* CVSS is emitted under ``properties.security-severity`` (the field
  GitHub uses to set its own severity column).

This is a pure renderer — no IO, no LLM, no agents. The R_001 report
agent calls it after building its ``ReportData``.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sentinel.core.finding import Finding, Severity

# SARIF level mapping per spec §3.27.10.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}


def _rule_for(finding: Finding) -> dict[str, Any]:
    tags = ["security", "mobile", "android", finding.agent_id.split("_")[0]]
    for tag in finding.source_tags or []:
        slug = str(tag).lower().replace(" ", "-")
        if slug and slug not in tags:
            tags.append(slug)
    return {
        "id": finding.agent_id,
        "name": finding.vuln_class.replace(" ", ""),
        "shortDescription": {"text": finding.vuln_class},
        "fullDescription": {"text": finding.recommendation or finding.vuln_class},
        "defaultConfiguration": {
            "level": _LEVEL.get(finding.severity, "note"),
        },
        "properties": {
            "tags": tags,
            "precision": "high" if finding.confidence and finding.confidence >= 0.75 else "medium",
        },
        "helpUri": "https://owasp.org/www-project-mobile-application-security/",
    }


def _result_for(finding: Finding) -> dict[str, Any]:
    ev = finding.evidence or {}
    # Prefer the new code_snippet hint for file/line if present — it points
    # at the precise offending line rather than a vague evidence dict key.
    snippet = finding.code_snippet or {}
    file_path = (
        snippet.get("file")
        or ev.get("file")
        or ev.get("path")
        or "AndroidManifest.xml"
    )
    line = int(snippet.get("line", ev.get("line", 1)) or 1)
    region: dict[str, Any] = {"startLine": max(1, line)}
    if snippet.get("start_col") is not None:
        region["startColumn"] = int(snippet["start_col"]) + 1
    if snippet.get("end_col") is not None:
        region["endColumn"] = int(snippet["end_col"]) + 1
    if snippet.get("content"):
        region["snippet"] = {"text": str(snippet["content"])[:2000]}

    cvss_score = ev.get("cvss_v3_score")
    properties: dict[str, Any] = {
        "evidence_keys": sorted(list(ev.keys())),
    }
    if cvss_score is not None:
        # GitHub Code Scanning reads this field to colour-grade the severity column.
        properties["security-severity"] = str(cvss_score)
    if getattr(finding, "cvss_vector", None):
        properties["cvss_vector"] = finding.cvss_vector

    # Djini-style enrichment — surfaced as SARIF properties so consumers
    # can render the same narrative the SENTINEL UI shows.
    if finding.severity_rationale:
        properties["severity_rationale"] = finding.severity_rationale
    if finding.verification_status:
        properties["verification_status"] = finding.verification_status
    if finding.source_tags:
        properties["source_tags"] = list(finding.source_tags)
    if finding.reproduction_commands:
        properties["reproduction_commands"] = list(finding.reproduction_commands)
    if finding.observed_result:
        properties["observed_result"] = finding.observed_result
    if finding.code_snippets:
        properties["code_snippets"] = [
            {k: s.get(k) for k in ("label", "file", "line", "content") if k in s}
            for s in finding.code_snippets
        ]

    # Prefer the runtime-observed narrative as the message text — it's the
    # single most useful sentence a triage reviewer can read.
    message_text = (
        finding.observed_result
        or finding.recommendation
        or finding.vuln_class
    )

    return {
        "ruleId": finding.agent_id,
        "level": _LEVEL.get(finding.severity, "note"),
        "message": {"text": message_text},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": str(file_path).replace("\\", "/")},
                "region": region,
            },
        }],
        "fingerprints": {
            "sentinel/v1": finding.finding_id,
        },
        "partialFingerprints": {
            "sentinel/agent+vuln+file": (
                f"{finding.agent_id}|{finding.vuln_class}|{file_path}"
            ),
        },
        "properties": properties,
    }


def render_sarif(
    findings: list[Finding],
    session_id: str,
    tool_version: str = "0.x",
) -> dict[str, Any]:
    """Build a SARIF v2.1.0 log document for ``findings``."""
    seen_rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        if f.agent_id not in seen_rules:
            seen_rules[f.agent_id] = _rule_for(f)
        results.append(_result_for(f))

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SENTINEL",
                    "version": tool_version,
                    "informationUri": "https://github.com/shambhu332/sentinel",
                    "rules": list(seen_rules.values()),
                },
            },
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat()
                                .replace("+00:00", "Z"),
                "properties": {"session_id": session_id},
            }],
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }


def render_sarif_json(findings: list[Finding], session_id: str,
                      tool_version: str = "0.x") -> str:
    """Serialise the SARIF log as a JSON string."""
    return json.dumps(
        render_sarif(findings, session_id, tool_version),
        indent=2,
        ensure_ascii=False,
    )


__all__ = ["render_sarif", "render_sarif_json"]
