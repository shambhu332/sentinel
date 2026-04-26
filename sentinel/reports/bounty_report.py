"""R_001 — HackerOne bounty report generator.

Produces submission-ready markdown reports for findings, with the structure
that HackerOne, Bugcrowd, and Intigriti reviewers expect:

1. Title (bold, descriptive, includes severity)
2. Summary (one paragraph, what & why it matters)
3. Steps to reproduce (numbered, includes exact curl/adb commands)
4. Proof of concept (raw evidence from the agent)
5. Impact (what an attacker can do with this)
6. Remediation (how to fix it)
7. References (CWE, OWASP MASVS, Firebase docs)

Reports are written to disk as markdown for easy copy-paste into the
bounty platform's submission form.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.finding import Finding, Severity

SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH: "🟠 High",
    Severity.MEDIUM: "🟡 Medium",
    Severity.LOW: "🔵 Low",
    Severity.INFO: "⚪ Informational",
}


# Per-vulnerability-class boilerplate. Maps `vuln_class` → reference data.
_CLASS_REFERENCES: dict[str, dict[str, Any]] = {
    "Firebase Misconfiguration": {
        "cwe": "CWE-284 (Improper Access Control)",
        "owasp_masvs": "MASVS-NETWORK-1, MASVS-STORAGE-2",
        "category": "Insecure Cloud Configuration",
        "references": [
            "https://firebase.google.com/docs/database/security",
            "https://mas.owasp.org/MASVS/05-MASVS-NETWORK/",
            "https://cwe.mitre.org/data/definitions/284.html",
        ],
        "default_impact": (
            "An unauthenticated remote attacker can read the entire contents of the "
            "Firebase Realtime Database. Depending on what the application stores there, "
            "this can expose user PII, authentication tokens, financial data, private "
            "messages, internal configuration, and any other application state. The "
            "leaked credentials may be re-used to attack other services."
        ),
    },
}


def generate_hackerone_report(
    finding: Finding,
    apk_package: str,
    apk_version: str,
    output_dir: Path,
    program_name: str = "(your bounty program)",
) -> Path:
    """Render a HackerOne-format markdown report and write it to disk.

    Returns the path to the generated report file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_id = finding.finding_id[:16]
    safe_class = finding.vuln_class.lower().replace(" ", "_")
    filename = f"{finding.agent_id}_{safe_class}_{safe_id}.md"
    report_path = output_dir / filename

    refs = _CLASS_REFERENCES.get(finding.vuln_class, {})

    sections: list[str] = []

    # ---------- Title and badges ----------
    sections.append(f"# {SEVERITY_BADGE[finding.severity]} — {finding.recommendation.split('.')[0][:80]}")
    sections.append("")
    sections.append(f"**Target:** `{apk_package}` (version {apk_version})")
    sections.append(f"**Program:** {program_name}")
    sections.append(f"**Severity:** {finding.severity.value}")
    sections.append(f"**Confidence:** {finding.confidence:.2f}")
    sections.append(f"**Detected by:** SENTINEL agent `{finding.agent_id}`")
    sections.append(f"**Vulnerability class:** {finding.vuln_class}")
    if refs.get("cwe"):
        sections.append(f"**CWE:** {refs['cwe']}")
    if refs.get("owasp_masvs"):
        sections.append(f"**OWASP MASVS:** {refs['owasp_masvs']}")
    sections.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    sections.append("")
    sections.append("---")
    sections.append("")

    # ---------- Summary ----------
    sections.append("## Summary")
    sections.append("")
    sections.append(_build_summary(finding, apk_package))
    sections.append("")

    # ---------- Steps to reproduce ----------
    sections.append("## Steps to Reproduce")
    sections.append("")
    for i, step in enumerate(_build_steps(finding, apk_package), start=1):
        sections.append(f"{i}. {step}")
    sections.append("")

    # ---------- Proof of concept ----------
    sections.append("## Proof of Concept")
    sections.append("")
    sections.append("Evidence captured by the SENTINEL agent during static and dynamic analysis:")
    sections.append("")
    sections.append("```json")
    sections.append(json.dumps(finding.evidence, indent=2, default=str))
    sections.append("```")
    sections.append("")

    # ---------- Impact ----------
    sections.append("## Impact")
    sections.append("")
    sections.append(refs.get("default_impact", _generic_impact(finding)))
    sections.append("")

    # ---------- Remediation ----------
    sections.append("## Remediation")
    sections.append("")
    sections.append(finding.recommendation)
    sections.append("")

    # ---------- References ----------
    if refs.get("references"):
        sections.append("## References")
        sections.append("")
        for ref in refs["references"]:
            sections.append(f"- {ref}")
        sections.append("")

    # ---------- Footer ----------
    sections.append("---")
    sections.append("")
    sections.append(
        f"_This report was generated automatically by SENTINEL "
        f"(finding ID `{finding.finding_id}`). "
        f"Please verify all evidence independently before submission. "
        f"Verify the target is in scope and that the testing techniques "
        f"used are permitted by the bug bounty program rules._"
    )
    sections.append("")

    report_path.write_text("\n".join(sections), encoding="utf-8")
    return report_path


def _build_summary(finding: Finding, package: str) -> str:
    """Class-aware summary paragraph."""
    if finding.vuln_class == "Firebase Misconfiguration":
        evidence = finding.evidence
        return (
            f"The Android application `{package}` embeds a Firebase Realtime Database "
            f"endpoint at `{evidence.get('url', '<unknown>')}`. "
            f"This endpoint is publicly readable without authentication: a single "
            f"unauthenticated HTTPS GET request to `{evidence.get('probe_endpoint', '')}` "
            f"returns the contents of the database (HTTP "
            f"{evidence.get('http_status', 'unknown')}). "
            f"This allows any internet user to retrieve all data stored in the database "
            f"including any PII, credentials, or business data the application has saved."
        )
    return (
        f"SENTINEL detected a {finding.vuln_class} issue in `{package}`. "
        f"Confidence: {finding.confidence:.0%}."
    )


def _build_steps(finding: Finding, package: str) -> list[str]:
    """Class-aware reproduction steps."""
    if finding.vuln_class == "Firebase Misconfiguration":
        url = finding.evidence.get("url", "")
        probe = finding.evidence.get("probe_endpoint", url + "/.json")
        files = finding.evidence.get("discovered_in_files", [])
        return [
            f"Download or obtain the APK file for `{package}`.",
            (f"Decompile the APK using JADX or apktool. The Firebase URL is referenced in: "
             f"`{', '.join(files[:3]) if files else '(see evidence above)'}`."),
            (f"Confirm the URL: `{url}`. This is the application's Firebase Realtime "
             f"Database backend."),
            ("Send an unauthenticated HTTPS GET request to the database root with "
             "`/.json` appended:"),
            f"```bash\ncurl -s '{probe}'\n```",
            ("Observe that the request returns HTTP 200 with the full database contents "
             "as a JSON payload, with no authentication required."),
            ("Inspect the returned data — any PII, credentials, or business data visible "
             "in the response confirms the impact."),
        ]
    return [
        "Reproduce the issue using the evidence in this report.",
        f"Inspect application package: `{package}`.",
    ]


def _generic_impact(finding: Finding) -> str:
    """Fallback impact paragraph for vulnerability classes we don't have boilerplate for."""
    return (
        f"This {finding.vuln_class} finding was detected with "
        f"{finding.confidence:.0%} confidence. The specific impact depends on the "
        f"data and operations exposed by the vulnerability — refer to the evidence "
        f"section for details that an attacker could exploit."
    )
