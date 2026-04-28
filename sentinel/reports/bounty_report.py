"""R_001 — HackerOne bounty report generator.

Produces submission-ready markdown reports for findings, with the structure
that HackerOne, Bugcrowd, and Intigriti reviewers expect:

1. Title (bold, descriptive, includes severity)
2. Summary (one paragraph, what & why it matters)
3. Steps to reproduce (numbered, includes exact curl/adb commands)
4. Proof of concept (raw evidence from the agent)
5. Impact (what an attacker can do with this)
6. Remediation (how to fix it)
7. References (CWE, OWASP MASVS, vendor docs)

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
    "Exposed Content Provider": {
        "cwe": "CWE-926 (Improper Export of Android Components)",
        "owasp_masvs": "MASVS-PLATFORM-1, MASVS-CODE-2",
        "category": "Insecure Inter-Process Communication",
        "references": [
            "https://developer.android.com/guide/topics/providers/content-provider-creating",
            "https://mas.owasp.org/MASVS/06-MASVS-PLATFORM/",
            "https://cwe.mitre.org/data/definitions/926.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
        "default_impact": (
            "Any app installed on the device can interact with this Content Provider "
            "without holding any special permissions. Depending on the provider's "
            "implementation, this enables one or more of: dumping the application's "
            "private database tables (PII, credentials, payment records); injecting "
            "arbitrary SQL through unsanitised selection arguments; reading arbitrary "
            "files inside the app's sandbox via openFile() path traversal. A malicious "
            "app on the device requires no user interaction and no permission grants "
            "to perform these queries — the exposed provider is the entire vulnerability."
        ),
    },
    "Cleartext Traffic": {
        "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
        "owasp_masvs": "MASVS-NETWORK-1",
        "category": "Insecure Network Communication",
        "references": [
            "https://developer.android.com/training/articles/security-config",
            "https://mas.owasp.org/MASVS/05-MASVS-NETWORK/",
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
        "default_impact": (
            "An attacker on the same network as the user (public WiFi, compromised "
            "router, malicious ISP, hostile cellular base station) can intercept all "
            "HTTP traffic in plaintext. This includes session tokens, authentication "
            "credentials, personal data, and any business logic transmitted by the app. "
            "The attacker can also actively modify traffic to inject malicious responses, "
            "downgrade security, or redirect the user to attacker-controlled servers."
        ),
    },
    "Hardcoded Secret": {
        "cwe": "CWE-798 (Use of Hard-coded Credentials)",
        "owasp_masvs": "MASVS-CODE-4, MASVS-AUTH-2",
        "category": "Credential Management",
        "references": [
            "https://mas.owasp.org/MASVS/07-MASVS-CODE/",
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html",
        ],
        "default_impact": (
            "The credential is embedded in the application binary and is recoverable "
            "by anyone who can download the APK from the Play Store. Depending on the "
            "credential type, this can expose cloud infrastructure (AWS, GCP), allow "
            "the attacker to charge customers (Stripe), send messages from the company "
            "(Twilio, Slack, SendGrid), or impersonate the app to its backend services. "
            "The credential should be considered compromised the moment the affected "
            "app version was published."
        ),
    },
    "World-Readable Storage": {
        "cwe": "CWE-732 (Incorrect Permission Assignment for Critical Resource)",
        "owasp_masvs": "MASVS-STORAGE-1, MASVS-PLATFORM-2",
        "category": "Insecure Local Data Storage",
        "references": [
            "https://developer.android.com/topic/security/data",
            "https://mas.owasp.org/MASVS/03-MASVS-STORAGE/",
            "https://cwe.mitre.org/data/definitions/732.html",
        ],
        "default_impact": (
            "Files stored with MODE_WORLD_READABLE are accessible to any other "
            "application installed on the device, without any permissions or user "
            "interaction. If those files contain authentication tokens, session "
            "cookies, personal data, or business secrets, a malicious app on the same "
            "device can exfiltrate them silently. MODE_WORLD_WRITEABLE is even worse "
            "— other apps can modify the data, potentially injecting payloads that "
            "the target app trusts on next read."
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
    if finding.vuln_class == "Exposed Content Provider":
        evidence = finding.evidence
        provider = evidence.get("provider", "<unknown>")
        guard_state = ("with no permission guard" if not evidence.get("has_any_guard")
                       else "with a permission guard that may be holdable by attacker apps")
        return (
            f"The Android application `{package}` exports a Content Provider "
            f"`{provider}` {guard_state}. Exported Content Providers are an "
            f"inter-process communication endpoint accessible to every other "
            f"application installed on the device. The implementation contains "
            f"{evidence.get('sqli_indicators_found', 0)} SQL injection indicator(s); "
            f"openFile() is "
            f"{'risky' if evidence.get('openfile_risky') else 'not flagged'}; "
            f"unrestricted full-table dump is "
            f"{'present' if evidence.get('full_dump_risky') else 'not detected'}. "
            f"A malicious app on the device can interact with this provider "
            f"without user interaction or permission prompts."
        )
    if finding.vuln_class == "Cleartext Traffic":
        evidence = finding.evidence
        manifest_flag = evidence.get("manifest_uses_cleartext_traffic")
        url_count = evidence.get("http_urls_count", 0)
        return (
            f"The Android application `{package}` is configured to allow unencrypted "
            f"HTTP network traffic. "
            f"{'The manifest sets android:usesCleartextTraffic=\"true\", which globally permits HTTP. ' if manifest_flag else ''}"
            f"{f'The decompiled code contains {url_count} hardcoded http:// URL(s). ' if url_count else ''}"
            f"An attacker positioned on the user's network (public WiFi, compromised "
            f"router, or hostile ISP) can read or modify all such traffic, including "
            f"any session tokens, credentials, or sensitive data the application "
            f"transmits over HTTP."
        )
    if finding.vuln_class == "Hardcoded Secret":
        evidence = finding.evidence
        provider = evidence.get("provider", "credential")
        return (
            f"The Android application `{package}` ships with a hardcoded {provider} "
            f"embedded as a string constant in the application binary. "
            f"{evidence.get('match_count', 1)} instance(s) were found across the "
            f"decompiled source and resources. Anyone who downloads the APK from "
            f"the Play Store (or any APK mirror) can extract this credential by "
            f"running JADX or apktool against the file — no authentication, "
            f"reverse-engineering skill, or device access is required."
        )
    if finding.vuln_class == "World-Readable Storage":
        evidence = finding.evidence
        by_kind = evidence.get("by_kind", {})
        kind_summary = ", ".join(f"{k}: {v}" for k, v in by_kind.items())
        return (
            f"The Android application `{package}` uses deprecated and insecure "
            f"file-permission modes when persisting data to local storage. "
            f"Detected indicators: {kind_summary}. Files stored with these modes "
            f"are accessible to any other application on the same device, without "
            f"any permission prompts or user interaction. On older Android versions "
            f"(below API 24) this exposes the data; on newer versions the call "
            f"throws SecurityException and likely crashes the affected feature."
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
            (f"Send an unauthenticated HTTPS GET request to the database root with "
             f"`/.json` appended:"),
            f"```bash\ncurl -s '{probe}'\n```",
            ("Observe that the request returns HTTP 200 with the full database contents "
             "as a JSON payload, with no authentication required."),
            ("Inspect the returned data — any PII, credentials, or business data visible "
             "in the response confirms the impact."),
        ]
    if finding.vuln_class == "Exposed Content Provider":
        provider = finding.evidence.get("provider", "")
        provider_lower = provider.lower()
        source_file = finding.evidence.get("source_file") or "(see evidence)"
        return [
            f"Install the target application `{package}` on a test device or emulator.",
            (f"Inspect AndroidManifest.xml of the application — the provider "
             f"`{provider}` is declared with `android:exported=\"true\"` and "
             f"with no permission attributes."),
            (f"Decompile the APK and inspect the provider implementation in "
             f"`{source_file}`."),
            "From any test app on the same device (or via adb shell), query the provider:",
            f"```bash\nadb shell content query --uri content://{provider_lower}/\n```",
            ("Observe that the query returns rows from the application's private "
             "database without any authentication."),
            ("If the implementation builds raw SQL using the `selection` argument, "
             "test SQL injection by passing a malicious selection:"),
            (f"```bash\nadb shell content query --uri content://{provider_lower}/ "
             f"--where \"1=1) UNION SELECT name,sql FROM sqlite_master WHERE (1=1\"\n```"),
        ]
    if finding.vuln_class == "Cleartext Traffic":
        evidence = finding.evidence
        url_samples = evidence.get("http_urls_sample", [])
        first_url = url_samples[0]["url"] if url_samples else "http://example.com/api"
        return [
            f"Decompile the APK for `{package}` using apktool: `apktool d {package}.apk`.",
            (f"Inspect AndroidManifest.xml — note `android:usesCleartextTraffic=\"true\"` "
             f"on the <application> element."
             if evidence.get("manifest_uses_cleartext_traffic")
             else "Inspect the decompiled source for hardcoded http:// URLs."),
            (f"Confirm hardcoded http:// URLs in the decompiled code "
             f"({evidence.get('http_urls_count', 0)} found). Examples:"),
            "```",
            *[f"  {u['url']}  (in {u['locations'][0] if u['locations'] else '?'})"
              for u in url_samples[:5]],
            "```",
            ("Set up a transparent proxy (e.g., mitmproxy with `mitmproxy --mode "
             "transparent`) on a test network."),
            "Connect the target device to that network and run the application normally.",
            (f"Observe HTTP traffic to {first_url} (or similar) flowing in plaintext "
             f"through the proxy. The proxy can both read and modify this traffic."),
            ("Confirm impact: identify any session tokens, credentials, or sensitive "
             "data visible in the captured plaintext traffic."),
        ]
    if finding.vuln_class == "Hardcoded Secret":
        evidence = finding.evidence
        provider = evidence.get("provider", "secret")
        sample_files = [m.get("file", "?") for m in evidence.get("matches", [])]
        return [
            f"Download the APK for `{package}` from Google Play (or any APK mirror).",
            f"Decompile the APK using JADX: `jadx -d output {package}.apk`",
            (f"Search the decompiled source for {provider} references. SENTINEL "
             f"detected matches in: {', '.join(sample_files[:3]) if sample_files else '(see evidence)'}."),
            (f"Verify the {provider} matches the expected pattern by inspecting "
             f"the redacted samples in this report's evidence section."),
            (f"Use the credential against the affected service to confirm it is "
             f"valid (only do this if explicitly permitted by the bounty program "
             f"rules — credential validation is sometimes restricted)."),
            ("Document the impact: what data, accounts, or actions does this "
             "credential authorise?"),
        ]
    if finding.vuln_class == "World-Readable Storage":
        evidence = finding.evidence
        sample_hits = evidence.get("hits", [])
        return [
            f"Install the target application `{package}` on a test device with API < 24 "
            "(world-* modes throw SecurityException on API 24+, but data files "
            "created in older versions persist).",
            "Decompile the APK and locate the insecure storage calls. SENTINEL detected:",
            "```",
            *[f"  {h.get('file', '?')}: {h.get('matched', '?')}" for h in sample_hits[:5]],
            "```",
            "Run the application normally so the affected files are created.",
            ("Install a second test app on the same device, and from that app "
             "(or via adb shell) read the target's data directory:"),
            f"```bash\nadb shell run-as {package} ls -la /data/data/{package}/\n```",
            ("Files marked with mode 0644 / 0666 are accessible to other apps. "
             "Confirm the file contents — if any contain session tokens, credentials, "
             "or PII, this is a complete credential leak."),
        ]
    return [
        f"Reproduce the issue using the evidence in this report.",
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