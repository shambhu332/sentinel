"""Per-finding narrative enrichment for the VAPT advisory template.

For every finding we want the report to look like a Bishop-Fox / NCC
advisory: a short prose summary, an explicit reproduction recipe, an
impact bullet list, a fix bullet list, and a reference list. Agents
themselves only emit a short evidence dict, so this module fills in
the prose layer.

Strategy:

1. Try ``FreeProviderRouter.query_json`` (Groq → Cerebras → Ollama).
   The prompt asks for a strict JSON object that maps cleanly onto
   :class:`FindingSection.narrative`.

2. If every provider fails (no API key, circuit open, parse error,
   etc.) we fall back to a *deterministic* boilerplate keyed by
   ``Finding.agent_id``. The boilerplate is honest — it never invents
   PoCs we don't have evidence for.

The renderer reads ``section.narrative`` if present and otherwise
degrades to evidence-only output.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.reporting.models import FindingSection
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_DEFAULT_IMPACT_BY_SEVERITY: dict[Severity, list[str]] = {
    Severity.CRITICAL: [
        "Full compromise of the affected component is feasible from an "
        "unprivileged caller.",
        "Account takeover, credential theft, or persistent backdoor on "
        "the device user is realistic.",
    ],
    Severity.HIGH: [
        "An attacker can extract sensitive data or bypass a security "
        "control without elevated privileges.",
        "Materially weakens the app's trust boundary against a "
        "co-installed or remote attacker.",
    ],
    Severity.MEDIUM: [
        "Degrades the application's defence-in-depth.",
        "Useful reconnaissance for a longer exploit chain.",
    ],
    Severity.LOW: [
        "Low-impact misconfiguration; informational defence-in-depth "
        "regression.",
    ],
    Severity.INFO: [
        "Informational observation with no direct attacker capability.",
    ],
}


_SYSTEM_PROMPT = (
    "You are a senior mobile security consultant writing a one-page "
    "advisory for a Bishop-Fox / NCC-style VAPT report. You will "
    "expand a single finding into a strict JSON object. Be precise, "
    "concrete, and do not invent file paths, line numbers, PoC URLs, "
    "or CVEs that are not present in the input. If you do not have "
    "evidence for a field, write \"\" or [] — never fabricate."
)

_USER_TEMPLATE = """\
Finding to expand:

  agent_id:       {agent_id}
  vuln_class:     {vuln_class}
  severity:       {severity}
  owasp:          {owasp}
  masvs:          {masvs}
  cvss_vector:    {cvss}
  recommendation: {recommendation}
  triage:         {triage}
  evidence_keys:  {evidence_keys}
  evidence_json:  {evidence_json}

Return ONLY a JSON object with these keys:

  summary:             4-6 sentences of consultancy-grade prose
                       explaining the bug class, why it matters in this
                       app, and the attacker prerequisites.
  affected_components: array of strings (file paths, class names,
                       manifest entries) drawn ONLY from the evidence.
                       Empty array if none.
  evidence_notes:      1-3 sentence walk-through of what the scanner
                       actually saw, citing the keys from evidence_json.
  repro_steps:         array of imperative steps a reviewer could run
                       on a test device to confirm. Do not invent URLs.
  poc_snippet:         a short, runnable snippet (adb command, Java
                       fragment, manifest XML) that demonstrates the
                       bug. Empty string if not safe to invent.
  impact_bullets:      array of 2-4 short bullets describing concrete
                       attacker capability.
  fix_bullets:         array of 2-4 imperative bullets, code-level.
  references:          array of objects {{"label": str, "url": str}}.
                       Include the canonical OWASP MASTG, CWE, and
                       Android-developer doc URLs relevant to this bug.

Return nothing else. No prose outside the JSON.
"""


async def enrich_section(
    section: FindingSection,
    router: Any,  # FreeProviderRouter | None
) -> None:
    """Populate ``section.narrative`` in-place.

    ``router`` may be None or any object with ``query_json``. When the
    LLM path fails for any reason we degrade to ``_fallback_narrative``.
    """
    if section.narrative:
        return

    if router is not None:
        try:
            data = await _query_router(router, section.finding)
            if isinstance(data, dict) and data.get("summary"):
                section.narrative = _coerce_narrative(data, section.finding)
                return
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "enrich: router failed for %s — falling back (%s)",
                section.finding.agent_id, exc,
            )

    section.narrative = _fallback_narrative(section.finding)


async def enrich_sections(
    sections: list[FindingSection],
    router: Any,
) -> None:
    """Enrich every section serially; cheaper providers don't tolerate
    bursty parallel load and most reports have <30 findings."""
    for s in sections:
        await enrich_section(s, router)


# ---------- internals ----------


async def _query_router(router: Any, finding: Finding) -> dict:
    import json
    evidence = finding.evidence or {}
    user_msg = _USER_TEMPLATE.format(
        agent_id=finding.agent_id,
        vuln_class=finding.vuln_class,
        severity=finding.severity.name if hasattr(finding.severity, "name")
                 else str(finding.severity),
        owasp=finding.owasp or "—",
        masvs=finding.masvs or "—",
        cvss=finding.cvss_vector or "n/a",
        recommendation=finding.recommendation or "—",
        triage="",
        evidence_keys=list(evidence.keys()) if isinstance(evidence, dict)
                     else "—",
        evidence_json=json.dumps(evidence, default=str)[:2000],
    )
    result = await router.query_json(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        tier="T2",
    )
    return result.get("content") or {}


def _coerce_narrative(data: dict, finding: Finding) -> dict:
    """Validate types, fill missing fields from deterministic fallback."""
    fb = _fallback_narrative(finding)
    out = {
        "summary": _str(data.get("summary"), fb["summary"]),
        "affected_components": _strlist(
            data.get("affected_components"), fb["affected_components"],
        ),
        "evidence_notes": _str(data.get("evidence_notes"), fb["evidence_notes"]),
        "repro_steps": _strlist(data.get("repro_steps"), fb["repro_steps"]),
        "poc_snippet": _str(data.get("poc_snippet"), fb["poc_snippet"]),
        "impact_bullets": _strlist(
            data.get("impact_bullets"), fb["impact_bullets"],
        ),
        "fix_bullets": _strlist(data.get("fix_bullets"), fb["fix_bullets"]),
        "references": _reflist(data.get("references"), fb["references"]),
    }
    return out


def _str(v: Any, default: str) -> str:
    if isinstance(v, str) and v.strip():
        return v.strip()
    return default


def _strlist(v: Any, default: list[str]) -> list[str]:
    if isinstance(v, list):
        out = [str(x).strip() for x in v if str(x).strip()]
        if out:
            return out
    return default


def _reflist(v: Any, default: list[dict]) -> list[dict]:
    if isinstance(v, list):
        out: list[dict] = []
        for x in v:
            if isinstance(x, dict) and x.get("url"):
                out.append({
                    "label": str(x.get("label") or x["url"]),
                    "url": str(x["url"]),
                })
        if out:
            return out
    return default


# ---------- deterministic fallback ----------


_BOILERPLATE: dict[str, dict[str, Any]] = {
    "P_001": {
        "summary": (
            "The application registers a custom URI scheme on an "
            "exported activity. Custom URI schemes cannot be verified "
            "on Android: only ``https://`` filters paired with a hosted "
            "``assetlinks.json`` benefit from the autoVerify attribute. "
            "Any other installed application can register the same "
            "scheme, and the Android system will surface a chooser the "
            "user has a 50/50 chance of resolving the wrong way."
        ),
        "repro_steps": [
            "Build a tiny attacker app whose manifest declares the same "
            "scheme/host on an exported activity.",
            "Sideload both the target app and the attacker app on a "
            "test device.",
            "Fire the deep link from a web page or `adb shell am start "
            "-a android.intent.action.VIEW -d <uri>`.",
            "Observe Android's chooser dialog or, when the attacker app "
            "has higher priority, silent capture of the URI.",
        ],
        "poc_snippet": (
            "adb shell am start -a android.intent.action.VIEW "
            "-d \"<scheme>://<host>/path?token=ABC123\""
        ),
        "impact_bullets": [
            "Capture of one-time URIs (password reset, magic login, "
            "OAuth callbacks).",
            "Hijack of affiliate / referral parameters.",
            "Input vector for a downstream WebView / open-redirect chain.",
        ],
        "fix_bullets": [
            "Move sensitive deep links to verified HTTPS App Links "
            "(`autoVerify=\"true\"` + `/.well-known/assetlinks.json`).",
            "Validate the URI against a canonical allow-list before "
            "persisting or routing it.",
            "Never carry tokens in a custom-scheme URI.",
        ],
        "references": [
            {"label": "Android App Links",
             "url": "https://developer.android.com/training/app-links"},
            {"label": "Digital Asset Links",
             "url": "https://developers.google.com/digital-asset-links"},
            {"label": "CWE-940",
             "url": "https://cwe.mitre.org/data/definitions/940.html"},
        ],
    },
    "A_001": {
        "summary": (
            "Authentication tokens are persisted to plain file or "
            "shared-preferences storage. Any backup, ADB pull from a "
            "rooted device, or co-resident app with the right "
            "permission can read these tokens and impersonate the user."
        ),
        "repro_steps": [
            "On a rooted or emulator device, run `adb shell run-as "
            "<pkg> cat shared_prefs/<file>.xml`.",
            "Confirm a bearer / refresh token value is present in "
            "cleartext.",
        ],
        "poc_snippet": "adb shell run-as <pkg> cat shared_prefs/<file>.xml",
        "impact_bullets": [
            "Account takeover via stolen bearer / refresh tokens.",
            "Persistent compromise across token rotation if refresh "
            "tokens are captured.",
        ],
        "fix_bullets": [
            "Store secrets in the Android Keystore.",
            "Use EncryptedSharedPreferences with a Keystore-bound key.",
            "Disable Auto Backup for credential files via "
            "`android:allowBackup=\"false\"` or a `backup_rules.xml` "
            "exclusion.",
        ],
        "references": [
            {"label": "MASVS-STORAGE-1",
             "url": "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/"},
            {"label": "Android Keystore",
             "url": "https://developer.android.com/training/articles/keystore"},
        ],
    },
    "B_002": {
        "summary": (
            "The application uses `java.util.Random` or `Math.random()` "
            "for what looks like a security-relevant value. These "
            "generators are predictable from a single observed output."
        ),
        "repro_steps": [
            "Observe one token / nonce produced by the application.",
            "Seed a local `java.util.Random` with the observed value "
            "and predict subsequent outputs.",
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Predictable session identifiers or password-reset tokens.",
            "Trivial brute-force where the entropy was assumed adequate.",
        ],
        "fix_bullets": [
            "Replace with `java.security.SecureRandom`.",
            "For key material, derive via `KeyGenerator` /  "
            "`KeyPairGenerator`.",
        ],
        "references": [
            {"label": "CWE-330",
             "url": "https://cwe.mitre.org/data/definitions/330.html"},
        ],
    },
    "N_002": {
        "summary": (
            "The application allows cleartext HTTP traffic. Any network "
            "attacker (rogue Wi-Fi, captive portal, ISP) can intercept "
            "or modify the traffic in transit."
        ),
        "repro_steps": [
            "Place the device on a Wi-Fi network you control with "
            "mitmproxy / Burp acting as the gateway.",
            "Observe HTTP requests originating from the app.",
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Credential and session-cookie interception.",
            "Response tampering enabling further client-side exploits.",
        ],
        "fix_bullets": [
            "Set `android:usesCleartextTraffic=\"false\"`.",
            "Pin TLS certificates for high-value endpoints via "
            "Network Security Config.",
        ],
        "references": [
            {"label": "Network Security Configuration",
             "url": "https://developer.android.com/training/articles/security-config"},
        ],
    },
    "P_010": {
        "summary": (
            "The app forwards an attacker-controllable Intent through "
            "`startActivity` without validating its target. A malicious "
            "caller can re-target the inner Intent at a private "
            "component to bypass export restrictions (CWE-926)."
        ),
        "repro_steps": [
            "From an attacker app, construct an outer Intent for the "
            "vulnerable activity with an inner Intent extra pointing "
            "at the target component.",
            "Start the outer Intent and observe the private component "
            "being launched with attacker-controlled extras.",
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Bypass of `android:exported=false` on internal screens.",
            "Pivot into authenticated flows from an unprivileged caller.",
        ],
        "fix_bullets": [
            "Strip the forwarded Intent's component / package / data.",
            "Validate the target against an allow-list before launching.",
        ],
        "references": [
            {"label": "CWE-926",
             "url": "https://cwe.mitre.org/data/definitions/926.html"},
        ],
    },
}


def _fallback_narrative(finding: Finding) -> dict:
    bp = _BOILERPLATE.get(finding.agent_id, {})
    evidence = finding.evidence or {}

    summary = bp.get("summary") or (
        finding.evidence.get("issue")
        if isinstance(evidence, dict) and evidence.get("issue") else None
    ) or (
        f"{finding.vuln_class}: the scanner identified a "
        f"{finding.severity.name.lower() if hasattr(finding.severity, 'name') else 'security'} "
        f"-relevant code or configuration pattern that warrants review."
    )

    affected: list[str] = []
    if isinstance(evidence, dict):
        for key in ("file", "files", "activity", "component", "class",
                    "manifest", "smali", "path", "location"):
            v = evidence.get(key)
            if isinstance(v, str):
                affected.append(v)
            elif isinstance(v, list):
                affected.extend(str(x) for x in v if x)

    evidence_notes = ""
    if isinstance(evidence, dict) and evidence:
        keys = list(evidence.keys())[:6]
        evidence_notes = (
            "Scanner evidence captured the following keys: "
            + ", ".join(f"``{k}``" for k in keys)
            + ". See the Evidence in the APK section for the raw payload."
        )

    repro = bp.get("repro_steps") or [
        "Pull the APK with `apkanalyzer` or `apktool d`.",
        "Locate the affected component listed above and confirm the "
        "scanner's pattern matches against the decompiled source.",
        "Where applicable, exercise the code path on a test device "
        "with `adb shell` or a small attacker app.",
    ]
    poc = bp.get("poc_snippet", "")
    impact = (
        bp.get("impact_bullets")
        or _DEFAULT_IMPACT_BY_SEVERITY.get(finding.severity, [])
    )

    fix_bullets = bp.get("fix_bullets")
    if not fix_bullets and finding.recommendation:
        # Split a long recommendation into bullets on '. ' boundaries.
        chunks = [
            c.strip().rstrip(".") + "."
            for c in finding.recommendation.split(". ") if c.strip()
        ]
        fix_bullets = chunks[:6] or [finding.recommendation]

    refs = list(bp.get("references", []))
    # Always add the OWASP/MASVS/CWE canonical URLs when present.
    if finding.owasp and "OWASP" not in " ".join(r["label"] for r in refs):
        refs.append({"label": finding.owasp,
                     "url": "https://mas.owasp.org/MASVS/"})
    if finding.masvs:
        refs.append({"label": finding.masvs,
                     "url": "https://mas.owasp.org/MASTG/"})

    return {
        "summary": summary,
        "affected_components": affected,
        "evidence_notes": evidence_notes,
        "repro_steps": repro,
        "poc_snippet": poc,
        "impact_bullets": impact,
        "fix_bullets": fix_bullets or [finding.recommendation or ""],
        "references": refs,
    }
