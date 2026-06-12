"""PRIV_001 — Sensitive data collection auditor.

Scans for code paths that read identifiers, location, or contacts
*before* any consent UI has been presented. Heuristic, not a formal
flow analysis: we look at which Activity hosts the call and compare it
against the manifest's MAIN/LAUNCHER activity. If the sensitive call
lives in an activity reachable before any consent fragment / dialog
class is referenced, we flag.

Why this matters: regulators (GDPR Art. 6, CCPA, India DPDP) treat
pre-consent collection of identifiers as the highest-priority class
of violation, and the fines scale with the volume of users.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Sensitive API patterns. Severity bands chosen for headline impact:
# IMEI/AndroidID are persistent identifiers — Critical/High. Location
# is High. Ad ID is Medium. Contacts is Medium.
_SENSITIVE_APIS: list[tuple[str, re.Pattern, Severity, str]] = [
    (
        "Device IMEI / IMSI",
        re.compile(
            r"TelephonyManager\s*\.\s*"
            r"(getDeviceId|getImei|getMeid|getSubscriberId)\s*\("
        ),
        Severity.HIGH,
        "Device IMEI/IMSI is a permanent hardware identifier. Use a "
        "first-party UUID stored in app preferences instead; collection "
        "without explicit consent violates GDPR/DPDP.",
    ),
    (
        "Android ID",
        re.compile(r"Settings\.Secure\.ANDROID_ID"),
        Severity.MEDIUM,
        "ANDROID_ID is per-app-signing-key since Android 8 but still a "
        "device-stable identifier. Surface a consent UI before reading.",
    ),
    (
        "Coarse / Fine Location",
        re.compile(
            r"LocationManager|FusedLocationProviderClient|getLastLocation"
        ),
        Severity.HIGH,
        "Location reads must be preceded by an explicit consent prompt "
        "describing the purpose. Background location requires the "
        "separate ACCESS_BACKGROUND_LOCATION runtime grant.",
    ),
    (
        "Advertising ID",
        re.compile(r"AdvertisingIdClient(\.Info)?\.getId\b"),
        Severity.MEDIUM,
        "AdvertisingIdClient should not be invoked before the user has "
        "agreed to ad personalisation. Google Play policy and DPDP both "
        "require explicit opt-in.",
    ),
    (
        "Contacts",
        re.compile(r"ContactsContract\.CommonDataKinds|READ_CONTACTS"),
        Severity.MEDIUM,
        "Reading the contact book is one of the highest-sensitivity "
        "operations on the device. Consent must be granular and "
        "purpose-bound.",
    ),
]

# Tokens that indicate a consent surface is somewhere in the class
_CONSENT_HINTS = (
    "consent", "Consent", "CONSENT",
    "Cmp", "OneTrust", "Didomi", "CookieConsent",
    "PrivacyPolicy", "privacyPolicy", "PRIVACY_POLICY",
    "TermsOf", "termsOf", "GdprDialog", "ConsentForm",
)

_MAX_FILES = 2000


class DataCollectionAuditorAgent(BaseAgent):
    """PRIV_001: flags pre-consent collection of sensitive identifiers."""

    AGENT_ID = "PRIV_001"
    VULN_CLASS = "Pre-Consent Sensitive Data Collection"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        # Identify the LAUNCHER activity from manifest (best-effort)
        launcher = self._launcher_activity()

        # First pass: index files that look like consent surfaces.
        # We later use this to decide whether a sensitive-API hit is
        # "obviously after consent" (same file references a consent
        # surface) vs. "no consent surface in this file" (more likely
        # pre-consent).
        consent_files: set[str] = set()
        sensitive_hits: list[dict] = []
        scanned = 0

        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(root))

            if any(h in text for h in _CONSENT_HINTS):
                consent_files.add(rel)

            for label, pattern, severity, rec in _SENSITIVE_APIS:
                m = pattern.search(text)
                if not m:
                    continue
                line_no = text[:m.start()].count("\n") + 1
                sensitive_hits.append({
                    "file": rel,
                    "line": line_no,
                    "label": label,
                    "severity": severity,
                    "rec": rec,
                    "in_launcher_path": (launcher in rel) if launcher else False,
                    "same_file_has_consent": any(h in text for h in _CONSENT_HINTS),
                })

        findings: list[Finding] = []
        for hit in sensitive_hits:
            if hit["same_file_has_consent"]:
                # Lower confidence — we found consent UI references in
                # the same class. Still report at INFO so the auditor
                # can confirm the call site is post-consent.
                severity = Severity.INFO
                confidence = 0.55
            elif hit["in_launcher_path"] or not consent_files:
                # Launcher path with no consent gate in this class, OR
                # the whole app has zero consent surfaces — escalate.
                severity = hit["severity"]
                confidence = 0.80
            else:
                severity = hit["severity"]
                confidence = 0.65

            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=confidence,
                recommendation=hit["rec"],
                evidence={
                    "api": hit["label"],
                    "file": hit["file"],
                    "line": hit["line"],
                    "in_launcher_path": hit["in_launcher_path"],
                    "consent_surfaces_found_in_app": len(consent_files),
                },
            ))
        return findings

    def _launcher_activity(self) -> str | None:
        """Return the LAUNCHER activity's class path fragment, if any."""
        for act in (self._context.manifest or {}).get("activities", []):
            if not isinstance(act, dict):
                continue
            filters = act.get("intent_filters") or []
            if not isinstance(filters, list):
                continue
            for f in filters:
                if not isinstance(f, dict):
                    continue
                cats = f.get("categories") or []
                if "android.intent.category.LAUNCHER" in cats:
                    name = act.get("name", "")
                    if name:
                        return name.replace(".", "/")
        return None


__all__ = ["DataCollectionAuditorAgent"]
