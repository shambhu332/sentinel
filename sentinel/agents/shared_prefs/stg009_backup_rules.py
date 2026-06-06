"""STG_009: Auto-Backup Rules Audit.

Android's Auto-Backup feature uploads the app's private data dir to
the user's Google Drive (cloud backup) or transfers it during a
device migration (D2D). Apps can pin the rules via:

* ``res/xml/backup_rules.xml`` (legacy ``android:fullBackupContent``)
* ``res/xml/data_extraction_rules.xml`` (Android 12+
  ``android:dataExtractionRules``)

Both files take ``<include>`` and ``<exclude>`` elements that target
``sharedpref``, ``database``, ``file``, ``external``, or ``root``
domains. The bug pattern: a developer includes the whole
``sharedpref`` domain (or even ``root``) and forgets to exclude the
specific prefs file that contains tokens / passwords / biometric
material. The cloud backup then ships those secrets to Google's
servers and back to any restored device.

We flag four shapes:

* ``<include>`` with no ``path``/``name`` attribute, or with
  ``path=""`` / ``path="."`` / ``path="/"`` — the entire domain
  ships to backup.
* ``<include>`` whose ``path`` name or ``name`` attribute matches
  one of the credential keywords (``token``, ``password``,
  ``secret``, ``auth``, ``credential``, ``key``, ``session``).
* ``<include>`` on the ``root`` domain (legacy backup_rules.xml) —
  always over-broad.
* Absence of an ``<exclude>`` covering a credential-shaped path
  when the ``sharedpref`` domain is broadly included — surfaced as
  MEDIUM (we can't prove the secret is in there but the surface is
  wide).

Severity:

* CRITICAL — credential-keyword include path.
* HIGH — wildcard / domain-wide include without compensating excludes.
* MEDIUM — broad sharedpref include without any excludes (advisory).
"""
from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_CREDENTIAL_KEYWORDS = (
    "token", "password", "passwd", "secret", "auth",
    "credential", "key", "session", "jwt", "private",
)
_WILDCARD_PATHS = {"", ".", "/", "./"}


class BackupRulesAgent(BaseAgent):
    """Audit auto-backup / data-extraction rules for credential exposure."""

    AGENT_ID = "STG_009"
    VULN_CLASS = "Insecure Auto-Backup Rules"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(self._context.resources_dir)

    async def analyze(self) -> list[Finding]:
        res = self._context.resources_dir
        if not res:
            return []

        xml_dir = res / "res" / "xml"
        if not xml_dir.exists():
            xml_dir = res / "xml"
        if not xml_dir.exists():
            return []

        findings: list[Finding] = []
        for xml_file in xml_dir.glob("*.xml"):
            try:
                content = xml_file.read_text(errors="replace")
            except OSError:
                continue
            # Heuristic: only audit files whose root tag matches a
            # backup-rules root.
            if not any(t in content for t in (
                "<full-backup-content",
                "<data-extraction-rules",
            )):
                continue

            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                continue

            includes: list[dict[str, str]] = []
            excludes: list[dict[str, str]] = []
            for elem in root.iter():
                tag = self._strip_ns(elem.tag)
                if tag == "include":
                    includes.append(self._element_attrs(elem))
                elif tag == "exclude":
                    excludes.append(self._element_attrs(elem))

            findings.extend(
                self._audit_includes(xml_file, includes, excludes),
            )
        return findings

    def _audit_includes(
        self,
        xml_file,
        includes: list[dict[str, str]],
        excludes: list[dict[str, str]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        rel = self._rel_xml(xml_file)
        excluded_keywords = {
            kw for kw in _CREDENTIAL_KEYWORDS
            for ex in excludes
            if kw in (ex.get("path", "") + ex.get("name", "")).lower()
        }

        for inc in includes:
            domain = inc.get("domain", "")
            path = inc.get("path", "")
            name = inc.get("name", "")
            label = path or name

            severity: Severity | None = None
            confidence = 0.85
            reason = ""

            haystack = (path + " " + name).lower()
            credential_hit = next(
                (kw for kw in _CREDENTIAL_KEYWORDS if kw in haystack),
                None,
            )

            if credential_hit and credential_hit not in excluded_keywords:
                severity = Severity.CRITICAL
                confidence = 0.90
                reason = (
                    f"include path contains credential keyword "
                    f"'{credential_hit}' with no compensating <exclude>"
                )
            elif domain == "root":
                severity = Severity.HIGH
                confidence = 0.85
                reason = "domain=\"root\" — entire app sandbox backed up"
            elif label.strip() in _WILDCARD_PATHS:
                severity = Severity.HIGH
                confidence = 0.80
                reason = (
                    f"wildcard include on domain '{domain or '<any>'}' — "
                    "every file in the domain ships to backup"
                )
            elif domain == "sharedpref" and not excludes:
                severity = Severity.MEDIUM
                confidence = 0.65
                reason = (
                    "sharedpref domain included with no <exclude> "
                    "elements — surface for any token-storing prefs file"
                )

            if severity is None:
                continue

            findings.append(self._make_finding(
                vuln_class="Insecure Auto-Backup Rules",
                severity=severity,
                confidence=confidence,
                evidence={
                    "file": rel,
                    "domain": domain or "<unspecified>",
                    "path": path or name or "<wildcard>",
                    "reason": reason,
                },
                recommendation=(
                    "Restrict the backup rule to specific non-sensitive "
                    "files. Add an <exclude domain=\"sharedpref\" "
                    "path=\"credentials.xml\" /> (and equivalents) for "
                    "any prefs / database / file path that stores "
                    "credentials, biometric material, OAuth tokens, "
                    "or PII. Better still, set "
                    "android:allowBackup=\"false\" if the app does not "
                    "have a legitimate need for Auto-Backup."
                ),
                owasp="M2: Inadequate Supply Chain Security",
                masvs="MSTG-STORAGE-8",
                cvss_vector=(
                    "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
                    if severity != Severity.MEDIUM
                    else "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
                ),
            ))
        return findings

    def _rel_xml(self, xml_file) -> str:
        rel = str(xml_file)
        res = self._context.resources_dir
        if res:
            try:
                rel = str(xml_file.relative_to(res))
            except ValueError:
                pass
        return rel

    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    @staticmethod
    def _element_attrs(elem) -> dict[str, str]:
        return {
            k.split("}")[-1]: v for k, v in elem.attrib.items()
        }
