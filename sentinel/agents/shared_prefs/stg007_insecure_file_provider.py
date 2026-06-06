"""STG_007: Insecure FileProvider Path Audit.

Android's ``FileProvider`` (and the underlying ``GrantUriPermission``
mechanism) lets one app share a content URI for a private file with
another app — receivers get read or write access without the sharer
needing to set the file world-readable. The path mappings are declared
in ``res/xml/*paths.xml`` and reference one of the canonical roots:

  * ``<root-path path="..." />``        → the device root, ``/``
  * ``<files-path path="..." />``       → ``Context.getFilesDir()``
  * ``<cache-path path="..." />``       → ``Context.getCacheDir()``
  * ``<external-path path="..." />``    → external storage
  * ``<external-files-path path="" />`` → app-private external dir
  * ``<external-cache-path path="" />``
  * ``<external-media-path path="" />``

Two bug patterns we flag:

1. **Over-broad mapping** — ``root-path`` (any value), ``external-path``
   or ``files-path`` with ``path="."`` / ``path=""`` / ``path="/"``.
   Any sibling whose URI we grant access to receives the whole
   sandbox / external storage instead of a specific file. Recipient
   apps can read SharedPreferences, the database, code-cache, etc.
2. **Exported FileProvider** — ``<provider android:exported="true">``
   for the FileProvider authority. FileProvider must always be
   ``exported="false"`` and rely on the per-URI grant flag the sharer
   sets at runtime. The framework's manifest template gets this right
   but custom subclasses sometimes flip it.

Severity:

* **CRITICAL** — exported FileProvider declaration
* **HIGH** — root-path or wildcard external-path
* **MEDIUM** — wildcard files-path / cache-path (still sandbox-scoped
  but every file in the app's data dir is reachable)
"""
from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_WILDCARD_VALUES = {"", ".", "/", "./"}

_OVERBROAD_TAGS = {
    # tag → severity bump when path is wildcard
    "root-path": (Severity.HIGH, "exposes / — entire device file system"),
    "external-path": (
        Severity.HIGH,
        "wildcard external-path maps the whole SD-card surface",
    ),
    "files-path": (
        Severity.MEDIUM,
        "wildcard files-path maps the entire app-private data dir",
    ),
    "cache-path": (
        Severity.MEDIUM,
        "wildcard cache-path maps the entire cache dir",
    ),
}


class InsecureFileProviderAgent(BaseAgent):
    """Audit res/xml/*paths*.xml mappings and FileProvider manifest entries."""

    AGENT_ID = "STG_007"
    VULN_CLASS = "Insecure FileProvider Path Mapping"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        # We need either resources (for the paths XML) or manifest
        # (for the exported-provider check).
        return bool(self._context.resources_dir) or bool(self._context.manifest)

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._audit_paths_xml())
        findings.extend(self._audit_manifest_exports())
        return findings

    def _audit_paths_xml(self) -> list[Finding]:
        findings: list[Finding] = []
        res = self._context.resources_dir
        if not res:
            return findings

        xml_dir = res / "res" / "xml"
        if not xml_dir.exists():
            # Some decompilers strip the leading res/ — fall back.
            xml_dir = res / "xml"
        if not xml_dir.exists():
            return findings

        for xml_file in xml_dir.glob("*.xml"):
            try:
                content = xml_file.read_text(errors="replace")
            except OSError:
                continue

            # Heuristic: only audit files that look like FileProvider
            # paths configs (root tag <paths> or <file-provider-paths>).
            if "<paths" not in content and "<file-provider-paths" not in content:
                continue

            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                continue

            for child in root.iter():
                tag = self._strip_ns(child.tag)
                if tag not in _OVERBROAD_TAGS and tag != "root-path":
                    continue
                # Read path explicitly — an empty string is meaningful
                # (it means "the whole root"), so we don't want the
                # ``or`` chain to fall through to the name attribute.
                raw_path = child.get("path")
                path_attr = (raw_path if raw_path is not None else "").strip()

                # root-path is over-broad regardless of path attribute.
                if tag == "root-path":
                    severity, rationale = _OVERBROAD_TAGS["root-path"]
                    findings.append(self._build_path_finding(
                        xml_file=xml_file,
                        tag=tag,
                        path_value=path_attr,
                        severity=severity,
                        rationale=rationale,
                    ))
                    continue

                if path_attr in _WILDCARD_VALUES:
                    severity, rationale = _OVERBROAD_TAGS[tag]
                    findings.append(self._build_path_finding(
                        xml_file=xml_file,
                        tag=tag,
                        path_value=path_attr or "<empty>",
                        severity=severity,
                        rationale=rationale,
                    ))
        return findings

    def _audit_manifest_exports(self) -> list[Finding]:
        findings: list[Finding] = []
        manifest: dict[str, Any] = self._context.manifest or {}
        exported = manifest.get("exported_components") or []
        for entry in exported:
            if entry.get("type") != "provider":
                continue
            name = entry.get("name") or ""
            if not self._is_file_provider(name):
                continue
            findings.append(self._make_finding(
                vuln_class="Exported FileProvider",
                severity=Severity.CRITICAL,
                confidence=0.90,
                evidence={
                    "provider": name,
                    "permission": entry.get("permission") or "<none>",
                    "issue": (
                        "FileProvider declared as android:exported=\"true\"."
                        " Per-URI grants stop working as the access "
                        "boundary — any app can resolve and read the "
                        "provider's URIs without a runtime grant."
                    ),
                },
                recommendation=(
                    "Set android:exported=\"false\" on FileProvider entries "
                    "and rely on Intent.FLAG_GRANT_READ_URI_PERMISSION at "
                    "the share site to authorize specific recipients."
                ),
                owasp="M1: Improper Platform Usage",
                masvs="MSTG-PLATFORM-2",
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            ))
        return findings

    def _build_path_finding(
        self,
        *,
        xml_file,
        tag: str,
        path_value: str,
        severity: Severity,
        rationale: str,
    ) -> Finding:
        rel = str(xml_file)
        if self._context.resources_dir:
            try:
                rel = str(xml_file.relative_to(self._context.resources_dir))
            except ValueError:
                pass
        return self._make_finding(
            vuln_class="Insecure FileProvider Path Mapping",
            severity=severity,
            confidence=0.85,
            evidence={
                "file": rel,
                "tag": tag,
                "path": path_value,
                "rationale": rationale,
            },
            recommendation=(
                "Narrow the FileProvider path mapping to the specific "
                f"directory the app intends to share. Replace <{tag} "
                f"path=\"{path_value}\" /> with a sub-path such as "
                "<files-path name=\"shared\" path=\"shared/\" /> and "
                "place exportable files inside that sub-directory. "
                "Avoid <root-path> — there is essentially no legitimate "
                "use case for it in shipping code."
            ),
            owasp="M2: Inadequate Supply Chain Security",
            masvs="MSTG-STORAGE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        )

    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    @staticmethod
    def _is_file_provider(name: str) -> bool:
        canonical = (
            "androidx.core.content.FileProvider",
            "android.support.v4.content.FileProvider",
        )
        if name in canonical:
            return True
        # Subclass detection: name ends in FileProvider.
        return bool(re.search(r"\.FileProvider$|FileProvider$", name))
