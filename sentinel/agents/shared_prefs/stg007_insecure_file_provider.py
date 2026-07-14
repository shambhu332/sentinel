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
   Static analysis can prove that the provider root is too broad. A
   runtime disclosure still depends on a reachable share flow and grant
   semantics, especially whether the app grants a sensitive URI or a
   prefix URI permission.
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
        package = manifest.get("package") or "<pkg>"
        for entry in exported:
            if entry.get("type") != "provider":
                continue
            name = entry.get("name") or ""
            if not self._is_file_provider(name):
                continue
            authority = entry.get("authority") or f"{package}.fileprovider"
            permission = entry.get("permission") or "<none>"
            snippet_xml = (
                f'<provider\n'
                f'    android:name="{name}"\n'
                f'    android:authorities="{authority}"\n'
                f'    android:exported="true"\n'
                f'    android:grantUriPermissions="true">\n'
                f'  <meta-data\n'
                f'      android:name="android.support.FILE_PROVIDER_PATHS"\n'
                f'      android:resource="@xml/file_paths" />\n'
                f'</provider>'
            )
            findings.append(self._make_finding(
                vuln_class="Exported FileProvider",
                severity=Severity.CRITICAL,
                confidence=0.90,
                evidence={
                    "provider": name,
                    "authority": authority,
                    "permission": permission,
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
                severity_rationale=(
                    f"Rated CRITICAL because {name} is declared exported. "
                    f"FileProvider's security model relies on "
                    f"android:exported=\"false\" plus per-URI grants "
                    f"issued at share time. An exported declaration either "
                    f"breaks the AndroidX FileProvider contract at runtime "
                    f"or, for a permissive custom subclass, removes the "
                    f"per-URI grant boundary."
                ),
                verification_status="Code-level only",
                source_tags=[
                    "Exported Component",
                    "FileProvider Misconfiguration",
                    "Manifest Misconfiguration",
                ],
                reproduction_commands=[
                    "# Decode or inspect the manifest provider declaration:",
                    "apktool d target.apk -o decoded",
                    "rg -n 'FileProvider|android:exported|grantUriPermissions' decoded/AndroidManifest.xml",
                    "",
                    "# Runtime confirmation, if a test build can be launched:",
                    f"adb shell dumpsys package {package} | rg -n '{re.escape(authority)}|FileProvider|exported=true'",
                ],
                observed_result=(
                    f"Static proof only: the manifest declares FileProvider "
                    f"authority {authority} with android:exported=\"true\". "
                    f"Runtime impact must be confirmed on device: AndroidX "
                    f"FileProvider normally rejects exported providers, while "
                    f"a permissive custom provider would expose mapped files "
                    f"without relying on share-time URI grants."
                ),
                code_snippets=[{
                    "label": "FileProvider declaration",
                    "file": "AndroidManifest.xml",
                    "line": 1,
                    "content": snippet_xml,
                }],
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

        manifest: dict[str, Any] = self._context.manifest or {}
        package = manifest.get("package") or "<pkg>"
        authority = self._guess_authority(manifest, package)

        snippet_xml = (
            "<paths xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
            f"  <{tag} name=\"external_files\" path=\"{path_value}\" />\n"
            "</paths>"
        )

        source_tags = [
            "FileProvider Misconfiguration",
            "Insecure Storage Path",
        ]
        if tag == "root-path":
            source_tags.append("Device-Root Exposure")
        elif tag == "external-path":
            source_tags.append("External Storage")

        return self._make_finding(
            vuln_class="Insecure FileProvider Path Mapping",
            severity=severity,
            confidence=0.85,
            code_snippet={
                "file": rel,
                "line": 1,
                "start_col": 0,
                "end_col": 0,
                "content": f'<{tag} name="external_files" path="{path_value}" />',
            },
            code_snippets=[{
                "label": "FileProvider paths config",
                "file": rel,
                "line": 1,
                "content": snippet_xml,
            }],
            evidence={
                "file": rel,
                "tag": tag,
                "path": path_value,
                "rationale": rationale,
                "authority": authority,
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
            severity_rationale=(
                f"Rated {severity.value} because <{tag} path=\"{path_value or '<empty>'}\"/> "
                f"{rationale}. This increases the blast radius of any "
                f"reachable FileProvider share flow because the mapping "
                f"may cover a much larger root than the app intended. "
                f"Runtime exploitability still depends on proving a share "
                f"flow that grants sensitive content or a prefix URI grant."
            ),
            verification_status="Code-level only",
            source_tags=source_tags,
            reproduction_commands=[
                "# Decode the APK and inspect the FileProvider paths XML:",
                "apktool d target.apk -o decoded",
                f"cat decoded/{rel}",
                "",
                "# Correlate the authority with share sites and grant flags:",
                (
                    "rg -n "
                    "'FileProvider|getUriForFile|FLAG_GRANT_(READ|WRITE|PREFIX)_URI_PERMISSION' "
                    "decoded/sources decoded/AndroidManifest.xml"
                ),
            ],
            observed_result=(
                f"Static proof only: decoded/{rel} declares <{tag} "
                f"path=\"{path_value}\"> for authority {authority}, so the "
                f"mapping is over-broad: {rationale}. A real file-read PoC must also "
                f"show a reachable app flow that issues a URI grant for "
                f"sensitive content or uses FLAG_GRANT_PREFIX_URI_PERMISSION; "
                f"this finding has not dynamically verified a content:// read."
            ),
        )

    @staticmethod
    def _guess_authority(manifest: dict[str, Any], package: str) -> str:
        """Best-effort lookup of the FileProvider authority for repro URIs.

        Walks ``exported_components`` for a provider whose name looks
        like a FileProvider and returns its authority. Falls back to
        the conventional ``<package>.fileprovider`` so the reproduction
        commands always have a concrete URI to point at.
        """
        for entry in manifest.get("exported_components") or []:
            if entry.get("type") != "provider":
                continue
            name = entry.get("name") or ""
            if "FileProvider" not in name:
                continue
            authority = entry.get("authority")
            if authority:
                return authority
        return f"{package}.fileprovider"

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
