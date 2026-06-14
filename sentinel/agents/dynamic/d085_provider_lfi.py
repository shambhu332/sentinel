"""D_085 — Content Provider LFI (paths.xml policy audit).

Static config audit of `res/xml/file_paths.xml` (and the
`provider_paths.xml` / `paths.xml` variants the Support library
accepts). D_024 is the passive runtime observer of file_provider
URIs being minted; D_065 is the active traversal-input fuzzer.
D_085 is the **policy review** half — overly broad root entries in
the XML grant the attacker an entire filesystem subtree even when
their input is well-formed.

Bad shapes we flag:

  <external-path  name="root"     path="." />       # all external storage
  <files-path     name="all"      path="/" />       # all app files dir
  <external-files-path name="any" path=""  />       # entire external-files
  <root-path      name="rootfs"   path="." />       # FS root (catastrophic)
  <cache-path     name="all"      path="" />        # entire cache

Severity bands:
  root-path + broad     => Critical
  external-path + broad => High
  files-path + broad    => Medium
  cache-path + broad    => Low

Output finding carries a `frida_payload` with curated probe URIs
the runtime hook will resolve via ContentResolver.openFileDescriptor.
Safety: probe URIs target only **app-owned** files under the granted
roots; never `/etc/shadow`, `/system/`, or any other off-app path.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Map each root tag to a severity band when the path is empty / "." / "/"
# (i.e. the entire subtree is exposed).
_ROOT_SEVERITY: dict[str, Severity] = {
    "root-path":          Severity.CRITICAL,
    "external-path":      Severity.HIGH,
    "external-media-path":Severity.HIGH,
    "files-path":         Severity.MEDIUM,
    "external-files-path":Severity.MEDIUM,
    "external-cache-path":Severity.LOW,
    "cache-path":         Severity.LOW,
}

# Curated, SAFE in-app probe files. The runtime hook will only try to
# resolve URIs under these app-owned paths.
_APP_OWNED_PROBE_FILES = [
    "shared_prefs/secret.xml",
    "shared_prefs/auth_token.xml",
    "shared_prefs/user.xml",
    "databases/auth.db",
    "databases/users.db",
    "files/session.json",
    "files/cache_token.txt",
]

# Substrings that mark a "broad" path attribute. Anything that opens
# the whole subtree gets flagged.
_BROAD_PATH_VALUES = {"", ".", "/", "./"}


class ProviderLfiAgent(BaseAgent):
    """D_085: paths.xml policy auditor + LFI probe target identifier."""

    AGENT_ID = "D_085"
    VULN_CLASS = "ContentProvider LFI (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.resources_dir and ctx.resources_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        xml_dir = ctx.resources_dir / "res" / "xml"
        if not xml_dir.is_dir():
            return []

        findings: list[Finding] = []
        for xml in xml_dir.glob("*.xml"):
            stem = xml.stem.lower()
            if "path" not in stem and "provider" not in stem:
                # Only inspect files whose name suggests provider config
                # — keeps us out of `network_security_config.xml` etc.
                continue
            try:
                tree = ET.parse(xml)
            except (ET.ParseError, OSError):
                continue
            root = tree.getroot()

            broad_entries: list[dict[str, Any]] = []
            for child in root:
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                severity = _ROOT_SEVERITY.get(tag)
                if severity is None:
                    continue
                name = child.attrib.get("name", "")
                path_val = child.attrib.get("path", "")
                if path_val not in _BROAD_PATH_VALUES:
                    continue  # narrow path — fine
                broad_entries.append({
                    "tag": tag,
                    "name": name,
                    "path": path_val,
                    "severity": severity,
                })

            if not broad_entries:
                continue

            # Headline severity = worst tag
            headline = max(
                broad_entries, key=lambda e: list(Severity).index(e["severity"]),
            )
            rel = str(xml.relative_to(ctx.resources_dir))
            authority = self._guess_authority(ctx, stem)
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=headline["severity"],
                confidence=0.85,
                recommendation=(
                    f"`{rel}` declares {len(broad_entries)} root entry/"
                    f"entries with a wildcard `path` "
                    f"(values {{`{'`, `'.join(sorted({e['path'] for e in broad_entries}))}` }}). "
                    "Any caller with the FileProvider authority can "
                    "resolve a `content://` URI under these roots to "
                    "read arbitrary files in the subtree. Replace the "
                    "wildcard with the narrowest possible literal "
                    "subpath; for files outside an app directory, "
                    "always copy them into a controlled cache before "
                    "sharing."
                ),
                evidence={
                    "file": rel,
                    "authority_guess": authority,
                    "broad_entries": broad_entries,
                    "dynamic_target": True,
                    "frida_payload": self._build_payload(
                        authority, broad_entries,
                    ),
                },
            ))
        return findings

    # ---------- helpers ----------

    @staticmethod
    def _guess_authority(ctx: Any, stem: str) -> str:
        """Best-effort authority lookup from the manifest."""
        for p in (ctx.manifest or {}).get("providers", []) or []:
            if not isinstance(p, dict):
                continue
            name = (p.get("name") or "").lower()
            if "fileprovider" in name:
                return p.get("authority") or ""
        return ""

    @staticmethod
    def _build_payload(
        authority: str, broad_entries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        # For each broad root + each curated app-owned probe file,
        # construct a content:// URI the runtime hook should try
        # to resolve. The hook NEVER reads /etc, /system, /proc, etc.
        probe_uris: list[str] = []
        for entry in broad_entries:
            for f in _APP_OWNED_PROBE_FILES:
                probe_uris.append(
                    f"content://{authority}/{entry['name']}/{f}"
                    if authority else
                    f"content://<authority>/{entry['name']}/{f}",
                )
        return {
            "type": "lfi_probe",
            "authority": authority,
            # Restrict the runtime hook to app-owned filenames only.
            "safe_app_owned_files": _APP_OWNED_PROBE_FILES,
            "probe_uris": probe_uris[:30],
            # Hard refuse list — the TS hook double-checks every URI
            # against these patterns and drops any that match.
            "forbidden_path_substrings": [
                "/etc/", "/system/", "/proc/", "/dev/", "/sys/",
                "/data/system/", "shadow", "passwd",
            ],
            "block_off_app_targets": True,
            "safety_budget": {
                "max_actions_total": 30,
                "max_actions_per_sec": 2,
                "wall_clock_budget_s": 30,
                "max_consecutive_crashes": 3,
            },
            "frida_script_hint":
                "// D_085 — resolve probe_uris via ContentResolver."
                "openFileDescriptor\n"
                "// rpc.exports.providerlfi(payload) is the entry\n",
        }


__all__ = ["ProviderLfiAgent"]
