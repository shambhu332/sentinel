"""D_065 — FileProvider active traversal fuzzer (Dynamic Testing Target).

Complement to D_024 (passive Frida observer of
`file_provider.uri_minted` events). D_024 detects bypasses that
actually happened at runtime. D_065 *forces* the issue: parses
res/xml/paths.xml + AndroidManifest.xml, generates a curated set of
adversarial input file paths (`../../databases/foo.db`, symlink
names, control-char filenames), and emits a Frida trigger payload
that calls `FileProvider.getUriForFile` with each probe — then
fires `ContentResolver.openInputStream(uri)` from a controlled
context to see whether the returned URI actually reads the target
file.

The two halves stack: run D_065 in Phase 2 SAST → DAST orchestrator
fires the probes in Phase 4.5 → D_024's existing event observer
confirms each minted URI's canonical_path. End-to-end coverage in
two hops.

Payload curation:
  * Path-traversal: `../../databases/X`, `../../shared_prefs/X`
  * Symlink names: `link-to-data`, `evil.lnk`
  * Control-char: `​` ZWSP, `\x00` NUL
  * Canonical-collision: `./foo`, `/foo`, `foo/./bar`

Bounded by SafetyBudget (max 40 probes, 5/s) so we don't flood the
target app or trip its anti-tamper.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Path-traversal probe payloads. Kept as raw strings — the Frida hook
# decides how to encode them depending on the FileProvider call site.
_PROBE_PATHS = [
    "../databases/auth.db",
    "../../databases/auth.db",
    "../shared_prefs/secrets.xml",
    "../../shared_prefs/secrets.xml",
    "../../../etc/hosts",
    "..%2f..%2fdatabases%2fauth.db",            # URL-encoded
    "..\\..\\databases\\auth.db",                # Windows-shaped (catches Win-aware impls)
    "./databases/auth.db",                      # leading-dot collapse
    "foo/../databases/auth.db",                  # mid-string traversal
    "​private.txt",                         # zero-width space prefix
    "\x00private.txt",                           # NUL injection (rarely accepted, but…)
    "link-to-data",                              # symlink name hint
]

# Anchor: any class that references FileProvider.getUriForFile or
# extends/uses androidx.core.content.FileProvider
_FILEPROVIDER_RE = re.compile(
    r"FileProvider\s*\.\s*getUriForFile|extends\s+FileProvider"
)


class FileProviderFuzzerAgent(BaseAgent):
    """D_065: emit a path-traversal fuzz plan for the Frida DAST phase."""

    AGENT_ID = "D_065"
    VULN_CLASS = "FileProvider Active Traversal Probe (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.decompiled_dir
            and ctx.decompiled_dir.exists()
            and ctx.manifest
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context

        # 1) Find declared providers + their authorities
        providers = self._fileprovider_entries(ctx.manifest or {})
        if not providers:
            return []

        # 2) Pull declared root paths from xml/paths.xml when present.
        roots = self._declared_roots(ctx.resources_dir)

        # 3) Sanity: at least one Java class uses FileProvider in code.
        # Cheap signal — saves us emitting noise on apps that bundle
        # FileProvider only because a transitive lib does.
        if not self._fileprovider_used_in_java(ctx.decompiled_dir):
            return []

        findings: list[Finding] = []
        for provider in providers:
            authority = provider.get("authority") or ""
            payload = self._build_payload(authority, roots)
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.MEDIUM,
                confidence=0.65,
                recommendation=(
                    "FileProvider declared in the manifest with declared "
                    "roots in `res/xml/paths.xml`. The DAST phase will "
                    "fire the curated probe path list through "
                    "FileProvider.getUriForFile + "
                    "ContentResolver.openInputStream and verify that any "
                    "non-rejecting URI actually reads outside the "
                    "declared roots (cross-checked with D_024's passive "
                    "observer). Fix by rejecting any path containing `..` "
                    "or non-printable characters before constructing the "
                    "File, and by avoiding granting URI permission to "
                    "files outside an explicit allow-list."
                ),
                evidence={
                    "authority": authority,
                    "declared_roots": roots,
                    "probe_count": len(payload["probe_paths"]),
                    "dynamic_target": True,
                    "frida_payload": payload,
                },
            ))
        return findings

    # ---------- manifest / xml parsing ----------

    @staticmethod
    def _fileprovider_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in manifest.get("providers", []) or []:
            if not isinstance(p, dict):
                continue
            name = (p.get("name") or "").lower()
            authority = p.get("authority", "")
            if "fileprovider" in name or "fileprovider" in str(authority).lower():
                out.append(p)
        return out

    @staticmethod
    def _declared_roots(resources_dir: Path | None) -> list[dict[str, str]]:
        if not resources_dir:
            return []
        candidates = [
            resources_dir / "res" / "xml" / "paths.xml",
            resources_dir / "res" / "xml" / "file_paths.xml",
            resources_dir / "res" / "xml" / "provider_paths.xml",
        ]
        out: list[dict[str, str]] = []
        for path in candidates:
            if not path.is_file():
                continue
            try:
                tree = ET.parse(path)
            except (ET.ParseError, OSError):
                continue
            for child in tree.getroot():
                tag = (child.tag.split("}")[-1] if "}" in child.tag
                       else child.tag)
                out.append({
                    "kind": tag,
                    "name": child.attrib.get("name", ""),
                    "path": child.attrib.get("path", ""),
                })
            break  # first file wins
        return out

    @staticmethod
    def _fileprovider_used_in_java(decompiled: Path | None) -> bool:
        if not decompiled:
            return False
        scanned = 0
        for p in decompiled.rglob("*.java"):
            scanned += 1
            if scanned > 1500:
                return False
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            if _FILEPROVIDER_RE.search(head):
                return True
        return False

    # ---------- payload ----------

    @staticmethod
    def _build_payload(
        authority: str, roots: list[dict[str, str]],
    ) -> dict[str, Any]:
        return {
            "authority": authority,
            "declared_roots": roots,
            "probe_paths": _PROBE_PATHS,
            "safety_budget": {
                "max_actions_total": 40,
                "max_actions_per_sec": 5,
                "wall_clock_budget_s": 30,
                "max_consecutive_crashes": 3,
            },
            "frida_script_hint":
                "// D_065 — fire FileProvider.getUriForFile traversal probes\n"
                f"// authority = {authority}\n"
                "// rpc.exports.proberfileprovider(payload) is the entry\n",
        }


__all__ = ["FileProviderFuzzerAgent"]
