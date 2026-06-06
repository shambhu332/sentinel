"""Manifest- and resource-based verifiers.

These verifiers re-read the artifacts the recon phase produced and
check the agent's claim against them directly. No device, no
captures, no LLM — just deterministic file reads.

The pattern: each verifier reads ``ctx.manifest`` /
``ctx.resources_dir``, looks for the specific pattern the agent
flagged, and returns ``verified`` / ``refuted`` / ``unsupported``.
"""
from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from sentinel.core.finding import Finding
from sentinel.verify.models import VerificationResult, VerifierContext


# ---------- META_002 — debuggable manifest ----------


class DebuggableManifestVerifier:
    AGENT_IDS = ("META_002",)

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        manifest = ctx.manifest
        if not manifest:
            return VerificationResult.unsupported(
                method="manifest-reread",
                reason="manifest dict empty — recon phase did not produce one",
            )
        debuggable = bool(manifest.get("debuggable"))
        if debuggable:
            return VerificationResult.verified(
                method="manifest-reread",
                evidence={
                    "manifest_debuggable": True,
                    "package": manifest.get("package", ""),
                },
            )
        return VerificationResult.refuted(
            method="manifest-reread",
            evidence={"manifest_debuggable": False},
            notes="manifest reports debuggable=false — likely stale finding",
        )


# ---------- P_005 — excessive permissions ----------


class ExcessivePermissionsVerifier:
    AGENT_IDS = ("P_005",)

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        manifest = ctx.manifest
        declared = set(manifest.get("permissions") or [])
        claimed = (finding.evidence or {}).get("permission")
        if not isinstance(claimed, str) or not claimed:
            return VerificationResult.unsupported(
                method="permission-reread",
                reason="finding evidence missing 'permission' field",
            )
        if claimed in declared:
            return VerificationResult.verified(
                method="permission-reread",
                evidence={
                    "permission": claimed,
                    "declared_count": len(declared),
                },
            )
        return VerificationResult.refuted(
            method="permission-reread",
            evidence={"permission": claimed},
            notes="permission no longer declared in re-parsed manifest",
        )


# ---------- STG_007 — insecure FileProvider paths ----------


class InsecureFileProviderVerifier:
    AGENT_IDS = ("STG_007",)

    _WILDCARD_VALUES = {"", ".", "/", "./"}

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        # Two finding shapes from STG_007:
        # (a) exported FileProvider in manifest
        # (b) over-broad <root-path> / wildcard path in res/xml.
        evidence = finding.evidence or {}
        if "provider" in evidence:
            return self._verify_exported_provider(evidence, ctx)
        return self._verify_paths_xml(evidence, ctx)

    def _verify_exported_provider(
        self, evidence: dict[str, Any], ctx: VerifierContext,
    ) -> VerificationResult:
        target = evidence.get("provider", "")
        manifest = ctx.manifest
        exported = manifest.get("exported_components") or []
        for e in exported:
            if (
                e.get("type") == "provider"
                and e.get("name") == target
                and e.get("explicitly_exported")
            ):
                return VerificationResult.verified(
                    method="manifest-reread",
                    evidence={
                        "provider": target,
                        "explicitly_exported": True,
                    },
                )
        return VerificationResult.refuted(
            method="manifest-reread",
            evidence={"provider": target},
            notes="provider not found / no longer exported in re-parsed manifest",
        )

    def _verify_paths_xml(
        self, evidence: dict[str, Any], ctx: VerifierContext,
    ) -> VerificationResult:
        res = ctx.resources_dir
        if not res:
            return VerificationResult.unsupported(
                method="paths-xml-reread",
                reason="resources_dir missing",
            )
        file_rel = evidence.get("file", "")
        if not file_rel:
            return VerificationResult.unsupported(
                method="paths-xml-reread",
                reason="finding evidence missing 'file' field",
            )
        candidate = res / file_rel
        if not candidate.exists():
            # The agent saved the file relative to ``res`` either with
            # or without the res/ prefix — try the alternative.
            alt = (
                res / "res" / file_rel
                if not file_rel.startswith("res/")
                else res / file_rel[4:]
            )
            candidate = alt if alt.exists() else candidate
        if not candidate.exists():
            return VerificationResult.unsupported(
                method="paths-xml-reread",
                reason=f"flagged path-config XML not on disk: {file_rel}",
            )
        try:
            tree = ET.fromstring(candidate.read_text(errors="replace"))
        except (ET.ParseError, OSError) as exc:
            return VerificationResult.inconclusive(
                method="paths-xml-reread",
                reason=f"could not parse: {exc}",
            )
        claimed_tag = evidence.get("tag", "")
        claimed_path = evidence.get("path", "")
        for elem in tree.iter():
            tag = elem.tag.rsplit("}", 1)[-1]
            if tag != claimed_tag:
                continue
            raw_path = elem.get("path")
            actual = (raw_path if raw_path is not None else "").strip()
            # Root-path or wildcard match is sufficient.
            if tag == "root-path":
                return VerificationResult.verified(
                    method="paths-xml-reread",
                    evidence={"tag": tag, "path": actual},
                )
            if actual in self._WILDCARD_VALUES or actual == claimed_path:
                return VerificationResult.verified(
                    method="paths-xml-reread",
                    evidence={"tag": tag, "path": actual},
                )
        return VerificationResult.refuted(
            method="paths-xml-reread",
            evidence={"tag": claimed_tag, "path": claimed_path},
            notes="claimed element not present in re-parsed XML",
        )


# ---------- STG_009 — backup rules ----------


class BackupRulesVerifier:
    AGENT_IDS = ("STG_009",)

    async def verify(
        self, finding: Finding, ctx: VerifierContext,
    ) -> VerificationResult:
        res = ctx.resources_dir
        if not res:
            return VerificationResult.unsupported(
                method="backup-rules-reread",
                reason="resources_dir missing",
            )
        evidence = finding.evidence or {}
        file_rel = evidence.get("file", "")
        if not file_rel:
            return VerificationResult.unsupported(
                method="backup-rules-reread",
                reason="finding evidence missing 'file' field",
            )
        candidate = res / file_rel
        if not candidate.exists():
            alt = (
                res / "res" / file_rel
                if not file_rel.startswith("res/")
                else res / file_rel[4:]
            )
            candidate = alt if alt.exists() else candidate
        if not candidate.exists():
            return VerificationResult.unsupported(
                method="backup-rules-reread",
                reason=f"flagged backup-rules XML not on disk: {file_rel}",
            )
        try:
            tree = ET.fromstring(candidate.read_text(errors="replace"))
        except (ET.ParseError, OSError) as exc:
            return VerificationResult.inconclusive(
                method="backup-rules-reread",
                reason=f"could not parse: {exc}",
            )
        claimed_domain = evidence.get("domain", "")
        claimed_path = evidence.get("path", "")
        for elem in tree.iter():
            tag = elem.tag.rsplit("}", 1)[-1]
            if tag != "include":
                continue
            attrs = {k.rsplit("}", 1)[-1]: v for k, v in elem.attrib.items()}
            domain = attrs.get("domain") or "<unspecified>"
            path_attr = attrs.get("path") or attrs.get("name") or ""
            if domain == claimed_domain and (
                path_attr == claimed_path
                or "<wildcard>" == claimed_path
            ):
                return VerificationResult.verified(
                    method="backup-rules-reread",
                    evidence={
                        "domain": domain,
                        "path": path_attr,
                    },
                )
        return VerificationResult.refuted(
            method="backup-rules-reread",
            evidence={"domain": claimed_domain, "path": claimed_path},
            notes="matching <include> not present in re-parsed XML",
        )
