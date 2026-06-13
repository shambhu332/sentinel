"""D_081 — Backup data extractor probe target.

This agent is the active-replay companion to the passive C_001 insecure
backup check. It only runs when ``ScanContext.active_replay`` is true
because the matching DAST tool invokes ``adb backup`` against a device.

Static half:

* read ``android:allowBackup`` from the parsed manifest;
* treat a missing value as backup-enabled for legacy/default behavior;
* emit a bounded DAST payload for ``sentinel.tools.backup_tool`` to run.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class BackupDataExtractorAgent(BaseAgent):
    """D_081: identify apps eligible for active ADB backup extraction."""

    AGENT_ID = "D_081"
    VULN_CLASS = "Backup Data Extraction Probe"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(self._context.active_replay and self._context.manifest)

    async def analyze(self) -> list[Finding]:
        if not self._context.active_replay:
            return []
        manifest = self._context.manifest or {}
        state = _backup_state(manifest, self._context.target_sdk)
        if not state["enabled"]:
            return []

        package = str(manifest.get("package") or "")
        payload = _build_payload(package)
        severity = (
            Severity.HIGH
            if state["source"] == "manifest_true"
            else Severity.MEDIUM
        )
        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.88 if severity == Severity.HIGH else 0.72,
            recommendation=(
                "Set `android:allowBackup=\"false\"` for apps that store "
                "tokens, PII, local databases, or cached session state. If "
                "backup is a product requirement, define restrictive "
                "`android:fullBackupContent` or Android 12+ "
                "`android:dataExtractionRules` and exclude `shared_prefs`, "
                "`databases`, and credential cache files. Re-run D_081 with "
                "`--active-replay` to verify extracted backups no longer "
                "contain high-entropy secrets."
            ),
            evidence={
                "package": package,
                "allow_backup": state["raw"],
                "allow_backup_source": state["source"],
                "target_sdk": state["target_sdk"],
                "full_backup_content": manifest.get("full_backup_content"),
                "data_extraction_rules": manifest.get("data_extraction_rules"),
                "requires_active_replay": True,
                "dynamic_target": True,
                "dast_payload": payload,
            },
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-8",
            cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        )]


def _backup_state(manifest: dict[str, Any], context_target_sdk: int) -> dict[str, Any]:
    target_sdk = int(manifest.get("target_sdk") or context_target_sdk or 0)
    if "allow_backup" not in manifest:
        return {
            "enabled": True,
            "raw": None,
            "source": "default_missing",
            "target_sdk": target_sdk,
        }
    raw = manifest.get("allow_backup")
    enabled = raw is True or str(raw).lower() == "true"
    return {
        "enabled": enabled,
        "raw": raw,
        "source": "manifest_true" if enabled else "manifest_false",
        "target_sdk": target_sdk,
    }


def _build_payload(package: str) -> dict[str, Any]:
    return {
        "type": "backup_extract",
        "package": package,
        "requires_active_replay": True,
        "scan_shared_prefs": True,
        "safety_budget": {
            "max_actions_total": 1,
            "max_actions_per_sec": 1,
            "wall_clock_budget_s": 120,
            "max_consecutive_crashes": 1,
        },
        "tool_hint": "sentinel.tools.backup_tool.extract_and_scan_backup",
    }


__all__ = ["BackupDataExtractorAgent"]
