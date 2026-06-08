"""D_035 — Sensitive Data Emitted to Log / Local File.

``android.util.Log.*``, ``System.out.println``, and direct
``FileOutputStream`` writes are routinely used to record diagnostics
in release builds. The bug pattern is the payload, not the API:
tokens, JWTs, OAuth bearers, passwords, emails, phone numbers, and
PAN-shaped strings end up in ``adb logcat``, in
``/sdcard/<pkg>/logs/``, or in third-party crash-reporter buffers
that ship off-device.

Detection
---------

We consume one Frida event kind:

* ``log.line_emitted`` — emitted from every ``Log.v/d/i/w/e``, the
  ``System.out``/``err`` print* methods, and ``FileOutputStream``
  writes whose target path falls outside the app's private dir.
  Payload: ``{api, level, tag, message_redacted,
  sensitive_shapes, target_path, stack}``.

``sensitive_shapes`` is a list of pattern labels (``jwt``,
``bearer``, ``email``, ``phone``, ``credit_card``,
``password_field``, ``base64_secret``) that the Frida side matched
against the raw text *before* redaction.

Severity matrix:

* **HIGH** — ``sensitive_shapes`` contains any of
  ``jwt`` / ``bearer`` / ``password_field`` / ``credit_card``.
* **HIGH** — ``api`` is ``FileOutputStream`` and ``target_path``
  lives under ``/sdcard``, ``/storage/emulated``, or another
  world-readable root (sensitive-shape or not — the file is
  reachable across UIDs).
* **MEDIUM** — ``sensitive_shapes`` contains ``email`` /
  ``phone`` / ``base64_secret``.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_HIGH_SHAPES = frozenset({"jwt", "bearer", "password_field", "credit_card"})
_MEDIUM_SHAPES = frozenset({"email", "phone", "base64_secret"})
_WORLD_READABLE_ROOTS = (
    "/sdcard/", "/storage/emulated/", "/storage/self/", "/mnt/sdcard/",
)


class LocalFileLogLeakAgent(BaseAgent):
    """D_035: catch sensitive payloads in log / local-file sinks."""

    AGENT_ID = "D_035"
    VULN_CLASS = "Sensitive Data Emitted to Log / Local File"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_035] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        high_shape_hits: list[dict[str, Any]] = []
        world_readable_hits: list[dict[str, Any]] = []
        medium_shape_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "log.line_emitted":
                continue
            payload = ev.payload or {}
            shapes = set(payload.get("sensitive_shapes") or [])
            api = str(payload.get("api") or "")
            target_path = str(payload.get("target_path") or "")
            sample = {
                "api": api,
                "level": str(payload.get("level") or ""),
                "tag": str(payload.get("tag") or "")[:120],
                "message_redacted": str(
                    payload.get("message_redacted") or "",
                )[:300],
                "sensitive_shapes": sorted(shapes),
                "target_path": target_path[:300],
                "stack": payload.get("stack"),
            }

            if shapes & _HIGH_SHAPES:
                high_shape_hits.append(sample)
            elif api == "FileOutputStream" and _is_world_readable(target_path):
                world_readable_hits.append(sample)
            elif shapes & _MEDIUM_SHAPES:
                medium_shape_hits.append(sample)

        findings: list[Finding] = []
        if high_shape_hits:
            findings.append(self._high_shape_finding(high_shape_hits))
        if world_readable_hits:
            findings.append(self._world_readable_finding(world_readable_hits))
        if medium_shape_hits:
            findings.append(self._medium_shape_finding(medium_shape_hits))
        return findings

    def _high_shape_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "A log line or local-file write contained a "
                    "high-sensitivity payload — JWT, OAuth bearer, "
                    "password-field, or PAN-shaped string. Anything "
                    "logcat captures is readable by the device "
                    "owner; third-party crash reporters ship logcat "
                    "buffers off-device by default."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook regex-matched the raw message body "
                    "against high-sensitivity patterns before "
                    "redaction."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Strip the sensitive value before logging — never "
                "rely on level filters in release builds. Use "
                "Timber's tree filtering or a ProGuard rule that "
                "removes Log.* calls in release."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        )

    def _world_readable_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Local File Written Outside App Private Dir",
            severity=Severity.HIGH,
            confidence=0.78,
            evidence={
                "issue": (
                    "A FileOutputStream wrote bytes to a path under "
                    "/sdcard / /storage/emulated — outside the app's "
                    "private data dir. The file is reachable by any "
                    "process whose UID can read shared storage."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on FileOutputStream.<init> flagged "
                    "target paths under world-readable roots."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Move the file under ``getFilesDir()`` or "
                "``getCacheDir()`` — those paths are owned by the "
                "app UID and isolated from other apps."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-STORAGE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        )

    def _medium_shape_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Log Line Carries PII-Shaped Content",
            severity=Severity.MEDIUM,
            confidence=0.65,
            evidence={
                "issue": (
                    "A log line contained an email / phone / "
                    "base64-secret-shaped string. Lower sensitivity "
                    "than tokens, but still PII that should not "
                    "live in logcat in a release build."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook regex-matched the raw message body "
                    "against PII patterns before redaction."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop the PII or hash-truncate it before logging."
            ),
            owasp="M9: Insecure Data Storage",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )


def _is_world_readable(path: str) -> bool:
    if not path:
        return False
    lower = path.lower()
    return any(lower.startswith(root) for root in _WORLD_READABLE_ROOTS)
