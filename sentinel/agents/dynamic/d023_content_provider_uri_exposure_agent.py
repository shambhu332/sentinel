"""D_023 — ContentProvider URI Exposure to Cross-UID Callers.

Android ``ContentProvider`` is the canonical way to share files
between apps, but the platform's permission model is famously
sharp-edged: an exported provider with ``android:grantUriPermissions``
hands the *caller* a transient read/write capability on whatever URI
the provider returns. The dangerous pattern is when the provider
returns a URI rooted at the app's *private* data dir (``getFilesDir``
/ ``getCacheDir`` / ``databases``) in response to a query that the
caller controls — that is, the caller gets to ask for any file and the
provider hands it over because the URI is well-formed.

Detection
---------

We consume two Frida event kinds:

* ``provider.uri_opened`` — emitted from
  ``ContentResolver.openFileDescriptor(uri, mode)`` and
  ``openAssetFileDescriptor`` overloads. Payload:
  ``{caller_uid, target_uid, uri, mode, real_path}``.
* ``provider.query_returned`` — emitted from ``ContentResolver.query``
  when the returned ``Cursor`` carries a column that *looks* like an
  on-disk path (``_data``, ``file_path``, ``path``). Payload:
  ``{caller_uid, target_uid, uri, exposed_paths}``.

The agent only acts when ``caller_uid != target_uid`` (i.e. an actual
cross-app boundary was crossed) and the surfaced path lives inside the
target app's private dir.

Severity matrix:

* **CRITICAL** — ``openFileDescriptor`` with mode ``"w"`` / ``"rw"``
  reached a private-dir file (cross-UID write into our own files —
  classic confused deputy).
* **HIGH** — ``openFileDescriptor`` with mode ``"r"`` reached a
  private-dir file (cross-UID read of own files).
* **MEDIUM** — ``query`` returned a ``_data`` column pointing at a
  private-dir path (the path leaks the FS layout to the caller even
  if the file is never opened).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_WRITE_MODES = ("w", "wa", "rw", "wt", "rwt")


class ContentProviderUriExposureAgent(BaseAgent):
    """D_023: catch cross-UID exposure of private-dir paths via provider URIs."""

    AGENT_ID = "D_023"
    VULN_CLASS = "ContentProvider URI Exposure to Cross-UID Caller"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_023] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        own_pkg = (self._context.manifest or {}).get("package") or ""

        write_hits: list[dict[str, Any]] = []
        read_hits: list[dict[str, Any]] = []
        path_leak_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            payload = ev.payload or {}
            if not _is_cross_uid(payload):
                continue

            if ev.kind == "provider.uri_opened":
                real_path = str(payload.get("real_path") or "")
                if not _is_private_dir_path(real_path, own_pkg):
                    continue
                mode = str(payload.get("mode") or "r").lower()
                sample = {
                    "uri": str(payload.get("uri") or "")[:300],
                    "real_path": real_path[:300],
                    "mode": mode,
                    "caller_uid": payload.get("caller_uid"),
                    "stack": payload.get("stack"),
                }
                if mode in _WRITE_MODES:
                    write_hits.append(sample)
                else:
                    read_hits.append(sample)

            elif ev.kind == "provider.query_returned":
                paths = payload.get("exposed_paths") or []
                leaked = [
                    p for p in paths
                    if isinstance(p, str) and _is_private_dir_path(p, own_pkg)
                ]
                if not leaked:
                    continue
                path_leak_hits.append({
                    "uri": str(payload.get("uri") or "")[:300],
                    "exposed_paths": leaked[:10],
                    "caller_uid": payload.get("caller_uid"),
                    "stack": payload.get("stack"),
                })

        findings: list[Finding] = []
        if write_hits:
            findings.append(self._write_finding(write_hits))
        if read_hits:
            findings.append(self._read_finding(read_hits))
        if path_leak_hits:
            findings.append(self._path_leak_finding(path_leak_hits))
        return findings

    def _write_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.92,
            evidence={
                "issue": (
                    "A ContentProvider URI resolved to a file in this "
                    "application's private data directory and was "
                    "opened for **write** by a process with a "
                    "different UID. Any caller who can address this "
                    "provider can rewrite the application's own files "
                    "— the textbook confused-deputy / arbitrary-file-"
                    "write primitive (CVE-2020-0096 family)."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on ContentResolver.openFileDescriptor "
                    "compared the calling-UID against the target-UID "
                    "and resolved the FD's path."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Reject write modes in the provider's ``openFile`` "
                "override unless the caller holds a signature-level "
                "permission. Resolve and canonicalize the requested "
                "URI inside the override and confirm it stays within "
                "an explicitly shareable sub-directory (never the "
                "files / databases / shared_prefs root). Drop "
                "``android:grantUriPermissions=\"true\"`` on the "
                "provider unless a specific export flow needs it."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        )

    def _read_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="ContentProvider Private File Read Across UID",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "A ContentProvider URI resolved to a file in this "
                    "application's private data directory and was "
                    "opened for **read** by a process with a different "
                    "UID. Any caller who can address this provider "
                    "can exfiltrate the file — tokens, databases, "
                    "shared_prefs, and cached PII are all reachable."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on ContentResolver.openFileDescriptor "
                    "compared the calling-UID against the target-UID "
                    "and resolved the FD's path."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Override the provider's ``openFile`` and reject any "
                "URI that resolves outside an explicit allow-list of "
                "shareable directories. Prefer placing public files "
                "under ``getExternalFilesDir(null)`` and exposing "
                "them through a ``FileProvider`` with a tight "
                "``paths.xml``."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        )

    def _path_leak_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="ContentProvider Cursor Exposes Private FS Path",
            severity=Severity.MEDIUM,
            confidence=0.75,
            evidence={
                "issue": (
                    "A ContentResolver.query call from a process with "
                    "a different UID returned a Cursor whose ``_data`` "
                    "(or equivalent) column held an absolute path "
                    "under this application's private data directory. "
                    "Even when the file itself is never opened the "
                    "path leaks the FS layout — useful to chain with "
                    "other primitives."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on ContentResolver.query inspected "
                    "returned Cursor columns named ``_data`` / "
                    "``file_path`` / ``path``."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop the ``_data`` column from the provider's "
                "projection or rewrite it to a relative identifier. "
                "MediaStore-style providers should return content:// "
                "URIs only, never on-disk paths."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )


def _is_cross_uid(payload: dict[str, Any]) -> bool:
    caller = payload.get("caller_uid")
    target = payload.get("target_uid")
    if caller is None or target is None:
        return False
    try:
        return int(caller) != int(target)
    except (TypeError, ValueError):
        return False


def _is_private_dir_path(path: str, own_pkg: str) -> bool:
    if not path:
        return False
    p = path.lower()
    if not own_pkg:
        # Without a manifest we still flag the canonical private root.
        return p.startswith("/data/data/") or p.startswith("/data/user/")
    pkg = own_pkg.lower()
    return (
        f"/data/data/{pkg}/" in p
        or f"/data/user/0/{pkg}/" in p
        or f"/data/user_de/0/{pkg}/" in p
    )
