"""D_022 — Local-Socket Server Exposed Across App Boundary.

``LocalSocket`` is Android's wrapper over Unix-domain sockets. A
``LocalServerSocket`` listening on the *filesystem* namespace
(``LocalSocketAddress.Namespace.FILESYSTEM`` or
``RESERVED``) is bound to a path under ``/data/data/<pkg>/`` and is
reachable to anyone who can ``connect`` to that path — every app with
the same UID, every app the FS permissions allow, and any process
that survived a UID re-mapping.

The ``ABSTRACT`` namespace (``\\0name``) is the more dangerous case:
it lives in a *kernel-managed* namespace with no filesystem
permissions whatsoever. Any process on the device can connect. Many
debug tools (Frida itself, gdb-server, Stetho, Bugsnag's older NDK
agent) listen on ABSTRACT-namespace sockets — left in a release build
they become arbitrary command channels.

Detection
---------

We consume Frida events of kind ``local_socket.server_created``. Each
payload describes one ``LocalServerSocket`` instantiation:

* ``namespace`` — ``ABSTRACT`` / ``FILESYSTEM`` / ``RESERVED``.
* ``name`` — the socket address.
* ``stack`` — caller stack.

Classification:

* **HIGH** — ABSTRACT-namespace server (cross-app reachability with
  zero filesystem permission gating).
* **MEDIUM** — FILESYSTEM-namespace server whose path is under
  ``/data/local/tmp`` or otherwise outside the app's private dir
  (cross-UID reachability).
* **INFO** — FILESYSTEM-namespace server under
  ``/data/data/<own-pkg>/`` (private-dir scoped, reachable only by
  same-UID processes).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class LocalSocketServerAgent(BaseAgent):
    """D_022: classify LocalServerSocket exposure at runtime."""

    AGENT_ID = "D_022"
    VULN_CLASS = "Local-Socket Server Exposed Across App Boundary"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_022] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        own_pkg = (self._context.manifest or {}).get("package") or ""
        abstract_hits: list[dict[str, Any]] = []
        cross_uid_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "local_socket.server_created":
                continue
            payload = ev.payload or {}
            namespace = str(payload.get("namespace") or "").upper()
            name = str(payload.get("name") or "")
            sample = {
                "namespace": namespace,
                "name": name,
                "stack": payload.get("stack"),
            }
            if namespace == "ABSTRACT":
                abstract_hits.append(sample)
            elif namespace in ("FILESYSTEM", "RESERVED"):
                if _is_cross_uid(name, own_pkg):
                    cross_uid_hits.append(sample)

        findings: list[Finding] = []
        if abstract_hits:
            findings.append(self._abstract_finding(abstract_hits))
        if cross_uid_hits:
            findings.append(self._cross_uid_finding(cross_uid_hits))
        return findings

    def _abstract_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application opened a LocalServerSocket in "
                    "the ABSTRACT namespace at runtime. The abstract "
                    "namespace lives in the kernel and ignores "
                    "filesystem permissions — any process on the "
                    "device can ``connect`` to the socket. Stetho, "
                    "older Bugsnag NDK builds, gdb-server, and Frida "
                    "use this same pattern as a debug back-channel; "
                    "left in a release build, the socket is an "
                    "arbitrary command channel."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on LocalServerSocket.<init> captured "
                    "the namespace argument."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Move the server to the FILESYSTEM namespace under "
                "``getFilesDir()`` so the app's UID owns the path. "
                "If the server is a debug-only feature, gate the "
                "open() call on ``BuildConfig.DEBUG``. If the server "
                "is part of a release build, audit the protocol — "
                "every accepted command should be authenticated."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def _cross_uid_finding(
        self, hits: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="LocalServerSocket Outside Private Dir",
            severity=Severity.MEDIUM,
            confidence=0.75,
            evidence={
                "issue": (
                    "The application opened a LocalServerSocket in "
                    "the FILESYSTEM namespace at a path outside its "
                    "own ``/data/data/<pkg>/`` directory (typically "
                    "``/data/local/tmp``). Any process whose UID has "
                    "FS access to the path can connect."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on LocalServerSocket.<init> captured "
                    "a path not rooted at the app's private directory."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Move the socket path to ``getFilesDir()`` or "
                "``getCacheDir()`` so only the app's UID can open "
                "it. Drop ``/data/local/tmp`` and other shared paths."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        )


def _is_cross_uid(name: str, own_pkg: str) -> bool:
    lower = name.lower()
    if not lower:
        return False
    if "/data/local/tmp" in lower:
        return True
    if own_pkg and f"/data/data/{own_pkg.lower()}/" in lower:
        return False
    if lower.startswith("/data/data/"):
        # Path is under another package's private dir — definitely
        # cross-UID.
        return True
    if lower.startswith("/sdcard/") or lower.startswith("/storage/"):
        return True
    return False
