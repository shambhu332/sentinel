"""D_005 — Dynamic Code Loading.

Android's dynamic class loaders let an app pull bytecode or native
libraries at runtime:

* ``DexClassLoader``         — load a ``.dex`` / ``.jar`` from a path
* ``PathClassLoader``        — variant of above
* ``InMemoryDexClassLoader`` — load bytecode directly from a buffer
* ``System.load(path)``      — load a ``.so`` from an arbitrary path
* ``Runtime.exec``           — invoke an external binary

These are the canonical Trojan / RAT primitive: ship a thin shell on
the Play Store, fetch the real payload on first launch from a server
the attacker owns. Even non-malicious apps that load code from
``/sdcard`` or a cache filled from the network grant any other app a
silent code-injection foothold.

Detection
---------

We consume Frida events of kind ``code_loading.dex_load`` and
``code_loading.native_load`` and ``code_loading.exec``. Each payload
carries the resolved path, the optional parent loader class, and a
caller stack. We flag:

* CRITICAL — path is on ``/sdcard``, ``/storage/emulated``, an
  external cache, or a temp location world-writable by other apps.
* HIGH     — path lives under the app's cache / files directory but
  was *not* shipped in the APK (heuristic: caller stack mentions an
  HTTP / WebView / OkHttp download). Persisted attacker code re-runs
  on every launch.
* MEDIUM   — path lives under the app's protected directory and the
  agent has no signal it came from the network. Still worth reporting
  because the threat model expands: any attacker with FS access can
  pivot.
* No finding — path is exactly the APK's bundled ``.dex`` / ``.so``.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_EXTERNAL_PREFIXES = (
    "/sdcard", "/storage/emulated", "/storage/sdcard",
    "/mnt/sdcard", "/data/local/tmp",
)
_APK_DIRS = ("base.apk", "/data/app/", "lib/")
_NETWORK_HINT = (
    "okhttp", "httpurl", "downloadmanager", "retrofit",
    "ktor", "volley", "webview", "fetch",
)


class DynamicCodeLoadingAgent(BaseAgent):
    """D_005: detect runtime DEX / native / exec loads from suspect paths."""

    AGENT_ID = "D_005"
    VULN_CLASS = "Dynamic Code Loading"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_005] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        findings: list[Finding] = []
        package = (self._context.manifest or {}).get("package") or ""
        for ev in capture.events:
            if ev.kind not in (
                "code_loading.dex_load",
                "code_loading.native_load",
                "code_loading.exec",
            ):
                continue
            payload = ev.payload or {}
            severity = self._classify(payload, package)
            if severity is None:
                continue
            findings.append(self._finding(ev.kind, payload, severity))
        return findings

    @staticmethod
    def _classify(payload: dict[str, Any], package: str) -> Severity | None:
        path = str(payload.get("path") or "").strip()
        if not path:
            return None
        lower = path.lower()

        # Bundled-in-APK loads are uninteresting.
        if any(d in lower for d in _APK_DIRS):
            return None

        # External storage = anyone-can-write = CRITICAL.
        if any(lower.startswith(prefix) for prefix in _EXTERNAL_PREFIXES):
            return Severity.CRITICAL

        stack = str(payload.get("stack") or "").lower()
        is_network_origin = any(h in stack for h in _NETWORK_HINT)
        in_app_private = f"/data/data/{package}".lower() in lower
        in_app_cache = "/cache/" in lower or "/files/" in lower

        if in_app_private and is_network_origin:
            return Severity.HIGH
        if in_app_cache:
            return Severity.HIGH if is_network_origin else Severity.MEDIUM
        # Path the heuristics don't recognise → report as MEDIUM so a
        # reviewer can decide.
        return Severity.MEDIUM

    def _finding(
        self,
        kind: str,
        payload: dict[str, Any],
        severity: Severity,
    ) -> Finding:
        loader_class = payload.get("loader_class") or kind
        path = payload.get("path") or "?"
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application loaded executable code at runtime "
                    f"via {loader_class!r} from a non-APK source. The "
                    "loaded module runs with the application's full "
                    "permissions. Any attacker who can write to the "
                    "source path has complete code-execution against "
                    "the app's identity."
                ),
                "loader_class": loader_class,
                "path": path,
                "stack": payload.get("stack"),
                "vector": (
                    "Frida hooks on DexClassLoader / PathClassLoader / "
                    "InMemoryDexClassLoader constructors, System.load, "
                    "and Runtime.exec captured the load event with the "
                    "resolved source path."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Do not load code from external storage, world-writable "
                "directories, or cache populated from the network. If "
                "the feature requires downloaded modules, verify the "
                "module against a server-signed manifest and a pinned "
                "public key before passing the path to the class "
                "loader. The Play Store explicitly forbids loading "
                "executable code via the Dynamic Code Loading APIs "
                "from sources outside the APK — non-APK loads risk "
                "store delisting in addition to the security impact."
            ),
            owasp="M7: Client Code Quality",
            masvs="MSTG-CODE-9",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        )
