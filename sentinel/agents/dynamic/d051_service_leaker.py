"""D_051 — Exported-Service leaker (Dynamic Testing Target).

Walks the manifest for `<service>` entries with `exported="true"` and
no `permission` attribute, then identifies the implementation class
for each (Service / IntentService / JobIntentService / AccessibilityService
subclass) and emits a Frida payload that bind / sends malicious
intents to each exported service.

The DAST hook's payload bag carries:

  * the action string from any matching intent-filter (or
    `android.intent.action.MAIN` when none is declared)
  * a short list of crafted extras (`isAdmin=true`,
    `command="getSecret"`, etc.)
  * a SafetyBudget envelope (15 binds, 1/s, 30s wall clock)

When the service exposes a Binder interface (AIDL), the Frida hook
calls `bindService(...)` with a `ServiceConnection` and inspects the
returned `IBinder` for callable methods via reflection — that's
enumeration, not exploitation. The exploitation half is left to the
human reviewer using the enumerated method list.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_SERVICE_BASE_RE = re.compile(
    r"\bextends\s+(Service|IntentService|JobIntentService|"
    r"AccessibilityService|NotificationListenerService|"
    r"TileService|HostApduService|TextToSpeech\.Engine)\b"
)
_ONHANDLE_RE = re.compile(
    r"\b(onHandleIntent|onStartCommand|onBind|onAccessibilityEvent)\s*\("
)

# Stock probe extras — the dynamic hook will rewrite per-service.
_PROBE_EXTRAS: list[dict[str, Any]] = [
    {"isAdmin": True, "command": "getSecret"},
    {"user_role": "admin", "force": True},
    {"debug": True, "verbose": True, "include_pii": True},
    {"action": "wipe_all"},
    {"target_account": "all", "delete_all": True},
    {"intent.extra.from": "../../databases/auth.db"},
]

_MAX_FILES = 2000
_MAX_SERVICES = 50


class ServiceLeakerAgent(BaseAgent):
    """D_051: enumerate exported services + emit bind + intent payload."""

    AGENT_ID = "D_051"
    VULN_CLASS = "Exported Service Bind / Probe (Dynamic Testing Target)"
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
        manifest = ctx.manifest or {}
        services = self._exported_services(manifest)
        if not services:
            return []

        root = ctx.decompiled_dir
        if root is None:
            return []

        # Build an index of Service-subclass files for cross-ref
        impl_index = self._index_service_impls(root)

        findings: list[Finding] = []
        for svc in services[:_MAX_SERVICES]:
            name = svc.get("name", "")
            simple = name.rsplit(".", 1)[-1]
            impl_files = impl_index.get(simple, [])
            actions = self._service_actions(svc)
            payload = self._build_payload(svc, actions)
            severity = (
                Severity.HIGH
                if any(a.endswith(".BIND") or "ADMIN" in a for a in actions)
                else Severity.MEDIUM
            )
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.70,
                recommendation=(
                    f"Service `{name}` is exported with no permission "
                    "guard. The Frida DAST hook will bind to it with "
                    f"action(s) {actions} and the curated probe extras, "
                    "enumerate any AIDL methods exposed on the returned "
                    "IBinder, and record the response. Add an explicit "
                    "permission attribute and reject every intent whose "
                    "extras don't match the declared schema."
                ),
                evidence={
                    "service": name,
                    "actions": actions,
                    "impl_files": impl_files[:3],
                    "dynamic_target": True,
                    "frida_payload": payload,
                },
            ))
        return findings

    # ---------- manifest helpers ----------

    @staticmethod
    def _exported_services(manifest: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for s in manifest.get("services", []) or []:
            if not isinstance(s, dict):
                continue
            if s.get("exported") is True and not s.get("permission"):
                out.append(s)
        return out

    @staticmethod
    def _service_actions(svc: dict[str, Any]) -> list[str]:
        actions: set[str] = set()
        for f in svc.get("intent_filters", []) or []:
            if not isinstance(f, dict):
                continue
            for a in (f.get("actions") or []):
                if isinstance(a, str):
                    actions.add(a)
            if isinstance(f.get("action"), str):
                actions.add(f["action"])
        return sorted(actions) or ["android.intent.action.MAIN"]

    # ---------- Java cross-ref ----------

    @staticmethod
    def _index_service_impls(root: Path) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        scanned = 0
        for p in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = p.read_text(encoding="utf-8", errors="replace")[:8000]
            except OSError:
                continue
            if not _SERVICE_BASE_RE.search(text):
                continue
            if not _ONHANDLE_RE.search(text):
                continue
            simple = p.stem.split("$")[0]
            out.setdefault(simple, []).append(str(p.relative_to(root)))
        return out

    # ---------- payload ----------

    @staticmethod
    def _build_payload(
        svc: dict[str, Any], actions: list[str],
    ) -> dict[str, Any]:
        return {
            "service_name": svc.get("name", ""),
            "actions": actions,
            "probe_extras": _PROBE_EXTRAS,
            "enumerate_aidl": True,
            "safety_budget": {
                "max_actions_total": 15,
                "max_actions_per_sec": 1,
                "wall_clock_budget_s": 30,
                "max_consecutive_crashes": 3,
            },
            "frida_script_hint":
                "// D_051 — bindService with crafted intents and "
                "enumerate AIDL\n"
                f"// service = {svc.get('name', '')}\n"
                "// rpc.exports.serviceprobe(payload) is the entry\n",
        }


__all__ = ["ServiceLeakerAgent"]
