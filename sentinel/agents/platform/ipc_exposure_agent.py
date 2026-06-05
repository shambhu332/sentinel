"""IPC_001 — IPC Exposure Agent.

Audits exported Activities, Services, and BroadcastReceivers (everything
*except* ContentProviders, which P_004 covers) for missing permission
guards. An exported component without an android:permission is callable
by any installed app on the device.

Why this matters: this is the bread-and-butter Android privilege
escalation surface. Examples that ship to bug-bounty regularly:
- Exported Activity that returns sensitive data via setResult()
- Exported Service that accepts an Intent with a file path and reads it
- Exported BroadcastReceiver that mutates app state on a sender-trusted
  Intent extra

Detection:
1. ctx.manifest['exported_components'] lists every exported component
   (manifest parser already filters to is_exported=true or
   has_intent_filter)
2. We split by type and bucket each into one of three risk tiers:
   - exposed without permission AND has intent filter → HIGH
     (third-party apps can find and invoke via implicit intent)
   - exposed without permission, no intent filter → MEDIUM
     (third-party apps need to know the fully-qualified name to call)
   - exposed WITH a permission but the permission's protectionLevel
     was not verified → LOW (situational awareness; many apps mark a
     custom permission as 'normal' which doesn't actually gate access)

Severity is then bumped one tier for known-dangerous types
(BroadcastReceivers receiving system actions, Services accepting
arbitrary Intent extras based on naming heuristics).

Deliberate non-goals (left for later sprints):
- Per-component source analysis (verify what the component actually
  does with caller-controlled data). Requires JADX + AST work.
- Custom permission protectionLevel resolution. Requires manifest
  permission declarations to be tracked.
"""
from __future__ import annotations

import logging
import re
from typing import Iterable

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_DANGEROUS_NAME_HINTS = re.compile(
    r"(?:admin|auth|login|payment|pay|order|account|debug|backup|"
    r"export|import|share|file|provider|sync|migrate|root|shell)",
    re.IGNORECASE,
)

# ContentProviders are P_004's job — we deliberately skip them.
_HANDLED_TYPES = {"activity", "service", "receiver"}


class IpcExposureAgent(BaseAgent):
    """IPC_001: flags exported Activities/Services/Receivers without
    permission guards.
    """

    AGENT_ID = "IPC_001"
    VULN_CLASS = "Exposed IPC Component"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        components = (self._context.manifest or {}).get("exported_components")
        if not components:
            logger.info("[IPC_001] No exported components — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        components = (ctx.manifest or {}).get("exported_components") or []

        findings: list[Finding] = []
        # Bucketize: (component_type, has_permission, has_filter) →
        # list of component dicts
        buckets: dict[tuple[str, bool, bool], list[dict]] = {}
        for c in components:
            ctype = (c.get("type") or "").lower()
            if ctype not in _HANDLED_TYPES:
                continue
            has_perm = bool((c.get("permission") or "").strip())
            has_filter = bool(c.get("has_intent_filter"))
            buckets.setdefault((ctype, has_perm, has_filter), []).append(c)

        for (ctype, has_perm, has_filter), entries in buckets.items():
            severity, confidence, title, rec = self._classify(
                ctype, has_perm, has_filter, entries,
            )
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=confidence,
                recommendation=rec,
                evidence={
                    "title": title,
                    "component_type": ctype,
                    "has_permission_guard": has_perm,
                    "has_intent_filter": has_filter,
                    "count": len(entries),
                    "components": [
                        {
                            "name": e.get("name", ""),
                            "permission": e.get("permission", ""),
                        }
                        for e in entries[:25]
                    ],
                    "truncated": len(entries) > 25,
                },
            ))

        return findings

    def _classify(
        self,
        ctype: str,
        has_perm: bool,
        has_filter: bool,
        entries: list[dict],
    ) -> tuple[Severity, float, str, str]:
        # Type-base severity
        type_base = {
            "activity": Severity.MEDIUM,
            "service": Severity.HIGH,
            "receiver": Severity.HIGH,
        }.get(ctype, Severity.MEDIUM)

        if has_perm:
            # Has a guard but the guard's protectionLevel wasn't verified
            return (
                Severity.LOW,
                0.65,
                f"Exported {ctype}(s) with permission guard ({len(entries)})",
                (
                    f"{len(entries)} exported {ctype}(s) declare an "
                    "android:permission. Verify each permission's "
                    "protectionLevel is 'signature' or 'signatureOrSystem' "
                    "— a 'normal' or 'dangerous' protectionLevel still "
                    "grants any installed app access on user grant. "
                    "Permissions you DEFINE must declare protectionLevel "
                    "in the same manifest; do not rely on undeclared "
                    "custom permissions."
                ),
            )

        # No permission. Sensitivity scales with discoverability + type.
        suspicious = [
            e for e in entries
            if _DANGEROUS_NAME_HINTS.search(e.get("name", ""))
        ]
        has_dangerous_name = bool(suspicious)

        if has_filter and has_dangerous_name:
            severity = _bump(type_base)
            confidence = 0.85
            extra = (
                "Component name(s) match high-risk hints "
                f"({', '.join(s.get('name','') for s in suspicious[:3])}...). "
            )
        elif has_filter:
            severity = type_base
            confidence = 0.80
            extra = ""
        else:
            # Exported but no intent-filter → callable only by fully-
            # qualified name. Still a bug, but less discoverable.
            severity = _demote(type_base)
            confidence = 0.70
            extra = (
                "No intent-filter, so third-party apps must know the "
                "fully-qualified component name to invoke it. Static "
                "analysis of decompiled callers reveals such names "
                "trivially. "
            )

        title = (
            f"Exported {ctype}(s) without permission guard "
            f"({len(entries)})"
        )
        rec = (
            f"{len(entries)} exported Android {ctype}(s) lack an "
            f"android:permission attribute and can be invoked by any "
            f"app on the device. {extra}"
            "Fix: set android:permission to a signature-protected "
            "permission, or set android:exported=\"false\" if cross-app "
            "access is not intended. For each component, also audit the "
            "code path that handles incoming Intent extras — assume "
            "caller-controlled data and validate accordingly."
        )
        return severity, confidence, title, rec


def _bump(s: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]
    i = order.index(s)
    return order[min(i + 1, len(order) - 1)]


def _demote(s: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]
    i = order.index(s)
    return order[max(i - 1, 0)]


__all__: Iterable[str] = ["IpcExposureAgent"]
