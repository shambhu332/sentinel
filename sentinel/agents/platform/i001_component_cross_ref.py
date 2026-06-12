"""I_001 — Manifest ↔ Java exported-component cross-reference.

The manifest says an Activity is `exported="true"`. Does the Java
`onCreate` actually call `checkCallingOrSelfPermission` (or a wrapper)
before doing anything? If not, the component is unprotected and any
app on the device can launch it with attacker-controlled extras.

Existing agents only check the manifest side (`P_*` family) or the
Java side (`B_*` family); none cross-reference the two. This is where
real bugs hide — the manifest looks fine in isolation, the activity
class looks fine in isolation, but together they expose an
unauthenticated kernel into your app.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Permission-check API surface that satisfies "the activity guards itself"
_GUARD_TOKENS = (
    "checkCallingOrSelfPermission",
    "checkCallingPermission",
    "enforceCallingOrSelfPermission",
    "enforceCallingPermission",
    "checkPermission",
    "getCallingPackage",       # at least proves they're checking who called
    "getCallingActivity",
)

# Cap files probed for the Java side
_MAX_PROBES = 200


class ComponentCrossRefAgent(BaseAgent):
    """I_001: flags exported components whose onCreate skips the auth gate."""

    AGENT_ID = "I_001"
    VULN_CLASS = "Unprotected Exported Component"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.manifest
            and ctx.decompiled_dir
            and ctx.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        manifest = ctx.manifest or {}
        activities = manifest.get("activities", []) or []

        # Activity entries from the manifest parser are dicts with
        # `name`, `exported`, optional `permission`, etc. We only care
        # about exported activities that have NO declared permission —
        # those are the candidates for runtime self-guarding.
        candidates = [
            a for a in activities
            if isinstance(a, dict)
            and a.get("exported") is True
            and not a.get("permission")
        ]
        if not candidates:
            return []

        findings: list[Finding] = []
        probed = 0
        for activity in candidates:
            if probed >= _MAX_PROBES:
                break
            probed += 1
            name = activity.get("name", "")
            if not name:
                continue
            path = self._locate_class(name)
            if path is None:
                # Java source not found — likely Kotlin or framework
                # shim; emit a lower-confidence finding.
                findings.append(self._emit(activity, source_file=None,
                                           reason="Java source not located"))
                continue
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if self._has_guard(src):
                continue
            findings.append(self._emit(
                activity, source_file=str(path.relative_to(ctx.decompiled_dir)),
                reason="onCreate lacks any permission-check call",
            ))
        return findings

    # ---------- helpers ----------

    def _locate_class(self, fqcn: str) -> Path | None:
        """Resolve a fully-qualified class name to a decompiled .java file."""
        ctx = self._context
        rel = fqcn.replace(".", "/") + ".java"
        candidate = (ctx.decompiled_dir or Path()) / "sources" / rel
        if candidate.is_file():
            return candidate
        # JADX layout sometimes omits the "sources" prefix
        candidate = (ctx.decompiled_dir or Path()) / rel
        if candidate.is_file():
            return candidate
        # Last resort: glob the basename. Slow but bounded.
        basename = fqcn.rsplit(".", 1)[-1] + ".java"
        for path in (ctx.decompiled_dir or Path()).rglob(basename):
            return path
        return None

    @staticmethod
    def _has_guard(src: str) -> bool:
        # Cheap check: did onCreate (or a method it calls) reference any
        # of the permission-guard tokens anywhere in the file?
        return any(tok in src for tok in _GUARD_TOKENS)

    def _emit(
        self, activity: dict[str, Any], source_file: str | None, reason: str,
    ) -> Finding:
        name = activity.get("name", "")
        intent_filters = activity.get("intent_filters") or []
        # If the activity also accepts an implicit VIEW with an http(s)
        # scheme, exposure surface is higher — escalate to HIGH.
        accepts_view = any(
            (f.get("action") == "android.intent.action.VIEW"
             or "VIEW" in (f.get("actions") or []))
            for f in intent_filters
        ) if isinstance(intent_filters, list) else False
        severity = Severity.HIGH if accepts_view else Severity.MEDIUM
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.80 if source_file else 0.55,
            recommendation=(
                "Either declare a custom permission on this activity in the "
                "manifest, or add a `checkCallingOrSelfPermission` (or "
                "`enforceCallingOrSelfPermission`) call as the first "
                "statement of onCreate. Activities that handle "
                "VIEW intents are the most exposed: any installed app can "
                "fire them via Intent.ACTION_VIEW."
            ),
            evidence={
                "activity": name,
                "source_file": source_file or "(not located)",
                "reason": reason,
                "accepts_view": accepts_view,
                "intent_filter_count": (
                    len(intent_filters) if isinstance(intent_filters, list) else 0
                ),
            },
        )


__all__ = ["ComponentCrossRefAgent"]
