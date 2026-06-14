"""P_011: Exported-Receiver Chain Hijack Detection.

Complements P_010 (IntentRedirectAgent). P_010 catches the case where a
whole ``Intent`` object pulled from ``getParcelableExtra`` is dispatched
through ``startActivity`` / ``sendBroadcast``. This agent targets the
*receiver-chain* variant: an exported ``BroadcastReceiver`` extracts a
*string or Uri* extra from the incoming ``Intent`` and uses it to
construct a brand-new ``Intent`` (setAction / setData / setPackage /
setComponent / setClassName / ``new Intent(action)``) that is then
re-dispatched. The newly built Intent's authority is attacker-controlled
even though the original Intent object isn't.

Why it's a distinct bug class
-----------------------------
The chain pattern is more common than full Intent reuse and tends to
look innocent in code review — a receiver that "just forwards the
notification" is the canonical case. The exploit primitive is the same
confused-deputy as CWE-926, but the source/sink shape differs.

Scope and FP control
--------------------
We only audit receivers the manifest declares as ``exported="true"`` and
whose ``android:permission`` is empty or normal-protection-level (we
don't know the level here, but the manifest entry tells us whether ANY
permission is set — see IPC_001 for protection-level audit). Non-exported
receivers can only be reached by the app itself or a signature-matched
peer, so the chain isn't externally reachable.

We do not call into tree-sitter — this is a regex pass over the
``onReceive`` method body. The combined source/sink heuristic is enough
to ship at confidence 0.55–0.75.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

# Source: read a STRING / Uri extra from the inbound intent (the
# parameter name is whatever the receiver chooses, so we just look for
# ``.getStringExtra(``, ``.getDataString(``, ``.getData(``,
# ``.getStringArrayListExtra(``, or a chained ``.getExtras().getString(``.
_SOURCE_PATTERN = re.compile(
    r"\.(getStringExtra|getDataString|getData|"
    r"getStringArrayListExtra|getCharSequenceExtra)\s*\(",
)
_BUNDLE_SOURCE_PATTERN = re.compile(
    r"\.getExtras\s*\(\s*\)\s*\.(getString|getCharSequence)\s*\(",
)

# Sink: the new-intent authority is attacker-controlled. Either the
# Intent ctor takes a string (the action) directly, or one of the
# setter methods that re-targets the Intent is invoked.
_NEW_INTENT_FROM_STRING = re.compile(
    r"new\s+Intent\s*\(\s*[A-Za-z_]\w*\s*\)",
)
_SINK_SETTERS = re.compile(
    r"\.(setAction|setData|setDataAndType|setPackage|"
    r"setComponent|setClassName|setSelector)\s*\(",
)

# Dispatch: the new Intent gets sent.
_DISPATCH_PATTERN = re.compile(
    r"\.(sendBroadcast(AsUser|OrderedBroadcast)?|sendStickyBroadcast|"
    r"startActivity(ForResult|IfNeeded|FromChild)?|startActivities|"
    r"startService|startForegroundService|bindService|"
    r"startIntentSender)\s*\(",
)

# onReceive method body — best-effort brace-balanced extractor below
# replaces this; this regex only locates the entry point.
_ONRECEIVE_HEAD = re.compile(
    r"(public\s+)?void\s+onReceive\s*\("
    r"\s*Context\s+\w+\s*,\s*Intent\s+\w+\s*\)",
)


def _extract_method_body(source: str, head_end: int) -> str | None:
    """Brace-balanced slice from the ``{`` after the head to its match.

    ``head_end`` points just past the closing ``)`` of the method head.
    Returns the body text (without the outer braces) or ``None`` if the
    braces are unbalanced — that happens in heavily obfuscated dumps and
    we just skip the receiver rather than crash.
    """
    open_idx = source.find("{", head_end)
    if open_idx == -1:
        return None
    depth = 0
    for i in range(open_idx, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[open_idx + 1 : i]
    return None


class ReceiverChainHijackAgent(BaseAgent):
    """Detect exported-receiver chain-hijack patterns."""

    AGENT_ID = "P_011"
    VULN_CLASS = "Receiver Chain Hijack"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        manifest = self._context.manifest or {}
        if not self._context.decompiled_dir:
            return False
        return any(
            c.get("type") == "receiver"
            for c in (manifest.get("exported_components") or [])
        )

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        manifest = self._context.manifest or {}
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return findings

        receivers = [
            c for c in (manifest.get("exported_components") or [])
            if c.get("type") == "receiver"
        ]

        for receiver in receivers:
            fqcn: str = receiver.get("name") or ""
            permission: str = receiver.get("permission") or ""
            if not fqcn:
                continue

            class_name = fqcn.rsplit(".", 1)[-1]
            for java_file in decompiled.rglob(f"{class_name}.java"):
                try:
                    source = java_file.read_text(errors="replace")
                except OSError:
                    continue

                head_match = _ONRECEIVE_HEAD.search(source)
                if not head_match:
                    continue
                body = _extract_method_body(source, head_match.end())
                if not body:
                    continue

                has_source = bool(
                    _SOURCE_PATTERN.search(body)
                    or _BUNDLE_SOURCE_PATTERN.search(body)
                )
                if not has_source:
                    continue

                has_new_intent = bool(_NEW_INTENT_FROM_STRING.search(body))
                has_setter = bool(_SINK_SETTERS.search(body))
                has_dispatch = bool(_DISPATCH_PATTERN.search(body))
                if not has_dispatch or not (has_new_intent or has_setter):
                    continue

                severity, confidence = self._score(
                    permission=permission,
                    has_new_intent=has_new_intent,
                    has_setter=has_setter,
                )

                findings.append(self._make_finding(
                    vuln_class="Receiver Chain Hijack",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "receiver": fqcn,
                        "file": str(java_file.relative_to(decompiled)),
                        "permission": permission or "<none>",
                        "pattern": self._describe(
                            has_new_intent=has_new_intent,
                            has_setter=has_setter,
                        ),
                        "snippet": body[:400],
                    },
                    recommendation=(
                        "Treat all inbound Intent extras as untrusted. Do "
                        "not re-emit them as the action / package / "
                        "component / data of a new Intent without "
                        "validating against an allowlist. Set "
                        "android:exported=\"false\" or guard with a "
                        "signature-level android:permission on the "
                        "receiver if external delivery is not required."
                    ),
                    owasp="M1: Improper Platform Usage",
                    masvs="MSTG-PLATFORM-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
                        if not permission
                        else "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
                    ),
                ))
                break  # one finding per receiver class

        return findings

    @staticmethod
    def _score(
        *,
        permission: str,
        has_new_intent: bool,
        has_setter: bool,
    ) -> tuple[Severity, float]:
        if not permission:
            base_conf = 0.75 if (has_new_intent and has_setter) else 0.65
            return Severity.HIGH, base_conf
        # Any permission set — protection level is checked by IPC_001;
        # demote here to avoid double counting.
        return Severity.MEDIUM, 0.55

    @staticmethod
    def _describe(*, has_new_intent: bool, has_setter: bool) -> str:
        parts: list[str] = []
        if has_new_intent:
            parts.append("new Intent(<extra>)")
        if has_setter:
            parts.append("setAction/setData/setPackage/setComponent")
        return " + ".join(parts) + " then dispatched"
