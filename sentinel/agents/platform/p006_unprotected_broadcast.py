"""P_006: Unprotected sendBroadcast Detection.

``Context.sendBroadcast(intent)`` without a receiver permission
delivers the Intent to *every* installed app whose manifest declares
the action — including malware that happens to register the same
filter. If the Intent carries auth state (login result, OTP code,
payment status, FCM token, internal event ID) or holds sensitive
extras, any sibling app can eavesdrop.

Android's recommended pattern is one of:

* ``sendBroadcast(intent, "signature-level permission")`` — the
  receiver must hold the named permission, declared with
  ``protectionLevel="signature"`` so only the same publisher's
  apps can receive.
* ``LocalBroadcastManager.sendBroadcast(intent)`` — in-process only.
  ``LocalBroadcastManager`` was deprecated in androidx but the
  modern equivalents are ``MutableSharedFlow`` /
  ``StateFlow`` / ``LiveData`` — none of which leave the process.
* ``intent.setPackage(getPackageName())`` — restricts delivery to
  this app's own receivers.

Detection
=========

For every ``sendBroadcast(`` / ``sendStickyBroadcast(`` /
``sendOrderedBroadcast(`` / ``sendBroadcastAsUser(`` call:

* Skip if the call has ≥ 2 arguments AND the second isn't ``null``
  (the second arg is the receiver permission).
* Skip if the Intent variable is target-pinned in the same method
  (``setPackage`` / ``setComponent`` / ``setClassName`` / a
  ``new Intent(Context, Class.class)`` ctor).
* Otherwise, look at the Intent's action / extras in scope for
  sensitive keywords. If matched → CRITICAL; if not → HIGH (still
  externally observable, just lower assumed payload value).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_BROADCAST_CALL = re.compile(
    r"\.\s*(sendBroadcast|sendStickyBroadcast|sendOrderedBroadcast|"
    r"sendBroadcastAsUser|sendStickyBroadcastAsUser)\s*\(",
)
_TARGET_PIN = re.compile(
    r"\.(setPackage|setComponent|setClassName|setSelector)\s*\(",
)
_EXPLICIT_INTENT_CTOR = re.compile(
    r"new\s+Intent\s*\(\s*[A-Za-z_]\w*\s*,\s*[A-Za-z_][\w$.]*\.class\s*\)",
)
_SENSITIVE_KEYWORDS = re.compile(
    r"\b("
    r"token|password|secret|auth|credential|otp|two_factor|2fa|"
    r"payment|wallet|account|biometric|fingerprint|pin|"
    r"private[_-]?key|session|refresh|access[_-]?token|fcm"
    r")\b",
    re.IGNORECASE,
)


def _balanced_args(source: str, paren_start: int) -> str | None:
    if paren_start >= len(source) or source[paren_start] != "(":
        return None
    depth = 0
    for i in range(paren_start, len(source)):
        ch = source[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[paren_start + 1 : i]
    return None


def _split_top_level_commas(args: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    last = 0
    for i, ch in enumerate(args):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(args[last:i].strip())
            last = i + 1
    parts.append(args[last:].strip())
    return parts


def _enclosing_method_body(source: str, idx: int) -> str | None:
    open_idx = source.rfind("{", 0, idx)
    while open_idx != -1:
        depth = 0
        i = open_idx
        while i < len(source):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    if i >= idx:
                        return source[open_idx + 1 : i]
                    break
            i += 1
        open_idx = source.rfind("{", 0, open_idx)
    return None


class UnprotectedBroadcastAgent(BaseAgent):
    """Flag sendBroadcast calls with no receiver permission and no target pin."""

    AGENT_ID = "P_006"
    VULN_CLASS = "Unprotected Broadcast"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            if not _BROADCAST_CALL.search(source):
                continue
            rel = str(java_file.relative_to(decompiled))

            for m in _BROADCAST_CALL.finditer(source):
                paren_idx = source.find("(", m.start())
                args = _balanced_args(source, paren_idx)
                if args is None:
                    continue
                parts = _split_top_level_commas(args)
                # Skip if permission argument is present (non-null).
                if len(parts) >= 2 and parts[1].strip().lower() != "null":
                    continue
                intent_arg = parts[0] if parts else ""

                body = _enclosing_method_body(source, m.start()) or ""
                if not body:
                    continue
                if self._target_pinned(body, intent_arg):
                    continue

                sensitive_match = _SENSITIVE_KEYWORDS.search(body)
                severity = Severity.CRITICAL if sensitive_match else Severity.HIGH
                confidence = 0.85 if sensitive_match else 0.70

                findings.append(self._make_finding(
                    vuln_class="Unprotected Broadcast",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "method": m.group(1),
                        "intent_arg": intent_arg[:80],
                        "sensitive_keyword": (
                            sensitive_match.group(1).lower()
                            if sensitive_match else None
                        ),
                        "issue": (
                            "Intent is broadcast without a receiver "
                            "permission argument and without a "
                            "setPackage / setComponent / setClassName "
                            "pin. Every app on the device that "
                            "registers the action receives the Intent."
                        ),
                    },
                    recommendation=(
                        "Either pass a signature-level permission to "
                        "the sendBroadcast call so only your own "
                        "publisher apps can receive, or pin the Intent "
                        "with intent.setPackage(getPackageName()) for "
                        "single-app delivery. For pure in-process "
                        "fan-out, switch from broadcasts to "
                        "MutableSharedFlow / StateFlow / LiveData — "
                        "they never leave the process."
                    ),
                    owasp="M1: Improper Platform Usage",
                    masvs="MSTG-PLATFORM-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _target_pinned(body: str, intent_var: str) -> bool:
        if _EXPLICIT_INTENT_CTOR.search(body):
            return True
        if not intent_var:
            return False
        var = intent_var.strip().split()[-1]
        if not var.isidentifier():
            return False
        pinned = re.compile(
            r"\b" + re.escape(var) + r"\b" + _TARGET_PIN.pattern,
        )
        return bool(pinned.search(body))
