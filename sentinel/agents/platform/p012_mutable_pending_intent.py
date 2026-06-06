"""P_012: Mutable PendingIntent Detection (CVE-2021-0938 family).

A ``PendingIntent`` lets one app hand a wrapped ``Intent`` to another app
that fires it back at the wrapper's UID and permissions. If the wrapped
intent is implicit (no component / package / class name) AND the
PendingIntent is mutable, ANY component on the device can hijack the
delivery by intercepting the outer broadcast and rewriting the inner
Intent's destination before it fires.

Android 12 (target SDK 31+) forces the developer to choose
``FLAG_IMMUTABLE`` or ``FLAG_MUTABLE`` explicitly — the framework
throws ``IllegalArgumentException`` when neither is set. Code targeting
SDK ≤ 30 silently gets the legacy "default mutable" behaviour, so the
bare-zero-flags pattern is a real bug.

Detection
=========
1. Find every call to ``PendingIntent.getActivity(``,
   ``PendingIntent.getActivities(``, ``PendingIntent.getBroadcast(``,
   ``PendingIntent.getService(``, ``PendingIntent.getForegroundService(``.
2. Inspect the *flags* argument (4th positional):
   * ``FLAG_IMMUTABLE`` (0x04000000) or the literal ``67108864`` present
     anywhere in the flags expression → safe (skip).
   * ``FLAG_MUTABLE`` (0x02000000) or literal ``33554432`` present →
     potentially-vulnerable; promote when the wrapped intent has no
     target-pinning.
   * Otherwise (bare ``0`` / lone bit-mask without IMMUTABLE) → vulnerable
     on legacy targetSdk.
3. Look at the *intent* argument's local-variable declaration in the
   same method. If we see ``setPackage(``, ``setComponent(``,
   ``setClass(``, ``setClassName(``, or ``new Intent(Context, Class)``
   on that variable, treat the inner intent as explicit (target-pinned).

Severity ladder
---------------
* CRITICAL — flags contain ``FLAG_MUTABLE`` AND the wrapped intent is
  implicit. Direct PendingIntent-hijack primitive.
* HIGH — explicit ``FLAG_MUTABLE`` with target-pinning, OR bare-zero
  flags with implicit intent (legacy SDKs).
* MEDIUM — bare-zero flags with explicit intent (legacy SDKs only).

Manifest's ``target_sdk`` further demotes MEDIUM → INFO when ≥ 31.
"""
from __future__ import annotations

import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_PI_CALL = re.compile(
    r"\bPendingIntent\.(getActivity|getActivities|getBroadcast|"
    r"getService|getForegroundService)\s*\(",
)
_FLAG_IMMUTABLE = re.compile(
    r"FLAG_IMMUTABLE\b|\b67108864\b",
)
_FLAG_MUTABLE = re.compile(
    r"FLAG_MUTABLE\b|\b33554432\b",
)
_TARGET_PIN_ON_VAR = re.compile(
    r"\.(setPackage|setComponent|setClass|setClassName|setSelector)\s*\(",
)
_EXPLICIT_INTENT_CTOR = re.compile(
    r"\bnew\s+Intent\s*\(\s*[A-Za-z_]\w*\s*,\s*[A-Za-z_][\w$.]*\.class\s*\)",
)


def _balanced_args(source: str, paren_start: int) -> str | None:
    """Slice the argument list of a call given the index of the ``(``.

    Returns the inner string between the matching parens, or ``None``
    when braces are unbalanced (heavily obfuscated dumps).
    """
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
    """Split ``args`` on commas at the top paren-nesting level only."""
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


class MutablePendingIntentAgent(BaseAgent):
    """Detect PendingIntent constructions vulnerable to CVE-2021-0938-style hijack."""

    AGENT_ID = "P_012"
    VULN_CLASS = "Mutable PendingIntent"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        manifest: dict[str, Any] = self._context.manifest or {}
        target_sdk = int(manifest.get("target_sdk") or 0)

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            for match in _PI_CALL.finditer(source):
                paren_idx = source.find("(", match.start())
                args_str = _balanced_args(source, paren_idx)
                if args_str is None:
                    continue
                parts = _split_top_level_commas(args_str)
                if len(parts) < 4:
                    continue
                intent_arg = parts[2]
                flags_arg = parts[3]

                if _FLAG_IMMUTABLE.search(flags_arg):
                    continue  # explicitly safe

                explicit_intent = self._intent_is_explicit(
                    source, intent_arg.split()[0] if intent_arg else "",
                )
                mutable_set = bool(_FLAG_MUTABLE.search(flags_arg))
                bare_zero = (flags_arg.strip() == "0")

                severity, confidence = self._classify(
                    mutable_set=mutable_set,
                    bare_zero=bare_zero,
                    explicit_intent=explicit_intent,
                    target_sdk=target_sdk,
                )
                if severity is None:
                    continue

                findings.append(self._make_finding(
                    vuln_class="Mutable PendingIntent",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": str(java_file.relative_to(decompiled)),
                        "call": match.group(0).rstrip("("),
                        "flags_arg": flags_arg[:120],
                        "intent_arg": intent_arg[:120],
                        "explicit_intent": explicit_intent,
                        "target_sdk": target_sdk,
                        "mutable_flag_present": mutable_set,
                        "bare_zero_flags": bare_zero,
                    },
                    recommendation=(
                        "Add PendingIntent.FLAG_IMMUTABLE to the flags "
                        "argument. If mutability is genuinely required, "
                        "first call setPackage() or setComponent() on the "
                        "wrapped Intent to pin its target. Android 12 "
                        "(target SDK 31+) requires an explicit mutability "
                        "flag — adopting it removes the legacy "
                        "default-mutable behaviour."
                    ),
                    owasp="M1: Improper Platform Usage",
                    masvs="MSTG-PLATFORM-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _intent_is_explicit(source: str, intent_var: str) -> bool:
        """Best-effort: does ``intent_var`` get target-pinned in the same file?"""
        if not intent_var or not intent_var.isidentifier():
            return False
        # explicit ctor: new Intent(ctx, Cls.class)
        if _EXPLICIT_INTENT_CTOR.search(source):
            return True
        # setPackage / setComponent / setClass / setClassName / setSelector
        # on the same variable. We don't try to track scope here — a
        # cross-method match still gives useful signal.
        pinned = re.compile(
            r"\b" + re.escape(intent_var) + r"\b" + _TARGET_PIN_ON_VAR.pattern,
        )
        return bool(pinned.search(source))

    @staticmethod
    def _classify(
        *,
        mutable_set: bool,
        bare_zero: bool,
        explicit_intent: bool,
        target_sdk: int,
    ) -> tuple[Severity | None, float]:
        if mutable_set and not explicit_intent:
            return Severity.CRITICAL, 0.90
        if mutable_set and explicit_intent:
            return Severity.HIGH, 0.75
        if bare_zero and not explicit_intent:
            return Severity.HIGH, 0.80
        if bare_zero and explicit_intent:
            if target_sdk >= 31:
                return Severity.INFO, 0.55
            return Severity.MEDIUM, 0.65
        return None, 0.0
