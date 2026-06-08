"""D_033 — Unsafe Reflection Invocation.

Reflection itself is not the bug. The bug is the combination:

1. ``Class.forName(s)`` where ``s`` is caller-influenced.
2. ``cls.getMethod(m, ...).invoke(...)`` on the resolved class.
3. The target class is *sensitive* (``Runtime`` /
   ``ProcessBuilder`` / ``dalvik.system.DexClassLoader`` /
   ``dalvik.system.PathClassLoader`` / ``android.app.Application``).

Apps that ship plug-in dispatchers, deep-link routers, or
scripting bridges typically end up wiring all three together.
Static SAST sees the calls in isolation; this agent ties them into
the same call window so reviewers see the actual chain.

Detection
---------

We consume three Frida event kinds:

* ``reflection.class_forname`` — from D_031, name + caller_class.
* ``reflection.method_invoked`` — ``Method.invoke`` calls. Payload:
  ``{target_class, method_name, declaring_class, caller_class,
  stack}``.
* ``reflection.constructor_invoked`` — ``Constructor.newInstance``
  calls. Payload: ``{target_class, caller_class, stack}``.

Severity matrix:

* **CRITICAL** — Method.invoke or Constructor.newInstance whose
  ``target_class`` is in the sensitive set
  (``java.lang.Runtime``, ``java.lang.ProcessBuilder``,
  ``dalvik.system.DexClassLoader``,
  ``dalvik.system.PathClassLoader``,
  ``dalvik.system.InMemoryDexClassLoader``).
* **HIGH** — Method.invoke or newInstance on a class that was
  ``Class.forName``'d in the prior 32 events (caller-resolved
  dynamic chain).
* **MEDIUM** — at least three distinct ``target_class`` values
  invoked from a single ``caller_class`` (plug-in dispatcher /
  scripting bridge pattern — warrants review of input provenance).
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_SENSITIVE_TARGETS = frozenset({
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "dalvik.system.DelegateLastClassLoader",
    "android.app.Application",
    "android.app.ActivityThread",
})

_FORNAME_WINDOW = 32
_DISPATCHER_TARGET_THRESHOLD = 3


class UnsafeReflectionInvokeAgent(BaseAgent):
    """D_033: correlate reflection-chain primitives at runtime."""

    AGENT_ID = "D_033"
    VULN_CLASS = "Unsafe Reflection Invocation Chain"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_033] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        recent_forname: deque[str] = deque(maxlen=_FORNAME_WINDOW)

        sensitive_hits: list[dict[str, Any]] = []
        dynamic_hits: list[dict[str, Any]] = []
        dispatcher_targets: dict[str, set[str]] = defaultdict(set)
        dispatcher_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "reflection.class_forname":
                name = str(payload.get("name") or "")
                if name:
                    recent_forname.append(name)
                continue
            if ev.kind not in (
                "reflection.method_invoked",
                "reflection.constructor_invoked",
            ):
                continue

            target = str(payload.get("target_class") or "")
            caller = str(payload.get("caller_class") or "")
            sample = {
                "kind": ev.kind,
                "target_class": target[:200],
                "method_name": str(payload.get("method_name") or "")[:100],
                "declaring_class": str(
                    payload.get("declaring_class") or "",
                )[:200],
                "caller_class": caller[:200],
                "stack": payload.get("stack"),
            }

            if target in _SENSITIVE_TARGETS:
                sensitive_hits.append(sample)
                continue
            if target and target in recent_forname:
                sample["resolved_via"] = "Class.forName"
                dynamic_hits.append(sample)
                continue
            if caller and target:
                dispatcher_targets[caller].add(target)
                if (len(dispatcher_targets[caller])
                        <= _DISPATCHER_TARGET_THRESHOLD + 2):
                    dispatcher_samples[caller].append(sample)

        findings: list[Finding] = []
        if sensitive_hits:
            findings.append(self._sensitive_finding(sensitive_hits))
        if dynamic_hits:
            findings.append(self._dynamic_finding(dynamic_hits))

        dispatcher_hits = [
            {
                "caller_class": caller,
                "distinct_targets": sorted(dispatcher_targets[caller])[:10],
                "samples": dispatcher_samples[caller][:5],
            }
            for caller, targets in dispatcher_targets.items()
            if len(targets) >= _DISPATCHER_TARGET_THRESHOLD
        ]
        if dispatcher_hits:
            findings.append(self._dispatcher_finding(dispatcher_hits))
        return findings

    def _sensitive_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.92,
            evidence={
                "issue": (
                    "Reflection reached a sensitive class — Runtime, "
                    "ProcessBuilder, or one of the dalvik.system "
                    "class loaders. If the call's argument list is "
                    "caller-influenced (Intent extra, push payload, "
                    "deep-link parameter), the app is one chain step "
                    "from arbitrary-command / arbitrary-code "
                    "execution."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Method.invoke / Constructor."
                    "newInstance compared target_class against an "
                    "allow-list of high-risk targets."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Audit every call site. Reflection into Runtime / "
                "ProcessBuilder is almost never necessary on Android "
                "— refactor to a typed API. For class loaders, pin "
                "the DEX / library path to a hash and load through a "
                "single helper that rejects caller input."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-8",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def _dynamic_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Reflection Chain — Class.forName + invoke",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "Method.invoke / Constructor.newInstance fired on "
                    "a class that was Class.forName'd in the prior 32 "
                    "events. If the class-name string came from an "
                    "Intent extra, deep-link parameter, or HTTP "
                    "response, the caller chose which code path runs. "
                    "Equivalent to a plug-in entry point exposed "
                    "without an allow-list."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hooks on Class.forName and Method.invoke "
                    "/ Constructor.newInstance correlated by target "
                    "class name across a sliding 32-event window."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Replace the Class.forName lookup with a static "
                "allow-list mapping. Never let an external field "
                "choose which class or constructor runs."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-8",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _dispatcher_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Reflection Dispatcher Pattern",
            severity=Severity.MEDIUM,
            confidence=0.60,
            evidence={
                "issue": (
                    "A single calling class invoked three or more "
                    "distinct target classes via reflection during "
                    "this capture. That is the shape of a plug-in "
                    "dispatcher, scripting bridge, or DI helper — "
                    "useful in their own right, dangerous if any "
                    "input the dispatcher reads is caller-supplied."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook aggregated Method.invoke / "
                    "Constructor.newInstance target_class values per "
                    "caller_class."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Confirm the dispatcher's input is constrained to a "
                "known allow-list. If the input is the keyset of a "
                "Map, document where the keys come from."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-8",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )
