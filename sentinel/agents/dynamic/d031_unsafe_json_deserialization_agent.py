"""D_031 — Unsafe JSON Deserialization.

Gson, Moshi, and Jackson are all safe by default *when* the target
type is concrete and known at compile time. The unsafe cases are:

1. **Typeless deserialization.** ``gson.fromJson(s, Object.class)``
   or ``mapper.readValue(s, Object.class)`` returns whatever shape
   the JSON dictates. When the JSON includes ``@class`` /
   ``@type`` markers (Jackson default typing) the library may
   reconstruct any class the classloader can find — the classic
   Jackson polymorphic-RCE chain (CVE-2017-7525 family).

2. **Polymorphic adapters.** Gson's ``RuntimeTypeAdapterFactory``
   and Moshi's ``PolymorphicJsonAdapterFactory`` are safe only when
   the subtype list is explicit. Jackson's
   ``activateDefaultTyping`` / ``@JsonTypeInfo(use=CLASS)`` opens
   the door to attacker-chosen classes.

3. **Dynamic type resolution.** The target ``Class`` argument to
   ``fromJson`` came from ``Class.forName(s)`` where ``s`` was
   built from an Intent extra, push payload, or HTTP response field
   in the same window.

Detection
---------

We consume two Frida event kinds:

* ``reflection.class_forname`` — emitted from ``Class.forName``
  with payload ``{name, caller_class, stack}``.
* ``json.deserialize_called`` — emitted from ``Gson.fromJson`` (all
  overloads), ``JsonAdapter.fromJson``, and ``ObjectMapper.read*``.
  Payload: ``{library, target_type, polymorphic_marker,
  caller_class, stack}``.

Severity matrix:

* **CRITICAL** — ``polymorphic_marker`` is non-empty (default-typing
  / RuntimeTypeAdapterFactory / @JsonTypeInfo seen). Active gadget
  surface.
* **HIGH** — ``target_type`` is ``java.lang.Object`` /
  ``java.util.Map`` / ``com.fasterxml.jackson.databind.JsonNode``
  (typeless deserialization).
* **HIGH** — same target type seen in a ``reflection.class_forname``
  event within 32 prior events (dynamic class + JSON pairing).
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_TYPELESS_TARGETS = frozenset({
    "java.lang.Object",
    "java.util.Map",
    "java.util.HashMap",
    "java.util.LinkedHashMap",
    "com.fasterxml.jackson.databind.JsonNode",
    "com.google.gson.JsonElement",
    "com.google.gson.JsonObject",
    "org.json.JSONObject",
})

_RECENT_CLASSNAME_WINDOW = 32


class UnsafeJsonDeserializationAgent(BaseAgent):
    """D_031: catch unsafe JSON deserialization patterns at runtime."""

    AGENT_ID = "D_031"
    VULN_CLASS = "Unsafe JSON Deserialization"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_031] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        recent_classnames: deque[str] = deque(maxlen=_RECENT_CLASSNAME_WINDOW)

        polymorphic_hits: list[dict[str, Any]] = []
        typeless_hits: list[dict[str, Any]] = []
        dynamic_class_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "reflection.class_forname":
                name = str(payload.get("name") or "")
                if name:
                    recent_classnames.append(name)
                continue
            if ev.kind != "json.deserialize_called":
                continue

            target = str(payload.get("target_type") or "")
            marker = str(payload.get("polymorphic_marker") or "")
            sample = {
                "library": str(payload.get("library") or ""),
                "target_type": target[:200],
                "polymorphic_marker": marker[:200],
                "caller_class": str(payload.get("caller_class") or "")[:200],
                "stack": payload.get("stack"),
            }

            if marker:
                polymorphic_hits.append(sample)
                continue
            if target in _TYPELESS_TARGETS:
                typeless_hits.append(sample)
                continue
            if target and target in recent_classnames:
                # The same class was just resolved by Class.forName.
                # That's the dynamic-type-resolution pattern.
                sample["resolved_via"] = "Class.forName"
                dynamic_class_hits.append(sample)

        findings: list[Finding] = []
        if polymorphic_hits:
            findings.append(self._polymorphic_finding(polymorphic_hits))
        if typeless_hits:
            findings.append(self._typeless_finding(typeless_hits))
        if dynamic_class_hits:
            findings.append(self._dynamic_class_finding(dynamic_class_hits))
        return findings

    def _polymorphic_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.92,
            evidence={
                "issue": (
                    "A JSON deserialiser was invoked with a "
                    "polymorphic-typing marker active — Jackson's "
                    "activateDefaultTyping / @JsonTypeInfo(use=CLASS), "
                    "Gson's RuntimeTypeAdapterFactory chain, or "
                    "Moshi's PolymorphicJsonAdapterFactory built "
                    "without an explicit subtype list. Any class the "
                    "classloader can resolve becomes a deserialisation "
                    "target, which is the textbook chain leading to "
                    "the Jackson CVE-2017-7525 family of RCE bugs."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on Gson.fromJson / Moshi "
                    "JsonAdapter.fromJson / ObjectMapper.readValue "
                    "captured the active polymorphic marker on the "
                    "Type / Adapter object."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Drop default typing and replace polymorphic adapters "
                "with explicit subtype registrations. For Jackson, "
                "use ``@JsonTypeInfo(use=NAME)`` plus "
                "``@JsonSubTypes``. For Gson, hand-roll a "
                "TypeAdapter with an allow-list. For Moshi, always "
                "pass an explicit ``withSubtype()`` chain."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-8",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def _typeless_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JSON Deserialised into Typeless Target",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "A JSON deserialiser was called with "
                    "``Object.class`` / a Map / a JsonNode as the "
                    "target type. The deserialised structure is "
                    "whatever the input dictated. When the consuming "
                    "code reflects on the resulting object's keys "
                    "(common for plug-in dispatchers), the caller "
                    "controls which downstream code path runs."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook read the target Class / Type passed "
                    "to fromJson / readValue."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Define a concrete DTO with @SerializedName / "
                "@JsonProperty fields. Reject unknown keys via "
                "Jackson's DeserializationFeature."
                "FAIL_ON_UNKNOWN_PROPERTIES or Moshi's failOnUnknown."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-8",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        )

    def _dynamic_class_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="JSON Target Type Resolved Dynamically",
            severity=Severity.HIGH,
            confidence=0.75,
            evidence={
                "issue": (
                    "The Class passed to a JSON deserialiser was "
                    "resolved by Class.forName earlier in the same "
                    "process. If the class-name string is sourced "
                    "from an Intent extra, push payload, or HTTP "
                    "response, the caller chooses the deserialisation "
                    "target — equivalent to Jackson default typing "
                    "without the marker."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hooks on Class.forName and fromJson / "
                    "readValue correlated by class-name string "
                    "across a sliding 32-event window."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Replace the Class.forName lookup with an explicit "
                "static map of allowed types. Never let an external "
                "field choose the deserialisation target."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-CODE-8",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )
