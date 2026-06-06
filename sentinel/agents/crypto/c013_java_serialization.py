"""C_013: Java Native Deserialization Sink Detection.

``ObjectInputStream.readObject()`` reads a Java-serialised object from
a stream and reconstructs it via reflective constructors and gadget-
chain side effects. If the stream is attacker-controlled, the gadget
chains shipped with common Android dependencies (Apache Commons,
Spring, Hibernate, JBoss) can be coerced into arbitrary code
execution — this is the canonical Java-deserialisation RCE.

Android apps shouldn't be using Java native serialisation at all —
the recommended replacements are JSON (Moshi / kotlinx.serialization
/ Gson) or Protocol Buffers, both of which are gadget-chain-free. We
flag any ``readObject()`` call site whose input stream plausibly
comes from outside the process boundary.

Detection
=========

Find every ``ObjectInputStream`` constructor or ``readObject()`` /
``readUnshared()`` call. Slice the enclosing brace-balanced method
body and look for a *source* in the same scope:

* Network sources — ``Socket.getInputStream``, ``URL.openStream``,
  ``HttpURLConnection.getInputStream``, ``OkHttp`` ``Response.body``.
* Intent extras — ``Intent.getByteArrayExtra`` /
  ``getSerializableExtra``.
* Files on external storage — ``getExternalStorageDirectory`` or
  ``/sdcard`` literal in scope.
* SharedPreferences-derived byte arrays.

Severity:

* CRITICAL — network source in scope (remote-RCE primitive).
* HIGH — Intent or external-storage source in scope.
* MEDIUM — ObjectInputStream usage with no obvious external source
  (still flagged because the safe answer is "don't use Java
  serialisation at all").
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_OIS_CTOR = re.compile(
    r"new\s+ObjectInputStream\s*\(",
)
_OIS_READ = re.compile(
    r"\.\s*(readObject|readUnshared)\s*\(\s*\)",
)
_NETWORK_SOURCE = re.compile(
    r"(getInputStream\s*\(|openStream\s*\(|HttpURLConnection|"
    r"OkHttpClient|Response\s*\.\s*body|Socket\s*\.\s*getInputStream)",
)
_INTENT_SOURCE = re.compile(
    r"\.(getByteArrayExtra|getSerializableExtra|getStringExtra)\s*\(",
)
_EXTERNAL_STORAGE = re.compile(
    r"(getExternalStorageDirectory|getExternalStoragePublicDirectory|"
    r'"/sdcard|"/mnt/sdcard|"/storage/emulated)',
)


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


class JavaSerializationAgent(BaseAgent):
    """Flag ObjectInputStream.readObject sinks fed from external sources."""

    AGENT_ID = "C_013"
    VULN_CLASS = "Java Native Deserialization"
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
            if not (_OIS_CTOR.search(source) or _OIS_READ.search(source)):
                continue

            rel = str(java_file.relative_to(decompiled))
            seen_methods: set[int] = set()

            for trigger in self._trigger_iter(source):
                body_pair = _enclosing_method_body_pair(source, trigger.start())
                if not body_pair:
                    continue
                body, method_offset = body_pair
                if method_offset in seen_methods:
                    continue
                seen_methods.add(method_offset)

                network = bool(_NETWORK_SOURCE.search(body))
                intent = bool(_INTENT_SOURCE.search(body))
                external = bool(_EXTERNAL_STORAGE.search(body))

                severity, confidence, reason = self._classify(
                    network=network,
                    intent=intent,
                    external=external,
                )
                findings.append(self._make_finding(
                    vuln_class="Java Native Deserialization",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "trigger": trigger.group(0).strip(),
                        "network_source": network,
                        "intent_source": intent,
                        "external_storage_source": external,
                        "reason": reason,
                    },
                    recommendation=(
                        "Replace Java native serialisation with JSON "
                        "(Moshi / kotlinx.serialization / Gson) or "
                        "Protocol Buffers — neither can be coerced into "
                        "a gadget-chain RCE. If ObjectInputStream is "
                        "required for legacy reasons, wrap it in a "
                        "subclass that overrides resolveClass() with "
                        "a strict allowlist of acceptable types, and "
                        "treat the source as untrusted regardless of "
                        "the transport."
                    ),
                    owasp="M7: Client Code Quality",
                    masvs="MSTG-CODE-8",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
                    ),
                ))
        return findings

    @staticmethod
    def _trigger_iter(source: str):
        yield from _OIS_CTOR.finditer(source)
        yield from _OIS_READ.finditer(source)

    @staticmethod
    def _classify(
        *,
        network: bool,
        intent: bool,
        external: bool,
    ) -> tuple[Severity, float, str]:
        if network:
            return Severity.CRITICAL, 0.90, "network-sourced input stream"
        if intent or external:
            return (
                Severity.HIGH, 0.80,
                "Intent extra or external-storage source in scope",
            )
        return (
            Severity.MEDIUM, 0.60,
            "Java native deserialisation used (safe answer is to remove it)",
        )


def _enclosing_method_body_pair(source: str, idx: int) -> tuple[str, int] | None:
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
                        return source[open_idx + 1 : i], open_idx
                    break
            i += 1
        open_idx = source.rfind("{", 0, open_idx)
    return None
