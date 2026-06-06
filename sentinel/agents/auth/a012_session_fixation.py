"""A_012: Session Fixation on Login.

A session fixation bug happens when the app accepts a session id /
auth token from an untrusted source and persists it as the user's
active session, without first asking the server to rotate to a
fresh, server-issued token. The canonical exploit chain on Android:

1. The attacker sends the victim a deep link of the form
   ``app://login?session_id=ATTACKER_KNOWN_VALUE``.
2. The app's deep-link handler reads the parameter and writes it
   into the auth-token slot of SharedPreferences (or DataStore /
   EncryptedSharedPreferences).
3. The user logs in normally. The app uses the attacker-supplied
   token for subsequent requests. The attacker can hijack the
   session because they already know the token value.

The OWASP MASVS-AUTH-3 control requires the client to obtain a
fresh, server-issued token on every authentication transition.

Detection
=========

For every method that pulls a session-shaped value from an external
source (Intent extra, deep-link query parameter), the agent
inspects the same method body for a ``putString`` /
``putEncrypted`` write of that value into a credential-shaped key
*without* a server-rotation call (``rotateSession`` /
``getNewSession`` /``refreshToken`` /``createSession`` /
``POST .* /session``) being visible in the same scope.

Severity:

* CRITICAL — attacker-controlled token written straight to a
  credential prefs key.
* HIGH — same, but the method calls a generic ``persist`` /
  ``save`` helper instead of an obvious putString. We flag the
  helper path at slightly lower confidence.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_TAINT_SOURCE = re.compile(
    r"\.(getStringExtra|getCharSequenceExtra|getDataString|getQueryParameter)\s*\("
)
_PUTSTRING_TOKEN = re.compile(
    r'(?:putString|putEncrypted)\s*\(\s*"'
    r"(?:token|access_token|session_id|sessionId|session|jwt|"
    r"auth_token|authToken|sid)"
    r'"\s*,\s*([A-Za-z_]\w*)',
    re.IGNORECASE,
)
_PERSIST_HELPER = re.compile(
    # Match both method-call style (``obj.saveAuth(``) and bare
    # in-class invocations (``setAuthToken(``); the trailing ``\w*``
    # lets the suffix carry additional camel-case words (Auth → AuthToken).
    r"\b(save|persist|store|set)(?:Auth|Session|Token|Credentials)\w*\s*\(",
)
_ROTATION_CALL = re.compile(
    r"\b("
    r"rotateSession|getNewSession|refreshToken|createSession|"
    r"requestSession|loginExchange|getNewToken|exchangeAuthCode"
    r")\s*\(|/session/(?:create|rotate|exchange)",
    re.IGNORECASE,
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


class SessionFixationAgent(BaseAgent):
    """Detect login flows that adopt attacker-supplied session ids."""

    AGENT_ID = "A_012"
    VULN_CLASS = "Session Fixation"
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
            if not _TAINT_SOURCE.search(source):
                continue

            rel = str(java_file.relative_to(decompiled))
            seen_methods: set[int] = set()

            for taint in _TAINT_SOURCE.finditer(source):
                open_idx = source.rfind("{", 0, taint.start())
                if open_idx in seen_methods:
                    continue
                body = _enclosing_method_body(source, taint.start())
                if not body:
                    continue
                seen_methods.add(open_idx)

                put_match = _PUTSTRING_TOKEN.search(body)
                helper_match = _PERSIST_HELPER.search(body)
                rotation_match = _ROTATION_CALL.search(body)

                if not (put_match or helper_match):
                    continue
                if rotation_match:
                    continue

                severity = Severity.CRITICAL if put_match else Severity.HIGH
                confidence = 0.85 if put_match else 0.70

                findings.append(self._make_finding(
                    vuln_class="Session Fixation",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "vector": (
                            "putString_token" if put_match
                            else "persist_helper"
                        ),
                        "issue": (
                            "Method reads a session-shaped value from "
                            "an Intent extra / deep-link parameter "
                            "and persists it into the auth-token slot "
                            "without invoking a server-side rotation "
                            "call. The token can be pre-fixated by an "
                            "attacker who tricks the victim into "
                            "opening a crafted deep link."
                        ),
                    },
                    recommendation=(
                        "On every login transition, request a fresh "
                        "session id / token from the server via a "
                        "POST that the server treats as the "
                        "authoritative session creation. Discard the "
                        "client-supplied identifier and store only "
                        "the server-issued response. Treat deep-link "
                        "parameters as untrusted."
                    ),
                    owasp="M2: Inadequate Supply Chain Security",
                    masvs="MSTG-AUTH-3",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings
