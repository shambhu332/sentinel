"""F_002: Firebase Cloud Messaging Token Disclosure.

A Firebase Cloud Messaging (FCM) registration token is a bearer
credential. Whoever holds the token can send push messages to that
device through the project's FCM server key — useful for phishing,
"your account has been disabled, tap here" social-engineering, or
silently triggering a deep-link handler. The token rotates only when
the app is reinstalled or the user clears app data.

The two failure modes we detect:

1. The token is written to ``Log.d/v/i/w/e`` (logcat). Any process
   with ``READ_LOGS`` (rooted devices, accessibility-service abuse)
   can scrape every device's token from a single sample.
2. The token is sent over plain HTTP (``http://``) to a developer's
   own collection endpoint instead of via FCM's authenticated
   transport. Network-position attackers harvest tokens at scale.

Detection
=========

Scan each decompiled ``.java`` file for one of the FCM-token API
shapes:

* ``FirebaseMessaging.getInstance().getToken()`` (modern SDK)
* ``FirebaseInstanceId.getInstance().getToken(...)`` (legacy)
* ``OnSuccessListener<String>`` whose callback receives a ``token``
  parameter (the canonical async style)

For each hit, walk the enclosing method body and look for a sink:

* ``Log.d/v/i/w/e(`` referencing the captured token identifier
* ``http://`` literal within the same method (Retrofit / OkHttp /
  HttpURLConnection call)

A finding fires only when a token-shaped expression *and* a sink are
both present in the same method. The intent is to flag the genuine
disclosure path while staying quiet on apps that only use the token
to subscribe to FCM topics (the safe pattern).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_TOKEN_SOURCES = (
    re.compile(r"FirebaseMessaging\s*\.\s*getInstance\s*\(\s*\)\s*\.\s*getToken\s*\("),
    re.compile(r"FirebaseInstanceId\s*\.\s*getInstance\s*\(\s*\)\s*\.\s*getToken\s*\("),
    re.compile(r"OnSuccessListener\s*<\s*String\s*>"),
)
_TOKEN_VAR_BIND = re.compile(
    r"\b(?:String|var)\s+(\w*[tT]oken\w*)\s*=",
)
_LOG_SINK = re.compile(
    r"\bLog\s*\.\s*(d|v|i|w|e)\s*\(",
)
_HTTP_LITERAL = re.compile(r'"http://[^"]+"')
_BUILDCONFIG_GUARD = re.compile(r"\bBuildConfig\.DEBUG\b")


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


class FcmTokenDisclosureAgent(BaseAgent):
    """Detect FCM tokens written to logcat or sent over cleartext HTTP."""

    AGENT_ID = "F_002"
    VULN_CLASS = "FCM Token Disclosure"
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
            if not any(p.search(source) for p in _TOKEN_SOURCES):
                continue

            rel = str(java_file.relative_to(decompiled))

            # Locate each token-binding spot and audit its method body.
            for bind in _TOKEN_VAR_BIND.finditer(source):
                token_var = bind.group(1)
                body = _enclosing_method_body(source, bind.start()) or ""
                if not body:
                    continue

                log_match = self._log_uses_var(body, token_var)
                http_match = self._http_send_present(body, token_var)
                if not (log_match or http_match):
                    continue
                guarded = bool(_BUILDCONFIG_GUARD.search(body))

                if log_match:
                    findings.append(self._make_logcat_finding(
                        rel=rel,
                        token_var=token_var,
                        guarded=guarded,
                    ))
                if http_match:
                    findings.append(self._make_cleartext_finding(
                        rel=rel,
                        token_var=token_var,
                    ))
        return findings

    @staticmethod
    def _log_uses_var(body: str, token_var: str) -> bool:
        # Look for any Log.X(...) call whose argument list mentions
        # the token variable name.
        for m in _LOG_SINK.finditer(body):
            # Capture up to next ``);`` of this Log call (best effort).
            tail = body[m.end():m.end() + 200]
            if re.search(r"\b" + re.escape(token_var) + r"\b", tail):
                return True
        return False

    @staticmethod
    def _http_send_present(body: str, token_var: str) -> bool:
        if not _HTTP_LITERAL.search(body):
            return False
        # Require the token variable to appear in the same body — i.e.
        # the token is plausibly carried over the cleartext request.
        return bool(re.search(r"\b" + re.escape(token_var) + r"\b", body))

    def _make_logcat_finding(
        self,
        *,
        rel: str,
        token_var: str,
        guarded: bool,
    ) -> Finding:
        severity = Severity.MEDIUM if guarded else Severity.HIGH
        confidence = 0.60 if guarded else 0.85
        return self._make_finding(
            vuln_class="FCM Token Logged to Logcat",
            severity=severity,
            confidence=confidence,
            evidence={
                "file": rel,
                "token_variable": token_var,
                "guard_detected": guarded,
                "issue": (
                    "Firebase Cloud Messaging token is written to "
                    "Log.x() — any process with READ_LOGS can scrape "
                    "the bearer credential. The token rotates only on "
                    "reinstall."
                ),
            },
            recommendation=(
                "Remove the Log.x call or wrap it in `if (BuildConfig."
                "DEBUG)` and verify R8 strips the debug branch from "
                "release. Treat the FCM token as a credential — never "
                "log it, never include it in crash reports, and prefer "
                "subscribing to FCM topics over storing the token "
                "server-side."
            ),
            owasp="M2: Inadequate Supply Chain Security",
            masvs="MSTG-STORAGE-3",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        )

    def _make_cleartext_finding(
        self,
        *,
        rel: str,
        token_var: str,
    ) -> Finding:
        return self._make_finding(
            vuln_class="FCM Token Sent Over HTTP",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "file": rel,
                "token_variable": token_var,
                "issue": (
                    "FCM token is plausibly carried over a cleartext "
                    "HTTP request to a developer-owned endpoint — a "
                    "network-position attacker can harvest tokens at "
                    "scale."
                ),
            },
            recommendation=(
                "Send the FCM token only over HTTPS to your token-"
                "collection endpoint, and ideally to an endpoint that "
                "validates the request with an Authorization header "
                "tied to the user's session. If the token need not "
                "leave the device, drop the upload entirely and rely "
                "on FCM topic subscriptions."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-NETWORK-1",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
