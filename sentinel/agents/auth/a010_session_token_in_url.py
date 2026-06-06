"""A_010: Session Token in URL Detection.

Putting a bearer token in a query string is a recurring high-impact
bug. The token ends up in:

* Web-server / reverse-proxy access logs (commonly long retention).
* The ``Referer`` header of any outbound link the page makes —
  the token leaks cross-origin to whatever the user clicks.
* The OS process table on Android (``/proc/<pid>/cmdline`` for the
  WebView render process) and on intermediate proxies.
* Crash reports and APM tools that capture full URLs.

OWASP MASVS-AUTH-2 explicitly requires session tokens to be carried
in headers, cookies, or body — never in URLs.

Detection
=========

We scan decompiled Java for two shapes:

1. Retrofit ``@Query("…")`` annotations whose parameter name (or
   annotation argument) matches a session-token keyword.
2. String literals containing ``http(s)://`` whose query string
   includes one of the keywords (``token``, ``session``,
   ``sessionId``, ``jwt``, ``access_token``, ``api_key`` /
   ``apikey``, ``auth``, ``bearer``).
3. ``Uri.Builder().appendQueryParameter("token", …)`` calls.

Severity / confidence:

* CRITICAL — ``access_token`` / ``jwt`` / ``bearer`` in a literal
  URL or Retrofit @Query (high-impact bearer credentials).
* HIGH — ``token`` / ``session`` / ``sessionId`` / ``auth``.
* MEDIUM — ``api_key`` / ``apikey`` (still credentials but lower
  blast radius than session tokens).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_CRITICAL_KEYS = {"access_token", "accesstoken", "jwt", "bearer", "id_token", "idtoken"}
_HIGH_KEYS = {"token", "session", "sessionid", "session_id", "auth"}
_MEDIUM_KEYS = {"api_key", "apikey", "apitoken", "api_token"}

_ALL_KEYS = sorted(_CRITICAL_KEYS | _HIGH_KEYS | _MEDIUM_KEYS, key=len, reverse=True)
_KEY_PATTERN = "|".join(re.escape(k) for k in _ALL_KEYS)

_RETROFIT_QUERY = re.compile(
    r'@Query\s*\(\s*"(' + _KEY_PATTERN + r')"\s*\)',
    re.IGNORECASE,
)
_URL_LITERAL = re.compile(
    r'"(https?://[^"\s]*[?&](?:' + _KEY_PATTERN + r')=[^"\s]*)"',
    re.IGNORECASE,
)
_APPEND_QUERY = re.compile(
    r'appendQueryParameter\s*\(\s*"(' + _KEY_PATTERN + r')"',
    re.IGNORECASE,
)


def _classify_key(key: str) -> tuple[Severity, float]:
    k = key.lower().replace("-", "_")
    if k in _CRITICAL_KEYS:
        return Severity.CRITICAL, 0.90
    if k in _HIGH_KEYS:
        return Severity.HIGH, 0.85
    return Severity.MEDIUM, 0.75


class SessionTokenInUrlAgent(BaseAgent):
    """Flag session-token-shaped query parameters in HTTP URLs."""

    AGENT_ID = "A_010"
    VULN_CLASS = "Session Token in URL"
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
            rel = str(java_file.relative_to(decompiled))
            seen: set[tuple[str, str]] = set()

            for pat, vector in (
                (_RETROFIT_QUERY, "retrofit_query"),
                (_URL_LITERAL, "url_literal"),
                (_APPEND_QUERY, "uri_builder"),
            ):
                for m in pat.finditer(source):
                    if vector == "url_literal":
                        url = m.group(1)
                        # Pull the offending key out of the query string.
                        key_match = re.search(
                            r"[?&](" + _KEY_PATTERN + r")=",
                            url, re.IGNORECASE,
                        )
                        if not key_match:
                            continue
                        key = key_match.group(1)
                        evidence_extra = {"url": url[:200]}
                    else:
                        key = m.group(1)
                        evidence_extra = {"key": key}
                    norm = key.lower()
                    fingerprint = (vector, norm)
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    severity, confidence = _classify_key(key)
                    findings.append(self._make_finding(
                        vuln_class="Session Token in URL",
                        severity=severity,
                        confidence=confidence,
                        evidence={
                            "file": rel,
                            "vector": vector,
                            "key": key,
                            **evidence_extra,
                        },
                        recommendation=(
                            f"Move the '{key}' parameter out of the URL "
                            "query string. Send the credential as the "
                            "``Authorization: Bearer <token>`` header "
                            "(or as a body field for non-credential "
                            "params). URL query strings land in "
                            "web-server access logs, the Referer header "
                            "of outbound links, the process table, "
                            "and crash-report captures."
                        ),
                        owasp="M3: Insecure Communication",
                        masvs="MSTG-AUTH-2",
                        cvss_vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                            if severity == Severity.CRITICAL
                            else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                        ),
                    ))
        return findings
