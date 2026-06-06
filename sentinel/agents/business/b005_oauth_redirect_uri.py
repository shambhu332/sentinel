"""B_005: OAuth ``redirect_uri`` Attacker-Controlled Construction.

In an OAuth 2.0 authorization-code flow, the ``redirect_uri`` is the
URL the authorization server bounces the user back to with the
``?code=…`` fragment. If a mobile client lets external input
influence that URL, an attacker can steer the code to their own
endpoint and exchange it for an access token.

The classic mobile exploit:

1. The app accepts a deep link or Intent extra named ``return_url``
   / ``redirect`` / ``redirect_uri`` / ``next``.
2. The handler concatenates that value into the authorize URL when
   it kicks off the OAuth flow.
3. The attacker triggers the deep link with their own
   ``https://evil.example.com/cb`` value.
4. The auth server redirects ``?code=<victim_code>`` to evil.

We detect three shapes:

* String concatenation that includes ``redirect_uri=`` and a
  variable rather than a literal value.
* ``Uri.Builder().appendQueryParameter("redirect_uri", <var>)``
  where ``<var>`` is not a string literal.
* Retrofit ``@Query("redirect_uri") String <var>`` on a method
  whose ``@GET`` / ``@POST`` path contains an OAuth keyword
  (``/authorize``, ``/oauth``, ``/login/authorize``, ``/connect/authorize``).

Severity:

* CRITICAL — variable redirect_uri AND a taint source (intent extra,
  getQueryParameter, getStringExtra) is present in the same method
  body.
* HIGH — variable redirect_uri with no obvious literal allowlist /
  validation but no in-scope taint source — the parameter could
  still come from a controllable input upstream.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_OAUTH_PATHS = re.compile(
    # Either a literal slash-prefixed URL path or a quoted path
    # segment used by Uri.Builder.appendPath("oauth") / appendPath(
    # "authorize"). Both shapes appear in real Android OAuth code.
    r'(/authorize|/oauth|/login/authorize|/connect/authorize'
    r'|appendPath\s*\(\s*"oauth"|appendPath\s*\(\s*"authorize")',
)
_REDIRECT_URI_CONCAT = re.compile(
    r'"\s*redirect_uri\s*=\s*"\s*\+\s*([A-Za-z_]\w*)',
)
_REDIRECT_URI_APPEND = re.compile(
    r'appendQueryParameter\s*\(\s*"redirect_uri"\s*,\s*([^)]+?)\s*\)',
)
_RETROFIT_REDIRECT = re.compile(
    r'@Query\s*\(\s*"redirect_uri"\s*\)\s+\w+\s+(\w+)',
)
_TAINT_INTENT_EXTRA = re.compile(
    r"\.(getStringExtra|getCharSequenceExtra|getDataString)\s*\(",
)
_TAINT_QUERY_PARAM = re.compile(
    r"getQueryParameter\s*\(",
)
_LITERAL_REDIRECT = re.compile(
    # ``"…redirect_uri=…"`` where the value is a literal URL — either
    # plain (``https://…``) or URL-encoded (``https%3A%2F%2F…``). The
    # quote may carry a leading ``?`` or ``&`` (split-string builders
    # very commonly stash the query glue in the next literal).
    r'"[?&]?redirect_uri=(?:https?(?:://|%3A%2F%2F)|[A-Za-z][\w+.-]*://)'
    r'[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+"',
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


class OAuthRedirectUriAgent(BaseAgent):
    """Flag OAuth flows whose redirect_uri parameter is variable-sourced."""

    AGENT_ID = "B_005"
    VULN_CLASS = "OAuth redirect_uri Hijack"
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
            if not _OAUTH_PATHS.search(source):
                continue

            rel = str(java_file.relative_to(decompiled))

            for pat, vector in (
                (_REDIRECT_URI_CONCAT, "string_concat"),
                (_REDIRECT_URI_APPEND, "uri_builder"),
                (_RETROFIT_REDIRECT, "retrofit_query"),
            ):
                for m in pat.finditer(source):
                    var_name = m.group(1).strip()
                    if var_name.startswith('"'):
                        # literal — safe (we only fire on variables).
                        continue
                    if vector == "uri_builder" and var_name.startswith('"') and var_name.endswith('"'):
                        continue
                    body = _enclosing_method_body(source, m.start()) or ""
                    taint_in_scope = bool(
                        _TAINT_INTENT_EXTRA.search(body)
                        or _TAINT_QUERY_PARAM.search(body)
                    )
                    has_literal_safe = bool(_LITERAL_REDIRECT.search(body))
                    if has_literal_safe and not taint_in_scope:
                        # The same method ships a literal redirect_uri
                        # right next to the variable — likely a safe
                        # builder pattern. Skip.
                        continue

                    severity = Severity.CRITICAL if taint_in_scope else Severity.HIGH
                    confidence = 0.85 if taint_in_scope else 0.70

                    findings.append(self._make_finding(
                        vuln_class="OAuth redirect_uri Hijack",
                        severity=severity,
                        confidence=confidence,
                        evidence={
                            "file": rel,
                            "vector": vector,
                            "variable": var_name[:80],
                            "taint_in_scope": taint_in_scope,
                            "issue": (
                                "OAuth authorize URL is constructed with "
                                "a variable redirect_uri value. If that "
                                "value originates from an external "
                                "input (deep link, Intent extra, "
                                "WebView postMessage) an attacker can "
                                "steer the authorization code to their "
                                "own endpoint and trade it for an "
                                "access token."
                            ),
                        },
                        recommendation=(
                            "Pin the redirect_uri to a single, "
                            "compile-time constant value bound to the "
                            "app's PackageManager-registered deep link "
                            "(e.g. com.example.app:/oauth/cb). Reject "
                            "any input that doesn't exactly match the "
                            "allowlisted URI before invoking the "
                            "authorize endpoint, and prefer the "
                            "AppAuth-Android library which enforces "
                            "this for you."
                        ),
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-AUTH-1",
                        cvss_vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
                            if severity == Severity.CRITICAL
                            else "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
                        ),
                    ))
        return findings
