"""A_011: Refresh-Token Survives Logout Detection.

A long-lived OAuth refresh token is meant to outlast the current
session — but only as long as the user *wants* the session to
continue. The canonical mobile logout bug is:

1. The app stores the refresh token in SharedPreferences (often as
   ``refresh_token`` or ``rt``) when the user signs in.
2. The user taps ``Sign out``, which clears the in-memory user
   model and navigates to the login screen.
3. The on-disk refresh token is never deleted. Anyone with physical
   access to the device — or any rooted-device attacker who pulls
   the prefs file — can still trade it for a fresh access token.

We flag any logout-style method whose body clears in-memory auth
state (``setUser(null)``, ``clearSession()``, ``mUser = null``)
without also calling ``.remove("refresh_token")`` /
``.edit().clear()`` / ``deleteAllUsers()`` on a SharedPreferences /
SQLite / DataStore handle that elsewhere in the file holds the
token.

Heuristics
==========

* Logout method: name contains ``logout`` / ``signOut`` /
  ``signout`` / ``onSignOut``.
* Stores the token: same file contains a write of a
  ``refresh_token`` / ``rt`` / ``refreshToken`` key into
  ``SharedPreferences.Editor`` or ``EncryptedSharedPreferences``.
* Logout body doesn't include ``.remove("refresh_token")`` or
  ``.clear()`` or an ``encryptedPrefs.edit()`` followed by clear.

Severity:

* HIGH — logout exists, token is stored, no clear in logout body.
* MEDIUM — same, but the logout body invokes a generic
  ``clearCache()`` / ``invalidate()`` helper that *might* clear
  prefs through another file (we surface this as uncertain).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_LOGOUT_METHOD = re.compile(
    r"(?:public|private|protected|\s)+\s+\w+\s+"
    r"(logout|signOut|signout|onSignOut|doLogout|performLogout)\s*\(",
)
_REFRESH_TOKEN_STORE = re.compile(
    r'(?:putString|putEncrypted)\s*\(\s*"(?:refresh_token|refreshToken|rt)"',
    re.IGNORECASE,
)
_CLEAR_TOKEN = re.compile(
    r'(?:\.remove\s*\(\s*"(?:refresh_token|refreshToken|rt)"\s*\)|'
    r'\.edit\s*\(\s*\)\s*\.\s*clear\s*\(|'
    r'EncryptedSharedPreferences[^;]*\.\s*edit\s*\(\s*\)\s*\.\s*clear\s*\()',
    re.IGNORECASE,
)
_UNCERTAIN_HELPER = re.compile(
    r"\b(clearCache|invalidate|resetSession|wipe(?:State|Local)?)\s*\(",
)


def _enclosing_method_body(source: str, idx: int) -> str | None:
    open_idx = source.find("{", idx)
    if open_idx == -1:
        return None
    depth = 0
    i = open_idx
    while i < len(source):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[open_idx + 1 : i]
        i += 1
    return None


class RefreshTokenReuseAgent(BaseAgent):
    """Flag logout flows that leave refresh tokens on disk."""

    AGENT_ID = "A_011"
    VULN_CLASS = "Refresh Token Survives Logout"
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
            if not _REFRESH_TOKEN_STORE.search(source):
                continue
            rel = str(java_file.relative_to(decompiled))

            for m in _LOGOUT_METHOD.finditer(source):
                method_name = m.group(1)
                body = _enclosing_method_body(source, m.end())
                if not body:
                    continue
                if _CLEAR_TOKEN.search(body):
                    continue

                helper_match = _UNCERTAIN_HELPER.search(body)
                severity = (
                    Severity.MEDIUM if helper_match else Severity.HIGH
                )
                confidence = 0.70 if helper_match else 0.85

                findings.append(self._make_finding(
                    vuln_class="Refresh Token Survives Logout",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "method": method_name,
                        "helper_in_scope": (
                            helper_match.group(1) if helper_match else None
                        ),
                        "issue": (
                            "Logout method clears in-memory state but "
                            "the file persists a refresh_token key into "
                            "SharedPreferences and the logout body does "
                            "not call .remove(\"refresh_token\") or "
                            ".edit().clear() on the prefs store."
                        ),
                    },
                    recommendation=(
                        "On logout, explicitly clear every persisted "
                        "credential: prefs.edit().remove(\"refresh_token\")"
                        ".remove(\"access_token\").apply(); revoke the "
                        "refresh token server-side; and wipe any cached "
                        "user records in SQLite / DataStore / "
                        "EncryptedSharedPreferences. Treat logout as a "
                        "destructive operation, not just a UI navigation."
                    ),
                    owasp="M3: Insecure Authentication/Authorization",
                    masvs="MSTG-AUTH-7",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings
