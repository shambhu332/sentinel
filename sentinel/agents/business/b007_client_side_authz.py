"""B_007: Client-Side Authorization Gate Detection.

The classic "client trusts itself" bug. The mobile app holds a
``User`` object with role flags decoded from a JWT (or worse, from
local prefs) and gates UI buttons + API calls behind those flags:

    if (user.isAdmin()) {
        api.adminDeleteAccount(targetUserId);
    }

The server-side endpoint then accepts the request as long as the
session is valid — never re-checking that the session actually
belongs to an admin. An attacker who can either (a) modify the
in-memory User object on a rooted device or via Frida, or (b) just
hit the endpoint from curl with a leaked token, bypasses the gate
entirely.

The fix is server-side: every authorization decision must happen on
the backend, every time, even when the mobile client has already
made a decision. Mobile-side ``if (user.isAdmin())`` is at most a
UX nicety to hide a button — it must not be the only gate.

Detection
---------

Look for conditional gates that immediately call a backend method:

    if (<user_object>.isAdmin()           ── role / feature predicate
        || <user_object>.canBilling()
        || <user_object>.role == "admin")
    {
        api.<method>(...);                ── network/API call inside the gate
        retrofit.<method>(...);
        httpClient.execute(...);
    }

The agent treats the call as "remote" when the receiver looks like
``api`` / ``service`` / ``client`` / ``retrofit`` / ``apolloClient`` /
``okHttpClient`` / ``backend`` or when the body of the call site
references one of those identifiers.

Severity:

* HIGH (0.75) — predicate name looks privilege-shaped
  (``isAdmin`` / ``canDelete`` / ``hasRole`` / ``isPaid`` /
  ``hasFeature`` / ``isOwner``).
* MEDIUM (0.65) — feature-flag predicate (``canShow`` / ``isEnabled``).

The agent intentionally surfaces this as a review nudge: server
gating is operationally invisible from the APK, so we cannot say
the bug exists for certain. The finding directs the reviewer to
verify the server side authorizes the call.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_PRIVILEGE_PREDICATE = re.compile(
    r"\b("
    r"isAdmin|isModerator|isOwner|isPaid|isPro|isPremium|isVip|"
    r"canDelete|canEdit|canModerate|canBilling|canAdmin|"
    r"hasRole|hasPermission|hasFeature|hasAccess|hasAdminAccess|"
    r"isBetaUser|isStaff|isSuperuser|isInternalUser|isEmployee"
    r")\s*\(\s*\)",
)

_FEATURE_FLAG = re.compile(
    r"\b("
    r"canShow|isEnabled|isFeatureOn|isAvailable|isUnlocked"
    r")\s*\(\s*\)",
)

_API_CLIENT_RECEIVER = re.compile(
    r"\b("
    r"api|service|client|retrofit|apolloClient|okHttpClient|"
    r"backend|repository|repo|gateway|http(?:Client)?|apolloService"
    r")\s*\.\s*"
)

_RETROFIT_ANNOTATION = re.compile(
    r"@(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(",
)


def _find_matching_brace(source: str, open_idx: int) -> int | None:
    """Return the index of the matching ``}`` for the ``{`` at open_idx."""
    if open_idx >= len(source) or source[open_idx] != "{":
        return None
    depth = 0
    for i in range(open_idx, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


class ClientSideAuthzAgent(BaseAgent):
    """Flag privilege predicates gating remote API calls — server gating may be missing."""

    AGENT_ID = "B_007"
    VULN_CLASS = "Client-Side Authorization Gate"
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
            # Need at least one predicate AND something that looks like
            # an API call surface in the file. Both are necessary.
            if not (
                _PRIVILEGE_PREDICATE.search(source)
                or _FEATURE_FLAG.search(source)
            ):
                continue
            if not (
                _API_CLIENT_RECEIVER.search(source)
                or _RETROFIT_ANNOTATION.search(source)
            ):
                continue

            rel = str(java_file.relative_to(decompiled))
            seen_methods: set[int] = set()

            # Walk every ``if (...) {`` whose condition mentions a
            # predicate and whose body invokes the API receiver.
            for m in re.finditer(r"\bif\s*\(", source):
                paren_start = source.find("(", m.start())
                close_paren = _find_matching_paren(source, paren_start)
                if close_paren is None:
                    continue
                condition = source[paren_start + 1 : close_paren]

                priv_match = _PRIVILEGE_PREDICATE.search(condition)
                feat_match = (
                    _FEATURE_FLAG.search(condition) if not priv_match else None
                )
                if not (priv_match or feat_match):
                    continue

                # Find the ``{`` that starts the if-body.
                brace = source.find("{", close_paren + 1)
                if brace == -1 or brace - close_paren > 32:
                    continue
                end = _find_matching_brace(source, brace)
                if end is None:
                    continue
                body = source[brace + 1 : end]

                if not _API_CLIENT_RECEIVER.search(body):
                    continue
                if brace in seen_methods:
                    continue
                seen_methods.add(brace)

                hit = priv_match or feat_match
                predicate = hit.group(1)
                severity = (
                    Severity.HIGH if priv_match else Severity.MEDIUM
                )
                confidence = 0.75 if priv_match else 0.65

                findings.append(self._make_finding(
                    vuln_class="Client-Side Authorization Gate",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "predicate": predicate,
                        "issue": (
                            f"Conditional ``if ({predicate}())`` gates a "
                            "subsequent API / client call. The mobile-"
                            "side predicate is invisible to the server "
                            "— anyone with a valid token can bypass it "
                            "via curl, Frida, or by rewriting the in-"
                            "memory User object on a rooted device. "
                            "Verify the backend enforces the same role "
                            "/ feature check on every endpoint reached "
                            "inside this branch."
                        ),
                    },
                    recommendation=(
                        "Treat the mobile predicate as a UX hint only. "
                        "Implement the same authorization decision on "
                        "the server (re-validate role / subscription "
                        "tier / feature flag on every request). The "
                        "server response should also drive any UI "
                        "state — never persist role flags only in the "
                        "client-side User object."
                    ),
                    owasp="M3: Insecure Authentication / Authorization",
                    masvs="MSTG-ARCH-2",
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
                        if severity == Severity.HIGH
                        else "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"
                    ),
                ))
        return findings


def _find_matching_paren(source: str, paren_start: int) -> int | None:
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
                return i
    return None
