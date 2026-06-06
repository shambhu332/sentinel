"""A_013: Magic-Link Token Replay Detection.

Magic-link sign-in (passwordless email auth) hands the user a deep
link containing a single-use token:

    https://app.example.com/auth?magic=abc123

The mobile handler extracts the token from the deep link and
exchanges it for a session. The bug pattern is twofold:

1. The handler **persists** the raw magic token into SharedPreferences
   as if it were a long-lived credential. Magic links are intended
   to be redeemed once; persisting the raw token gives the attacker
   (who has the email or a backup-extracted prefs file) repeated
   replay attempts until the server's TTL expires.

2. The logout flow clears in-memory state and possibly the access
   token but never the stored magic token. Anyone with the device
   later (or with the user's restored backup) can replay it.

The fix is: never persist the raw magic link. Redeem it once for a
server-issued session, persist only the session token (rotated on
every authentication transition per MSTG-AUTH-3), and invalidate the
magic token server-side on first use.

Detection
---------

For every file that handles a deep link (``getQueryParameter`` /
``getData`` / Intent with ACTION_VIEW), look for:

1. A read of a magic-token-shaped query parameter
   (``magic`` / ``magic_link`` / ``magic_token`` / ``ott`` /
   ``magicLink`` / ``signin_token`` / ``oneTimeToken``).
2. A ``putString`` write of THAT value into a credential prefs key
   (``magic`` / ``token`` / ``auth_token`` / ``access_token``).
3. Absence of any of these defences in scope:
   * ``rotateSession`` / ``getNewSession`` / ``refreshToken`` /
     ``redeemMagicLink`` / ``exchangeMagicLink``
   * ``prefs.edit().remove("magic*")`` / ``prefs.edit().clear()``
   * the value being immediately overwritten with a server response.

Severity:

* CRITICAL — magic token persisted to prefs with no redeem call in
  scope (token-replay primitive)
* HIGH — same but a generic ``persist()`` helper is invoked instead
  of a direct putString (less certain)
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_MAGIC_QUERY_PARAM = re.compile(
    r'getQueryParameter\s*\(\s*"'
    r'(magic|magic[_-]link|magic[_-]?token|ott|signin[_-]?token|'
    r'one[_-]?time[_-]?token|loginToken)'
    r'"\s*\)',
    re.IGNORECASE,
)

_MAGIC_INTENT_EXTRA = re.compile(
    r'\.getStringExtra\s*\(\s*"'
    r'(magic|magic[_-]link|magic[_-]?token|ott|signin[_-]?token|'
    r'one[_-]?time[_-]?token|loginToken)'
    r'"\s*\)',
    re.IGNORECASE,
)

_PUTSTRING_TOKEN = re.compile(
    r'(?:putString|putEncrypted)\s*\(\s*"'
    r'(magic|magic[_-]link|magic[_-]?token|ott|token|auth[_-]?token|'
    r'access[_-]?token|signin[_-]?token)'
    r'"\s*,\s*([A-Za-z_]\w*)',
    re.IGNORECASE,
)

_PERSIST_HELPER = re.compile(
    r"\b(save|persist|store|set)(?:Auth|Magic|Token|Session|Credentials)\w*\s*\("
)

_REDEEM_CALL = re.compile(
    r"\b("
    r"redeemMagicLink|exchangeMagicLink|redeemOneTime|"
    r"rotateSession|getNewSession|refreshToken|createSession|"
    r"exchangeAuthCode|verifyMagicLink"
    r")\s*\(",
    re.IGNORECASE,
)

_CLEAR_PREFS = re.compile(
    r'\.remove\s*\(\s*"(?:magic[^"]*|token|auth[_-]?token|access[_-]?token)"\s*\)|'
    r'\.edit\s*\(\s*\)\s*\.\s*clear\s*\(',
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


class MagicLinkTokenAgent(BaseAgent):
    """Detect magic-link tokens persisted as if they were session credentials."""

    AGENT_ID = "A_013"
    VULN_CLASS = "Magic Link Token Replay"
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
            has_magic_source = bool(
                _MAGIC_QUERY_PARAM.search(source)
                or _MAGIC_INTENT_EXTRA.search(source)
            )
            if not has_magic_source:
                continue

            rel = str(java_file.relative_to(decompiled))
            seen_methods: set[int] = set()

            for source_match in list(_MAGIC_QUERY_PARAM.finditer(source)) + list(
                _MAGIC_INTENT_EXTRA.finditer(source),
            ):
                open_idx = source.rfind("{", 0, source_match.start())
                if open_idx in seen_methods:
                    continue
                body = _enclosing_method_body(source, source_match.start())
                if not body:
                    continue
                seen_methods.add(open_idx)

                if _REDEEM_CALL.search(body):
                    continue

                put = _PUTSTRING_TOKEN.search(body)
                helper = _PERSIST_HELPER.search(body)
                if not (put or helper):
                    continue

                if put and _CLEAR_PREFS.search(body):
                    # ambiguous — the same method both writes and
                    # immediately clears. Skip.
                    continue

                severity = Severity.CRITICAL if put else Severity.HIGH
                confidence = 0.85 if put else 0.70

                findings.append(self._make_finding(
                    vuln_class="Magic Link Token Replay",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "vector": (
                            "putString_magic_token" if put
                            else "persist_helper"
                        ),
                        "magic_param": source_match.group(1),
                        "issue": (
                            "Deep-link handler reads a magic-link "
                            "token and persists it without invoking "
                            "a redeem / exchange call against the "
                            "server. The raw token survives in "
                            "SharedPreferences and is replayable for "
                            "the server-side TTL window."
                        ),
                    },
                    recommendation=(
                        "Treat magic links as one-shot. On receipt, "
                        "POST the token to the auth backend, receive "
                        "a freshly-issued session token, persist only "
                        "the session token, and discard the magic "
                        "value. The backend MUST invalidate the magic "
                        "token on first redeem. On logout, clear "
                        "every persisted credential — explicitly "
                        "include any residual magic-* keys via "
                        "prefs.edit().remove(\"magic_token\")."
                    ),
                    owasp="M3: Insecure Authentication / Authorization",
                    masvs="MSTG-AUTH-3",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                        if severity == Severity.CRITICAL
                        else "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings
