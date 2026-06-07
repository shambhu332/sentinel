"""D_001 — Clipboard Sensitive-Data Leak Agent.

The Android system clipboard is a process-wide shared buffer. Any app
holding ``READ_LOGS`` (debug), any accessibility service, any
foregrounded app, and on Android 10+ any *previously foregrounded* app
can read whatever the user last copied. Banking, password manager,
auth, and crypto-wallet apps that push credentials, OTPs, recovery
phrases, or account numbers onto the clipboard expose them to every
other co-installed app silently.

Static analysis catches the obvious ``ClipboardManager.setPrimaryClip``
call sites, but framework wrappers, Kotlin extensions, and reflection
defeat the pattern match. Runtime observation through a Frida hook on
``android.content.ClipboardManager.setPrimaryClip`` /
``getPrimaryClip`` proves the call is actually executed during normal
app use and captures the *value* type so we can flag credential-shaped
data with high confidence.

Detection
---------

We consume Frida events of kind ``clipboard.write`` and
``clipboard.read``. Each event payload is expected to carry:

* ``label``      — String label passed to ``ClipData.newPlainText``
                   (often the app's hint about the contents)
* ``text``       — The clip text. Long values are truncated by the
                   hook; we never log the full secret.
* ``mime_types`` — list[str] reported by the ClipData
* ``stack``      — optional caller class/method to localise the issue

A write is flagged when:

1. The ``label`` or ``text`` contains a credential keyword
   (token / auth / otp / password / pin / secret / key / seed /
   mnemonic / recovery / account / iban / card / cvv / ssn).
2. OR the ``text`` looks like a high-entropy short string (heuristic:
   8–64 chars, ≥ 1 digit and 1 letter, no whitespace).

A read is flagged only when the calling stack is from the app itself
(not the Android paste UI), because reading the clipboard is the
classic supply-chain-attack pattern for keyboard apps and crypto
"sniffers" looking for wallet addresses.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_CREDENTIAL_HINT = re.compile(
    r"(?:token|auth|otp|password|passwd|pwd|pin|secret|"
    r"key|seed|mnemonic|recovery|account|iban|card|cvv|ssn|"
    r"jwt|bearer|credential|wallet)",
    re.IGNORECASE,
)

# 8–64 char alphanumeric clump with at least 1 digit and 1 letter.
_TOKEN_SHAPED = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_\-\.]{8,64}$")


class ClipboardLeakAgent(BaseAgent):
    """D_001: detects credential-shaped clipboard writes/reads at runtime."""

    AGENT_ID = "D_001"
    VULN_CLASS = "Clipboard Sensitive Data Leak"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_001] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        writes: list[dict[str, Any]] = []
        reads: list[dict[str, Any]] = []
        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "clipboard.write":
                if self._is_sensitive(payload):
                    writes.append({
                        "label": payload.get("label"),
                        "text_preview": _redact(payload.get("text")),
                        "mime_types": payload.get("mime_types"),
                        "stack": payload.get("stack"),
                        "timestamp": ev.timestamp,
                    })
            elif ev.kind == "clipboard.read":
                if self._is_in_app_read(payload):
                    reads.append({
                        "stack": payload.get("stack"),
                        "mime_types": payload.get("mime_types"),
                        "timestamp": ev.timestamp,
                    })

        findings: list[Finding] = []
        if writes:
            findings.append(self._write_finding(writes))
        if reads:
            findings.append(self._read_finding(reads))
        return findings

    # ---------- heuristics ----------

    @staticmethod
    def _is_sensitive(payload: dict[str, Any]) -> bool:
        label = str(payload.get("label") or "")
        text = str(payload.get("text") or "")
        if _CREDENTIAL_HINT.search(label) or _CREDENTIAL_HINT.search(text):
            return True
        # Token-shaped opaque string copied without a label = likely
        # session token / API key / wallet address fragment.
        if _TOKEN_SHAPED.match(text.strip()):
            return True
        return False

    @staticmethod
    def _is_in_app_read(payload: dict[str, Any]) -> bool:
        stack = str(payload.get("stack") or "")
        if not stack:
            # Without a stack we can't distinguish the system paste UI
            # from the app reading the clipboard itself. Conservative
            # default: skip — false positives here become noise.
            return False
        # System paste UI lives under android.widget / android.view —
        # only flag reads originating from the app's own code.
        return not stack.startswith(("android.", "androidx."))

    # ---------- findings ----------

    def _write_finding(self, writes: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.90,
            evidence={
                "issue": (
                    "The application wrote credential-shaped data to the "
                    "system clipboard at runtime. Any other installed app "
                    "with foreground access (or any accessibility service) "
                    "can read this value silently."
                ),
                "occurrence_count": len(writes),
                "samples": writes[:5],
                "vector": (
                    "Frida hook on android.content.ClipboardManager."
                    "setPrimaryClip captured the call with credential-"
                    "shaped contents."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Do not write secrets, OTPs, tokens, or account numbers "
                "to the system clipboard. If the UI requires a copy "
                "affordance, mark the ClipData as sensitive with "
                "ClipDescription.EXTRA_IS_SENSITIVE (Android 13+) so "
                "the system suppresses preview and auto-clears the "
                "clipboard, and clear the entry on a short timer. For "
                "values shared with another flow inside the same app, "
                "pass them via Intent extras or an in-memory channel — "
                "never through the global clipboard."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-STORAGE-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        )

    def _read_finding(self, reads: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Clipboard Read by Application",
            severity=Severity.LOW,
            confidence=0.80,
            evidence={
                "issue": (
                    "The application read from the system clipboard from "
                    "its own code path (not the system paste UI). This is "
                    "the canonical pattern for clipboard sniffers — "
                    "specifically wallet-address swappers and keylogger-"
                    "style apps. Confirm the behaviour is user-initiated."
                ),
                "occurrence_count": len(reads),
                "samples": reads[:5],
                "vector": (
                    "Frida hook on android.content.ClipboardManager."
                    "getPrimaryClip with a caller stack rooted in the "
                    "application package."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Read the clipboard only in direct response to a user "
                "gesture (paste button, long-press menu). Never poll "
                "ClipboardManager. On Android 12+, system Toast warns "
                "the user on every clipboard read — do not try to "
                "suppress it."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )


def _redact(value: Any) -> str:
    """Show at most the first 4 and last 2 characters of a clipboard value.

    Reports should not echo full secrets even when the agent runs
    locally. The redacted preview is enough to identify the shape.
    """
    s = str(value or "")
    if not s:
        return ""
    if len(s) <= 8:
        return s[:2] + "…"
    return f"{s[:4]}…{s[-2:]} (len={len(s)})"
