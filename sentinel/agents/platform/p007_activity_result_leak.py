"""P_007: Activity-Result Sensitive-Data Leak.

The Android ``startActivityForResult`` (and its modern replacement
``registerForActivityResult``) pattern hands control to a target
Activity and receives a result Intent when it finishes:

    void onActivityResult(int requestCode, int resultCode, Intent data) {
        String token = data.getStringExtra("auth_token");
        // ... do something with token
    }

The bug class P_007 detects: an Activity in this app calls
``setResult(RESULT_OK, intent)`` with an Intent whose extras carry
credential-shaped data, AND the Activity is exported. The result
Intent travels back to the *caller* of ``startActivityForResult``,
and on Android a malicious app can be the caller. Anyone who can
launch the exported Activity receives the sensitive return payload.

A symmetric variant lives on the read side: an unexported result
handler reading credential-shaped extras from
``getIntent().getStringExtra("auth_token")`` (the caller chose them)
and storing them is the input form of the bug — covered by
A_012 / P_010 already. We focus on the write side here.

Detection
---------

For every exported activity in the manifest, look at its decompiled
source for:

1. A ``setResult(...)`` call passing an Intent.
2. That Intent receives ``putExtra(``credential_key``, value)`` where
   the key matches the credential-keyword set
   (``token`` / ``auth`` / ``password`` / ``otp`` / ``session`` /
   ``credential`` / ``code`` / ``secret`` / ``jwt``).

Severity:

* CRITICAL (0.85) — both conditions met AND the activity has
  ``android:permission`` empty / missing (any app can be the caller).
* HIGH (0.70) — both met AND permission is non-empty (still risky,
  protection-level audit in IPC_001).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_CREDENTIAL_KEY = re.compile(
    r'"(?:[^"]*(?:token|auth|password|passwd|pwd|otp|session|'
    r'credential|code|secret|jwt|private)[^"]*)"',
    re.IGNORECASE,
)

_SET_RESULT = re.compile(
    r"\bsetResult\s*\(\s*(?:Activity\s*\.\s*)?RESULT_OK\s*,\s*([A-Za-z_]\w*)\s*\)"
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


class ActivityResultLeakAgent(BaseAgent):
    """Detect exported activities returning credential-shaped extras."""

    AGENT_ID = "P_007"
    VULN_CLASS = "Activity-Result Sensitive Data Leak"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        manifest = self._context.manifest or {}
        if not self._context.decompiled_dir:
            return False
        return any(
            c.get("type") == "activity"
            for c in (manifest.get("exported_components") or [])
        )

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []
        manifest = self._context.manifest or {}
        exported = [
            c for c in (manifest.get("exported_components") or [])
            if c.get("type") == "activity"
        ]
        if not exported:
            return []

        findings: list[Finding] = []
        for activity in exported:
            fqcn = activity.get("name") or ""
            permission = activity.get("permission") or ""
            class_name = fqcn.rsplit(".", 1)[-1]
            if not class_name:
                continue

            for java_file in decompiled.rglob(f"{class_name}.java"):
                try:
                    source = java_file.read_text(errors="replace")
                except OSError:
                    continue

                for set_result_match in _SET_RESULT.finditer(source):
                    intent_var = set_result_match.group(1).strip()
                    if not intent_var.isidentifier():
                        continue
                    body = _enclosing_method_body(
                        source, set_result_match.start(),
                    )
                    if not body:
                        continue

                    # Look at putExtra calls on the same intent
                    # variable inside the method body.
                    put_extra_re = re.compile(
                        r"\b" + re.escape(intent_var)
                        + r"\s*\.\s*putExtra\s*\(\s*"
                        r'"([^"]+)"',
                    )
                    sensitive_keys: list[str] = []
                    for pe in put_extra_re.finditer(body):
                        key = pe.group(1)
                        if _CREDENTIAL_KEY.match(f'"{key}"'):
                            sensitive_keys.append(key)
                    if not sensitive_keys:
                        continue

                    severity = (
                        Severity.CRITICAL if not permission
                        else Severity.HIGH
                    )
                    confidence = 0.85 if not permission else 0.70

                    findings.append(self._make_finding(
                        vuln_class="Activity-Result Sensitive Data Leak",
                        severity=severity,
                        confidence=confidence,
                        evidence={
                            "activity": fqcn,
                            "file": str(java_file.relative_to(decompiled)),
                            "sensitive_extras": sorted(set(sensitive_keys)),
                            "permission": permission or "<none>",
                            "issue": (
                                "Activity is exported and returns "
                                "credential-shaped extras through "
                                "setResult(). Anyone with the "
                                "permission to launch the Activity "
                                "(any app, if no permission gate is "
                                "set) receives the payload through "
                                "their onActivityResult / "
                                "ActivityResultLauncher callback."
                            ),
                        },
                        recommendation=(
                            "Do not return credentials through the "
                            "Activity-result Intent. Either: "
                            "(a) set android:exported=\"false\" on the "
                            "Activity so only this app can be the "
                            "caller, "
                            "(b) require a signature-level "
                            "android:permission on the manifest "
                            "declaration so a malicious app cannot "
                            "launch the Activity, OR "
                            "(c) return only opaque references (an "
                            "encrypted handle the calling code "
                            "exchanges with the backend) so the "
                            "Intent itself never carries the secret."
                        ),
                        owasp="M1: Improper Platform Usage",
                        masvs="MSTG-PLATFORM-1",
                        cvss_vector=(
                            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
                            if severity == Severity.CRITICAL
                            else "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                        ),
                    ))
                # One finding per activity is enough — break out of
                # the file loop on first hit so we don't emit
                # multiple findings for sibling decompiled copies.
                if findings and findings[-1].evidence.get("activity") == fqcn:
                    break

        return findings
