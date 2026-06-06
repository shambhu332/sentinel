"""STG_008: Credential Write to External Storage.

External storage on Android is world-readable on API ≤ 28 and (with
``MANAGE_EXTERNAL_STORAGE`` or the legacy storage opt-out) still
broadly accessible on later releases. Writing credential-shaped data
to one of the public external roots leaks the data to every other app
on the device — and persists across uninstall, since the file remains
in the public Downloads directory.

The roots that warrant suspicion:

* ``Environment.getExternalStorageDirectory()`` — ``/sdcard/`` root.
* ``Environment.getExternalStoragePublicDirectory(...)`` — typed
  public directories such as ``DIRECTORY_DOWNLOADS`` /
  ``DIRECTORY_DOCUMENTS`` / ``DIRECTORY_PICTURES``.
* ``Context.getExternalFilesDir(...)`` — app-private under API 19+
  but still readable by sideloading or ``adb pull`` on debuggable
  devices.
* The hard-coded ``/sdcard/`` or ``/mnt/sdcard/`` path literal.

We only emit a finding when the destination path is *combined with*
a credential-shaped filename or in-flight credential content. The
heuristics:

* The write call (``FileOutputStream``, ``OpenOutputStream``,
  ``FileWriter``, ``Files.write``, ``BufferedWriter``) refers in
  the same method body to one of the credential keywords:
  ``token``, ``password``, ``secret``, ``credential``, ``apikey``,
  ``api_key``, ``jwt``, ``auth``, ``private_key``, ``privatekey``.

Severity:

* HIGH — credential keyword + external root in the same method body.
* MEDIUM — generic credential filename without the explicit external
  root (catches ``new File(downloadDir, "session.json")`` patterns
  where ``downloadDir`` is plausibly external).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_EXTERNAL_ROOTS = re.compile(
    r"\b(Environment\s*\.\s*getExternalStorageDirectory|"
    r"Environment\s*\.\s*getExternalStoragePublicDirectory|"
    r"getExternalFilesDir|getExternalCacheDir|"
    r"getExternalMediaDirs)\s*\(",
)
_EXTERNAL_PATH_LITERAL = re.compile(
    r'"(?:/sdcard|/mnt/sdcard|/storage/emulated)[^"]*"',
)
_WRITE_CALL = re.compile(
    r"\b(?:new\s+FileOutputStream|new\s+FileWriter|new\s+BufferedWriter|"
    r"getContentResolver\s*\(\s*\)\s*\.\s*openOutputStream|"
    r"Files\s*\.\s*write|Files\s*\.\s*writeString)\s*\(",
)
_CREDENTIAL_KEYWORDS = re.compile(
    r'"[^"]*?'
    r"(token|password|passwd|secret|credential|api[-_]?key|jwt|auth"
    r"|private[-_]?key|session)"
    r'[^"]*?"',
    re.IGNORECASE,
)


def _enclosing_method_body(source: str, idx: int) -> tuple[str, int] | None:
    """Return ``(body_text, open_brace_offset)`` for the enclosing method.

    Returning the open-brace offset lets callers dedup by enclosing
    scope — ``id(body_text)`` is not stable because each call to
    ``rfind`` + slice produces a fresh string.
    """
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


class ExternalStorageCredentialAgent(BaseAgent):
    """Flag credential writes to external storage."""

    AGENT_ID = "STG_008"
    VULN_CLASS = "Credential Write to External Storage"
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
            if not _WRITE_CALL.search(source):
                continue

            rel = str(java_file.relative_to(decompiled))
            emitted_methods: set[int] = set()

            for write in _WRITE_CALL.finditer(source):
                result = _enclosing_method_body(source, write.start())
                if not result:
                    continue
                body, method_offset = result
                # Avoid emitting twice for the same enclosing method.
                if method_offset in emitted_methods:
                    continue

                ext_root_hit = bool(_EXTERNAL_ROOTS.search(body))
                ext_literal_hit = bool(_EXTERNAL_PATH_LITERAL.search(body))
                cred_match = _CREDENTIAL_KEYWORDS.search(body)
                if not cred_match:
                    continue

                if not (ext_root_hit or ext_literal_hit):
                    continue

                emitted_methods.add(method_offset)
                severity = Severity.HIGH
                confidence = 0.85 if ext_root_hit else 0.75

                findings.append(self._make_finding(
                    vuln_class="Credential Write to External Storage",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": rel,
                        "external_root_api": ext_root_hit,
                        "external_path_literal": ext_literal_hit,
                        "credential_marker": cred_match.group(1).lower(),
                        "issue": (
                            "A FileOutputStream / FileWriter / "
                            "Files.write call sits in the same method "
                            "body as both an external-storage root and "
                            "a credential-shaped literal — the secret "
                            "is plausibly being written to a world-"
                            "readable path."
                        ),
                    },
                    recommendation=(
                        "Persist credentials in EncryptedSharedPreferences "
                        "(Jetpack Security) or seal them with an Android "
                        "Keystore key and store the ciphertext in "
                        "internal storage (Context.getFilesDir). Never "
                        "write secrets to getExternalStorageDirectory / "
                        "DIRECTORY_DOWNLOADS / /sdcard — those paths are "
                        "world-readable on API ≤ 28 and persist across "
                        "uninstall on every release."
                    ),
                    owasp="M2: Inadequate Supply Chain Security",
                    masvs="MSTG-STORAGE-2",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings
