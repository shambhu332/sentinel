"""STG_010: Plaintext Password File Write.

The most embarrassing storage anti-pattern: the "remember me" code
path that drops a literal password to a ``credentials.json`` or
``user.txt`` file in the app's data dir. Anyone with root, anyone
running on a debuggable build, anyone who pulls a device backup —
free credentials.

STG_010 fires when a file-write call site references both:

* a credential-shaped variable / literal in scope (``password``,
  ``passwd``, ``pwd``, ``passphrase``, ``master_password``), and
* a destination filename literal whose extension is one of ``.txt``,
  ``.json``, ``.properties``, ``.xml``, ``.csv``, ``.dat``, OR a
  variable named like a credential file (``credentials*``,
  ``user_data``, ``account``, ``vault``).

We deliberately do *not* require the write to live on external
storage — internal-only writes are still findings because anyone
with root, ``run-as`` on a debuggable build, or an auto-backup
hit can read them.

A nearby crypto call (``Cipher.``, ``EncryptedSharedPreferences``,
``KeyStore.getInstance("AndroidKeyStore")``) suppresses the finding
on the assumption that the file is encrypted before write.
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_WRITE_CALL = re.compile(
    r"\b(?:new\s+FileOutputStream|new\s+FileWriter|new\s+BufferedWriter|"
    r"new\s+PrintWriter|Files\s*\.\s*write|Files\s*\.\s*writeString|"
    r"getContentResolver\s*\(\s*\)\s*\.\s*openOutputStream)\s*\(",
)
_PASSWORD_TOKEN = re.compile(
    r'(?:"[^"]*(password|passwd|pwd|passphrase|master[_-]?password|'
    r"login[_-]?secret)[^\"]*\"|"
    r"\b(?:password|passwd|pwd|passphrase|masterPassword|loginSecret)\b)",
    re.IGNORECASE,
)
_CREDENTIAL_DEST = re.compile(
    r'"[^"]*(\.txt|\.json|\.properties|\.xml|\.csv|\.dat|'
    r"credentials|user_data|account|vault|password)"
    r'[^\"]*\"',
    re.IGNORECASE,
)
_ENCRYPTION_NEARBY = re.compile(
    r"\b(?:Cipher\s*\.|EncryptedSharedPreferences|"
    r'KeyStore\s*\.\s*getInstance\s*\(\s*"AndroidKeyStore|'
    r"MasterKeys|MasterKey\.Builder)",
)


def _enclosing_method_body_pair(source: str, idx: int) -> tuple[str, int] | None:
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


class PlaintextPasswordFileAgent(BaseAgent):
    """Flag plaintext password writes to data-dir files."""

    AGENT_ID = "STG_010"
    VULN_CLASS = "Plaintext Password File"
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
            seen_methods: set[int] = set()

            for write in _WRITE_CALL.finditer(source):
                result = _enclosing_method_body_pair(source, write.start())
                if not result:
                    continue
                body, method_offset = result
                if method_offset in seen_methods:
                    continue

                pwd_match = _PASSWORD_TOKEN.search(body)
                dest_match = _CREDENTIAL_DEST.search(body)
                if not (pwd_match and dest_match):
                    continue
                if _ENCRYPTION_NEARBY.search(body):
                    continue

                seen_methods.add(method_offset)
                findings.append(self._make_finding(
                    vuln_class="Plaintext Password File",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    evidence={
                        "file": rel,
                        "password_marker": (
                            pwd_match.group(0)[:60]
                        ),
                        "destination_marker": dest_match.group(0)[:60],
                        "issue": (
                            "A file-write call site references a "
                            "password-shaped variable / literal "
                            "alongside a credential-shaped destination "
                            "filename, with no Cipher / "
                            "EncryptedSharedPreferences / Android "
                            "Keystore call in the same method. The "
                            "password is plausibly being written in "
                            "plaintext."
                        ),
                    },
                    recommendation=(
                        "Stop writing passwords to files. Use "
                        "EncryptedSharedPreferences (Jetpack Security) "
                        "for the small persisted-secret case, or seal "
                        "the value with an Android Keystore key and "
                        "store the ciphertext. For \"remember me\" "
                        "feature flows, persist a server-issued "
                        "refresh token instead of the user's "
                        "password."
                    ),
                    owasp="M2: Inadequate Supply Chain Security",
                    masvs="MSTG-STORAGE-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    ),
                ))
        return findings
