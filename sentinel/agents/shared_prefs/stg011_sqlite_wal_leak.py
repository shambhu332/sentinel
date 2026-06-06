"""STG_011: SQLite WAL / Journal Leak Detection.

SQLite databases on Android default to ``journal_mode = WAL`` (Write-
Ahead Log) since the AOSP Honeycomb-era change. The WAL file (suffix
``-wal``) and the optional shared-memory file (``-shm``) live next to
the main ``.db`` file. Both retain raw bytes of *deleted* rows
because SQLite reuses pages lazily.

The classic data-disclosure path:

1. App stores an auth token / personal data in a SQLite table.
2. App calls ``db.delete("tokens", …)`` to remove it on logout.
3. The pages are flagged "free" but never zeroed.
4. Anyone who reads ``<dbname>.db-wal`` (root, ``adb backup`` if
   ``allowBackup="true"``, file-extraction on a debuggable build)
   recovers the original bytes.

SQLite ships a ``PRAGMA secure_delete = ON`` that zero-fills freed
pages on the way out. The Android SQLiteDatabase API exposes it via
``db.execSQL("PRAGMA secure_delete = ON")`` immediately after open.
Apps that store secrets but skip this pragma leak the secrets even
when the developer believes they were deleted.

Detection
---------

For every file that opens a database
(``openOrCreateDatabase`` / ``SQLiteOpenHelper.getWritableDatabase`` /
``SQLiteOpenHelper.getReadableDatabase`` / ``Room.databaseBuilder``)
we look at the same file for:

1. A ``DELETE`` or ``UPDATE`` SQL statement (or
   ``db.delete(table, ...)`` / ``db.update(table, ...)``) operating
   on a table whose name contains a credential keyword
   (``token`` / ``auth`` / ``password`` / ``credential`` / ``session``
   / ``user`` / ``account`` / ``private``). Or an ``INSERT INTO`` of
   a credential-shaped column into ANY table — the WAL still leaks.

2. No ``PRAGMA secure_delete`` execution in scope.

Severity:

* HIGH (0.85) — credential-named table written to or deleted from,
  no secure_delete pragma, AND ``allowBackup`` is true (we can read
  the manifest off the context).
* MEDIUM (0.75) — same patterns without the backup flag (still bad
  on rooted / debuggable devices, just narrower reach).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_DB_OPEN_CALL = re.compile(
    r"\b(?:openOrCreateDatabase|getWritableDatabase|getReadableDatabase|"
    r"SQLiteOpenHelper\s*\(|Room\s*\.\s*databaseBuilder|"
    r"openDatabase)\s*\(",
)

_SECURE_DELETE = re.compile(
    r'"\s*PRAGMA\s+secure_delete\s*=\s*(?:ON|1|true)',
    re.IGNORECASE,
)

_CREDENTIAL_TABLES = re.compile(
    r'\b(token|auth|password|passwd|credential|session|'
    r'private|wallet|secret)\w*\b',
    re.IGNORECASE,
)

_WRITE_SQL_LITERAL = re.compile(
    r'"\s*(?:INSERT\s+(?:OR\s+(?:REPLACE|IGNORE)\s+)?INTO|'
    r'DELETE\s+FROM|UPDATE)\s+([A-Za-z_]\w*)',
    re.IGNORECASE,
)

_API_WRITE_CALL = re.compile(
    r'\.(insert|delete|update|replace|insertOrThrow|insertWithOnConflict)'
    r'\s*\(\s*"([^"]+)"',
)


class SqliteWalLeakAgent(BaseAgent):
    """Detect SQLite credential storage without secure_delete pragma."""

    AGENT_ID = "STG_011"
    VULN_CLASS = "SQLite WAL / Journal Leak"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        backup_enabled = bool((self._context.manifest or {}).get("allow_backup"))

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue
            if not _DB_OPEN_CALL.search(source):
                continue
            if _SECURE_DELETE.search(source):
                continue

            credential_tables: set[str] = set()
            credential_columns: set[str] = set()

            for m in _WRITE_SQL_LITERAL.finditer(source):
                table = m.group(1)
                if _CREDENTIAL_TABLES.search(table):
                    credential_tables.add(table.lower())

            for m in _API_WRITE_CALL.finditer(source):
                table = m.group(2)
                if _CREDENTIAL_TABLES.search(table):
                    credential_tables.add(table.lower())

            for m in re.finditer(
                r'"([A-Za-z_]\w*)"\s*,\s*[^,;\)]+(?:token|password|secret|jwt)',
                source,
                re.IGNORECASE,
            ):
                credential_columns.add(m.group(1).lower())

            if not credential_tables and not credential_columns:
                continue

            severity = (
                Severity.HIGH if backup_enabled else Severity.MEDIUM
            )
            confidence = 0.85 if backup_enabled else 0.75

            findings.append(self._make_finding(
                vuln_class="SQLite WAL / Journal Leak",
                severity=severity,
                confidence=confidence,
                evidence={
                    "file": str(java_file.relative_to(decompiled)),
                    "credential_tables": sorted(credential_tables),
                    "credential_columns": sorted(credential_columns),
                    "allow_backup": backup_enabled,
                    "issue": (
                        "Database holds credential-named "
                        "table(s) / column(s) and the file does not "
                        "enable PRAGMA secure_delete. SQLite WAL keeps "
                        "deleted bytes recoverable from the -wal "
                        "sidecar file."
                    ),
                },
                recommendation=(
                    "Execute "
                    "``db.execSQL(\"PRAGMA secure_delete = ON\")`` "
                    "immediately after every open. The pragma is "
                    "per-connection on Android, so include it in the "
                    "``onConfigure(SQLiteDatabase)`` of every "
                    "SQLiteOpenHelper. Additionally, set "
                    "android:allowBackup=\"false\" if the database "
                    "stores secrets — otherwise ``adb backup`` "
                    "extracts the WAL bytes wholesale. For new code, "
                    "prefer SQLCipher with hardware-backed key "
                    "material instead of relying on file-system "
                    "permissions."
                ),
                owasp="M9: Insecure Data Storage",
                masvs="MSTG-STORAGE-2",
                cvss_vector=(
                    "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    if severity == Severity.HIGH
                    else "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
                ),
            ))
        return findings
