"""SQLite store for cross-scan finding baselines.

A baseline is a flat (APK SHA-256 × finding fingerprint) table that
the ``sentinel diff`` command writes to after every comparison. The
table answers two questions:

1. **When did this fingerprint first appear?** — ``first_seen`` is
   monotonically the earliest timestamp we ever observed.
2. **When was this fingerprint last observed?** — ``last_seen`` is
   bumped on every diff that re-encounters it.

The store is intentionally tiny: no migrations, no ORM, one ~25-line
schema. Rebuilding it is cheap (just rerun every diff); the on-disk
file is data, not source. It is gitignored alongside the OSV DB.
"""
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from sentinel.core.diff import (
    _extract_path,
    _extract_snippet,
    _normalize_path,
    _normalize_snippet,
    finding_fingerprint,
)
from sentinel.core.finding import Finding

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path("data/baselines.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    apk_hash    TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    vuln_class  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    file        TEXT NOT NULL,
    snippet     TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (apk_hash, fingerprint)
);

CREATE INDEX IF NOT EXISTS ix_baselines_apk ON baselines(apk_hash);
"""


class BaselineStore:
    """Connection wrapper. Use as a context manager."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else _DEFAULT_DB

    def __enter__(self) -> BaselineStore:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(_SCHEMA)
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self._conn.commit()
        finally:
            self._conn.close()

    # ---------- Reads ----------

    def fingerprints_for(self, apk_hash: str) -> set[str]:
        """Return every recorded fingerprint for the given APK."""
        cur = self._conn.execute(
            "SELECT fingerprint FROM baselines WHERE apk_hash = ?",
            (apk_hash,),
        )
        return {row[0] for row in cur.fetchall()}

    def rows_for(self, apk_hash: str) -> list[dict[str, str]]:
        """Return every column for every fingerprint of one APK."""
        cur = self._conn.execute(
            "SELECT fingerprint, agent_id, vuln_class, severity, "
            "       file, snippet, first_seen, last_seen "
            "FROM baselines WHERE apk_hash = ?",
            (apk_hash,),
        )
        cols = ("fingerprint", "agent_id", "vuln_class", "severity",
                "file", "snippet", "first_seen", "last_seen")
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    # ---------- Writes ----------

    def record(self, apk_hash: str, findings: Iterable[Finding]) -> int:
        """Upsert one row per finding. Returns the number of rows touched.

        ``first_seen`` is preserved on update (UPSERT does not clobber
        it). ``last_seen`` is bumped to "now" on every observation.
        Same finding observed again across two diffs of the same APK
        → two updates, no duplicates, monotone last_seen.
        """
        now = datetime.now(timezone.utc).isoformat()
        touched = 0
        for f in findings:
            fp = finding_fingerprint(f)
            path = _normalize_path(_extract_path(f))
            snippet = _normalize_snippet(_extract_snippet(f))[:1000]
            self._conn.execute(
                """
                INSERT INTO baselines
                  (apk_hash, fingerprint, agent_id, vuln_class, severity,
                   file, snippet, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(apk_hash, fingerprint) DO UPDATE SET
                  last_seen = excluded.last_seen,
                  severity  = excluded.severity
                """,
                (
                    apk_hash, fp, f.agent_id, f.vuln_class,
                    f.severity.value, path, snippet, now, now,
                ),
            )
            touched += 1
        return touched


__all__ = ["BaselineStore"]
