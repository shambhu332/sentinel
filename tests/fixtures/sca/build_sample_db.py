"""Builds the tiny OSV sample SQLite used by SCA_001 unit tests.

The production fetch script (scripts/fetch_osv_db.py) walks the full
OSV.dev Maven dump — that's ~50 MiB and slow. This helper writes a
hand-crafted 4-row snapshot covering the cases the test suite needs:

  * okhttp <= 4.9.1               → vulnerable        (CVE-2021-0341)
  * gson  <= 2.8.8                → vulnerable        (CVE-2022-25647)
  * commons-lang3 <= 3.11         → vulnerable, critical CVSS=9.8
  * a fictional "edge-lib" range  → tests boundary semver matching

The schema must match scripts/fetch_osv_db.py exactly so the agent
code is portable between the sample and the real DB.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

# (group_artifact, vuln_id, cvss, severity, summary, ranges, fixed)
_SAMPLE_ROWS: list[tuple[str, str, float, str, str, list[dict], str | None]] = [
    (
        "com.squareup.okhttp3:okhttp",
        "CVE-2021-0341",
        7.5,
        "High",
        "OkHttp before 4.9.2 trusts the OS-level hostname verifier even "
        "when an application-supplied verifier rejects the cert, allowing "
        "MITM in some pinning configurations.",
        [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "4.9.2"},
            ],
        }],
        "4.9.2",
    ),
    (
        "com.google.code.gson:gson",
        "CVE-2022-25647",
        7.5,
        "High",
        "Gson deserialization issue in versions before 2.8.9 allows DoS "
        "via crafted JSON.",
        [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.8.9"},
            ],
        }],
        "2.8.9",
    ),
    (
        "org.apache.commons:commons-lang3",
        "CVE-2099-CRIT",
        9.8,
        "Critical",
        "Synthetic critical fixture used by tier-3 unit tests.",
        [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "3.12.0"},
            ],
        }],
        "3.12.0",
    ),
    (
        "com.example.edge:edge-lib",
        "CVE-EDGE-001",
        5.5,
        "Medium",
        "Synthetic record for testing introduced/fixed boundary "
        "semantics. Affects 1.2.0 (inclusive) through 1.5.0 (exclusive).",
        [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.2.0"},
                {"fixed": "1.5.0"},
            ],
        }],
        "1.5.0",
    ),
]


def build_sample_db(path: Path) -> Path:
    """Create the sample DB at `path` (parent dirs are created)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE vulns ("
            " group_artifact TEXT NOT NULL,"
            " vuln_id TEXT NOT NULL,"
            " cvss REAL NOT NULL,"
            " severity TEXT NOT NULL,"
            " summary TEXT NOT NULL,"
            " affected_ranges TEXT NOT NULL,"
            " fixed_version TEXT"
            ")",
        )
        conn.execute(
            "CREATE INDEX ix_group_artifact ON vulns(group_artifact)",
        )
        conn.executemany(
            "INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (ga, vid, cvss, sev, summary, json.dumps(ranges), fixed)
                for ga, vid, cvss, sev, summary, ranges, fixed in _SAMPLE_ROWS
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return path
