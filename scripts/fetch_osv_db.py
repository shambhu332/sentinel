#!/usr/bin/env python3
"""scripts/fetch_osv_db.py — build the offline OSV Maven CVE database.

Downloads the public OSV.dev Maven ecosystem dump, parses every JSON
advisory, and writes a SQLite database that SCA_001 (SCAAgent) queries
at scan time. The upstream dump refreshes daily; re-run this script
whenever you want newer CVE coverage.

Default output: data/osv_maven.sqlite (gitignored — refresh locally).

Schema:
    vulns(
        group_artifact   TEXT NOT NULL,   -- "com.squareup.okhttp3:okhttp"
        vuln_id          TEXT NOT NULL,   -- "GHSA-..." or "CVE-..."
        cvss             REAL NOT NULL,   -- 0.0–10.0 (0.0 if unknown)
        severity         TEXT NOT NULL,   -- Critical/High/Medium/Low
        summary          TEXT NOT NULL,
        affected_ranges  TEXT NOT NULL,   -- JSON-encoded OSV `ranges`
        fixed_version    TEXT             -- first `fixed` event, if any
    )
    INDEX ix_group_artifact ON vulns(group_artifact)

Each row is one (advisory × affected-Maven-package) pair, so a CVE
hitting two coordinates inserts two rows. Querying by group_artifact
returns every CVE touching that coordinate.

Usage:
    poetry run python scripts/fetch_osv_db.py
    poetry run python scripts/fetch_osv_db.py --db /tmp/osv.sqlite
    poetry run python scripts/fetch_osv_db.py --zip pre-downloaded.zip
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sqlite3
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

OSV_MAVEN_URL = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
DEFAULT_DB_PATH = Path("data/osv_maven.sqlite")

logger = logging.getLogger("fetch_osv_db")


def _cvss_for(advisory: dict) -> float:
    """Pull the highest CVSS base score out of an OSV advisory.

    OSV's `severity` is a list of {type, score}. CVSS_V3/V4 scores are
    formatted as either a vector ("CVSS:3.1/AV:N/...") OR a bare number,
    depending on the source feed. Parse the trailing number in either
    case; fall back to `database_specific.cvss_score` for advisories that
    only carry a vendor-supplied numeric.
    """
    best = 0.0
    for entry in advisory.get("severity") or []:
        score = str(entry.get("score") or "")
        m = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*$", score)
        if m:
            try:
                v = float(m.group(1))
                if v > best:
                    best = v
            except ValueError:
                pass
    ds = advisory.get("database_specific")
    if isinstance(ds, dict):
        for key in ("cvss_score", "score", "severity"):
            val = ds.get(key)
            if isinstance(val, (int, float)) and float(val) > best:
                best = float(val)
    return best


def _severity_for(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _fixed_version(ranges: list) -> str | None:
    """Walk OSV `ranges`, return the first explicit `fixed` event.

    Returns None when every range is open-ended (no upstream fix yet) —
    SCA_001 surfaces this case in its recommendation text.
    """
    for r in ranges or []:
        for event in r.get("events", []):
            if "fixed" in event:
                return event["fixed"]
    return None


def _download(url: str, dest: Path) -> None:
    logger.info("Downloading %s ...", url)
    req = urllib.request.Request(
        url, headers={"User-Agent": "sentinel-sca/0.1"},
    )
    # bandit: URL is hard-coded to OSV; no user-controlled input
    with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310
        with dest.open("wb") as f:
            while chunk := resp.read(1 << 20):
                f.write(chunk)
    size_mb = dest.stat().st_size / (1024 * 1024)
    logger.info("Downloaded %.1f MiB", size_mb)


def _iter_advisories(zip_path: Path):
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if n.endswith(".json")]
        logger.info("Found %d advisory files in dump", len(names))
        for name in names:
            try:
                with z.open(name) as f:
                    yield json.load(f)
            except (json.JSONDecodeError, KeyError, OSError) as e:
                logger.debug("Skip %s: %s", name, e)


def build_db(db_path: Path, zip_path: Path) -> int:
    """Parse the zip and write rows. Returns number of rows inserted."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
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

        rows: list[tuple] = []
        adv_count = 0
        for adv in _iter_advisories(zip_path):
            adv_count += 1
            vuln_id = adv.get("id", "")
            summary = (adv.get("summary") or adv.get("details") or "")[:500]
            cvss = _cvss_for(adv)
            severity = _severity_for(cvss)

            for affected in adv.get("affected") or []:
                pkg = affected.get("package") or {}
                if pkg.get("ecosystem") != "Maven":
                    continue
                ga = (pkg.get("name") or "").strip()
                if ":" not in ga:
                    continue
                ranges = affected.get("ranges") or []
                fixed = _fixed_version(ranges)
                rows.append((
                    ga.lower(), vuln_id, cvss, severity, summary,
                    json.dumps(ranges), fixed,
                ))

            if len(rows) >= 5000:
                conn.executemany(
                    "INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?)", rows,
                )
                rows.clear()

        if rows:
            conn.executemany(
                "INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?)", rows,
            )
        conn.commit()
        (total,) = conn.execute(
            "SELECT COUNT(*) FROM vulns",
        ).fetchone()
        logger.info(
            "Parsed %d advisories, inserted %d rows into %s",
            adv_count, total, db_path,
        )
        return total
    finally:
        conn.close()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(
        description=(
            "Build the offline OSV Maven CVE database for SENTINEL's "
            "SCA_001 supply-chain agent."
        ),
    )
    parser.add_argument(
        "--db", type=Path, default=DEFAULT_DB_PATH,
        help=f"Destination SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--zip", type=Path, default=None,
        help="Use a pre-downloaded all.zip instead of fetching (offline)",
    )
    args = parser.parse_args()

    if args.zip and args.zip.exists():
        logger.info("Building from pre-downloaded zip: %s", args.zip)
        rows = build_db(args.db, args.zip)
    else:
        with tempfile.TemporaryDirectory() as td:
            zip_path = Path(td) / "all.zip"
            try:
                _download(OSV_MAVEN_URL, zip_path)
            except (urllib.request.HTTPError, urllib.request.URLError, OSError) as e:
                logger.error("Download failed: %s", e)
                logger.error(
                    "If you are offline, fetch %s manually and pass it "
                    "with --zip",
                    OSV_MAVEN_URL,
                )
                return 2
            rows = build_db(args.db, zip_path)

    logger.info("Done. DB at %s (%d rows).", args.db, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
