"""D_045 — Local SQLite SQLi prober (Dynamic Testing Target).

Complements D_063 (ContentProvider SQLi). D_063 targets the
cross-app boundary; D_045 targets app-internal SQLite — rawQuery /
execSQL inside the app's own ROOM/SQLite helper where input came
from a deep link, push notification, or saved-state restore.
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_UNSAFE_SQL_RE = re.compile(
    r'\b(rawQuery|execSQL)\s*\(\s*"[^"]*"\s*\+'
    r'|\b(rawQuery|execSQL)\s*\(\s*\w+\s*\+'
    r"|\b(rawQuery|execSQL)\s*\(\s*\".*?\"\s*\+\s*\w"
)
_HELPER_RE = re.compile(
    r"extends\s+SQLiteOpenHelper|extends\s+RoomDatabase|"
    r"@Query\s*\(\s*[\"']"
)
_INPUT_SOURCES_RE = re.compile(
    r"intent\.getStringExtra|getQueryParameter|getString\("
)


class SqliteProberAgent(BaseAgent):
    AGENT_ID = "D_045"
    VULN_CLASS = "Local SQLite SQLi (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir
            and self._context.decompiled_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        root = self._context.decompiled_dir
        assert root is not None
        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > 2000:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            unsafe_hits = _UNSAFE_SQL_RE.findall(text)
            if not unsafe_hits:
                continue
            in_db_class = bool(_HELPER_RE.search(text))
            input_tainted = bool(_INPUT_SOURCES_RE.search(text))
            severity = Severity.HIGH if (input_tainted and in_db_class) else Severity.MEDIUM
            rel = str(path.relative_to(root))
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.65,
                recommendation=(
                    "rawQuery / execSQL with string-concatenated input "
                    "inside a SQLite helper class. The Frida hook will "
                    "intercept the rawQuery entry and inject 5 SQLi probe "
                    "selections; the DAST observer correlates returned "
                    "row counts. Switch to bind args (?,?,?) or Room "
                    "@Query parameter binding."
                ),
                evidence={
                    "file": rel,
                    "unsafe_call_count": len(unsafe_hits),
                    "in_sqlite_helper_class": in_db_class,
                    "user_input_traceable": input_tainted,
                    "dynamic_target": True,
                    "frida_payload": {
                        "target_class_file": rel,
                        "probe_selections": [
                            "' OR 1=1--",
                            "1) UNION SELECT name FROM sqlite_master--",
                            "x'; DROP TABLE x--",
                            "1=1)--",
                            "0 UNION SELECT 1,2,3--",
                        ],
                        "safety_budget": {
                            "max_actions_total": 25,
                            "max_actions_per_sec": 3,
                            "wall_clock_budget_s": 30,
                            "max_consecutive_crashes": 3,
                        },
                    },
                },
            ))
        return findings


__all__ = ["SqliteProberAgent"]
