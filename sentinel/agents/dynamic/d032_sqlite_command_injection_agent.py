"""D_032 — SQLite Command Injection / Unparameterised Query.

Android's ``SQLiteDatabase`` exposes ``rawQuery``,
``execSQL``, ``query``, and ``insert`` / ``update`` / ``delete``.
The safe path is always the same: a fixed SQL string with ``?``
placeholders and a separate ``selectionArgs`` array. The unsafe path
is string concatenation:

    db.execSQL("UPDATE users SET name='" + name + "' WHERE id=" + id);

If ``name`` carries a single quote or ``id`` is a SQL fragment, the
attacker has rewritten the statement. Static SAST catches obvious
``+`` concatenations; this agent catches the obfuscated cases —
``String.format``, builder patterns, third-party ORMs with raw
escape hatches, and runtime-decoded template strings.

Detection
---------

We consume one Frida event kind:

* ``sqlite.query_executed`` — emitted from every
  ``rawQuery`` / ``execSQL`` / ``query`` overload.
  Payload: ``{api, sql, args_count, has_question_marks,
  contains_quote_literal, caller_class, stack}``.

``args_count`` is the length of the bind-args array (0 / null if the
caller didn't pass one). ``has_question_marks`` is whether the SQL
string contains at least one ``?`` placeholder.
``contains_quote_literal`` is whether the SQL string contains a
``'…'`` literal — a strong indicator of concatenated user input
since safe templates put quotes around ``?`` placeholders, not
literal values.

Severity matrix:

* **HIGH** — ``args_count == 0`` and the SQL contains both a
  ``'…'`` literal and a SQL keyword that takes a value (``WHERE``,
  ``SET``, ``VALUES``, ``LIKE``). Strong indicator of concatenation.
* **HIGH** — ``args_count == 0`` and the SQL contains a ``--`` or
  ``;`` outside a string literal (typical of injected SQL surviving
  through a vulnerable concat).
* **MEDIUM** — ``args_count == 0`` on a ``rawQuery`` / ``execSQL``
  call where the SQL string is longer than 200 characters (large
  hand-built queries are statistically more likely to embed
  variable content).
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_VALUE_KEYWORD = re.compile(
    r"\b(where|set|values|like)\b", re.IGNORECASE,
)
_STRING_LITERAL = re.compile(r"'[^']{1,200}'")
_COMMENT_OR_TERMINATOR = re.compile(r"(--|;)")


def _has_value_keyword(sql: str) -> bool:
    return bool(_VALUE_KEYWORD.search(sql))


def _has_string_literal(sql: str) -> bool:
    return bool(_STRING_LITERAL.search(sql))


def _has_comment_or_terminator(sql: str) -> bool:
    # Strip out the string literals before checking — a ; or -- inside
    # a quoted string is fine.
    stripped = _STRING_LITERAL.sub("''", sql)
    return bool(_COMMENT_OR_TERMINATOR.search(stripped))


class SqliteCommandInjectionAgent(BaseAgent):
    """D_032: catch unparameterised SQL at runtime."""

    AGENT_ID = "D_032"
    VULN_CLASS = "SQLite Command Injection / Unparameterised Query"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_032] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        literal_hits: list[dict[str, Any]] = []
        comment_hits: list[dict[str, Any]] = []
        large_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "sqlite.query_executed":
                continue
            payload = ev.payload or {}
            sql = str(payload.get("sql") or "")
            if not sql:
                continue
            args_count = _coerce_int(payload.get("args_count")) or 0
            if args_count > 0:
                # The caller bound arguments — likely safe.
                continue
            api = str(payload.get("api") or "")
            sample = {
                "api": api,
                "sql": sql[:400],
                "sql_length": len(sql),
                "args_count": args_count,
                "caller_class": str(payload.get("caller_class") or "")[:200],
                "stack": payload.get("stack"),
            }

            if _has_string_literal(sql) and _has_value_keyword(sql):
                literal_hits.append(sample)
            elif _has_comment_or_terminator(sql):
                comment_hits.append(sample)
            elif len(sql) > 200 and api in {"rawQuery", "execSQL"}:
                large_hits.append(sample)

        findings: list[Finding] = []
        if literal_hits:
            findings.append(self._literal_finding(literal_hits))
        if comment_hits:
            findings.append(self._comment_finding(comment_hits))
        if large_hits:
            findings.append(self._large_finding(large_hits))
        return findings

    def _literal_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.82,
            evidence={
                "issue": (
                    "A SQLite statement was issued without bind-args, "
                    "contained both a value-taking keyword (WHERE / "
                    "SET / VALUES / LIKE) and an embedded string "
                    "literal (``'…'``). That is the canonical shape "
                    "of a query built by concatenating a Java string "
                    "into the SQL — when the substituted value comes "
                    "from external input, the statement is injectable."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on SQLiteDatabase.{rawQuery, "
                    "execSQL, query} captured the SQL string and "
                    "bind-args count."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Replace the concatenated literal with a ``?`` "
                "placeholder and pass the value through "
                "``selectionArgs``. For non-WHERE columns (table / "
                "column names that cannot be parameterised), validate "
                "the input against an explicit allow-list."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _comment_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="SQLite Statement Contains Comment / Statement Terminator",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "An issued SQLite statement contains a ``--`` "
                    "comment or a ``;`` statement terminator outside "
                    "any string literal. Both are common artefacts of "
                    "an injection payload that survived through a "
                    "concatenation. Even if the value was supplied "
                    "innocently, the parser accepted it — confirm "
                    "whether the input is attacker-influenceable."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook saw a ``--`` / ``;`` in the SQL "
                    "after stripping string literals."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Move to bound parameters. Add an explicit reject for "
                "any input containing ``--``, ``;``, or unmatched "
                "quotes at the API boundary."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        )

    def _large_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Large Unparameterised SQLite Statement",
            severity=Severity.MEDIUM,
            confidence=0.55,
            evidence={
                "issue": (
                    "A rawQuery / execSQL statement longer than 200 "
                    "characters was issued without any bind-args. "
                    "Long hand-built statements are statistically "
                    "more likely to embed variable content. The shape "
                    "is suspicious even when the keyword + literal "
                    "rules don't trip."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook flagged SQL strings > 200 chars with "
                    "an empty selectionArgs."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Audit the call sites and migrate any caller-"
                "influenced values onto ``?`` placeholders."
            ),
            owasp="M7: Insufficient Binary Protections",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        )


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
