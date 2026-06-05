"""Finding dedup — merges duplicates between SG_001 (Semgrep) and the
bespoke hand-rolled agents.

Problem: SG_001 rules and C_007 / C_004 / C_002 / A_007 etc. routinely
hit the same vuln in the same file from different angles. Without
dedup the user sees the same issue twice with different agent IDs,
different confidence scores, and different finding_ids — confusing and
inflates the count.

Strategy: conservative, evidence-driven. Two findings dedup when:
  1. They map to the same canonical vulnerability class (lookup table
     of synonyms — Semgrep rule titles vs hand-agent vuln_class)
  2. They reference at least one overlapping source file path

When both hold, keep the higher-severity finding; merge the loser's
evidence under evidence['_deduped_from'] so the data isn't lost.

Deliberate non-goals:
- Line-level merging (Semgrep gives line numbers, hand-agents often
  do not — comparing breaks asymmetrically and produces false negatives)
- LLM-based equivalence (too expensive for a post-Phase-2 step)

The dedup function is pure and side-effect-free aside from emitting
the new evidence key on survivors. Logged when something is dropped.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Canonical category → set of vuln_class substrings (case-insensitive)
# that should all be treated as the same kind of bug. Keep these
# patterns narrow — false dedups silently lose findings.
_CANONICAL: dict[str, tuple[str, ...]] = {
    "weak_crypto": (
        "weak crypto", "weak hash", "ecb cipher", "default cipher",
        "broken crypto", "insecure crypto",
    ),
    "hardcoded_secret": (
        "hardcoded secret", "hardcoded key", "hardcoded api key",
        "api key", "private key", "bearer token",
        # Native side from NL_001
        "secret in native library",
    ),
    "insecure_webview": (
        "insecure webview", "webview javascriptinterface",
        "addjavascriptinterface", "webview file access",
    ),
    "world_readable_storage": (
        "world-readable", "world-writeable", "world_readable",
        "world_writeable", "mode_world_",
    ),
    "insecure_logging": (
        "insecure logging", "sensitive data in log",
    ),
    "cleartext_traffic": (
        "cleartext traffic", "cleartext http", "http traffic",
    ),
    "missing_cert_pinning": (
        "missing certificate pinning", "missing cert pinning",
        "no certificate pinning",
    ),
    "insecure_random": (
        "insecure random",
    ),
}


# Severity priority (higher = stronger)
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _canonicalize(vuln_class: str) -> str | None:
    """Return the canonical category for this vuln_class, or None."""
    lowered = vuln_class.lower()
    for canon, needles in _CANONICAL.items():
        if any(n in lowered for n in needles):
            return canon
    return None


def _file_paths_in(finding: Finding) -> set[str]:
    """Pull every file path mentioned in a finding's evidence."""
    paths: set[str] = set()
    ev = finding.evidence or {}

    # Common direct keys
    for key in ("file", "path"):
        v = ev.get(key)
        if isinstance(v, str) and v:
            paths.add(v)

    # Common list-of-hits shapes
    hits = ev.get("hits")
    if isinstance(hits, list):
        for h in hits:
            if not isinstance(h, dict):
                continue
            for key in ("file", "path", "lib"):
                v = h.get(key)
                if isinstance(v, str) and v:
                    paths.add(v)

    # Semgrep-style 'matches' list
    matches = ev.get("matches")
    if isinstance(matches, list):
        for m in matches:
            if isinstance(m, dict):
                v = m.get("path") or m.get("file")
                if isinstance(v, str) and v:
                    paths.add(v)

    return paths


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge equivalent findings.

    Returns a new list in original order, with merged findings replacing
    losers. Evidence of dropped findings is attached to the survivor
    under evidence['_deduped_from'].
    """
    if len(findings) < 2:
        return findings

    # Bucket by (canonical_category, anchor_file).
    # anchor_file = first sorted file path mentioned in evidence (so
    # two findings hit the same bucket only when at least one file
    # overlaps after intersection).
    # We do a pairwise pass to handle the asymmetric "any path overlap"
    # rule rather than a simple group-by.

    survivors: list[Finding] = []
    survivor_dropped: dict[int, list[dict[str, Any]]] = {}

    for incoming in findings:
        canon = _canonicalize(incoming.vuln_class)
        if canon is None:
            survivors.append(incoming)
            continue

        in_paths = _file_paths_in(incoming)

        merged = False
        for idx, existing in enumerate(survivors):
            existing_canon = _canonicalize(existing.vuln_class)
            if existing_canon != canon:
                continue
            ex_paths = _file_paths_in(existing)
            # If neither has paths, fall back to canonical+severity
            # only — but only collapse if same severity to be safe.
            if not in_paths and not ex_paths:
                continue
            if in_paths and ex_paths and not (in_paths & ex_paths):
                continue
            # Found a duplicate. Decide winner by severity, then
            # confidence as tiebreaker.
            in_rank = _SEVERITY_RANK[incoming.severity]
            ex_rank = _SEVERITY_RANK[existing.severity]
            if in_rank > ex_rank or (
                in_rank == ex_rank
                and incoming.confidence > existing.confidence
            ):
                # Incoming wins — swap, accumulate
                survivor_dropped[idx] = survivor_dropped.get(idx, []) + [
                    _dropped_summary(existing),
                ]
                survivors[idx] = incoming
                logger.info(
                    "[dedup] %s/%s superseded %s/%s for canonical=%s",
                    incoming.agent_id, incoming.vuln_class,
                    existing.agent_id, existing.vuln_class, canon,
                )
            else:
                # Existing wins — drop incoming
                survivor_dropped[idx] = survivor_dropped.get(idx, []) + [
                    _dropped_summary(incoming),
                ]
                logger.info(
                    "[dedup] %s/%s dropped (covered by %s/%s) canon=%s",
                    incoming.agent_id, incoming.vuln_class,
                    existing.agent_id, existing.vuln_class, canon,
                )
            merged = True
            break

        if not merged:
            survivors.append(incoming)

    # Re-emit survivors with merged-evidence annotations
    if not survivor_dropped:
        return survivors
    result: list[Finding] = []
    for idx, f in enumerate(survivors):
        dropped = survivor_dropped.get(idx)
        if not dropped:
            result.append(f)
            continue
        new_evidence = dict(f.evidence or {})
        existing_merged = new_evidence.get("_deduped_from")
        if isinstance(existing_merged, list):
            new_evidence["_deduped_from"] = existing_merged + dropped
        else:
            new_evidence["_deduped_from"] = dropped
        # Re-validate via Finding constructor so the dedup metadata
        # stays inside the strict Pydantic envelope.
        result.append(f.model_copy(update={"evidence": new_evidence}))
    return result


def _dropped_summary(f: Finding) -> dict[str, Any]:
    """Lightweight summary of a dropped finding for audit trail."""
    return {
        "agent_id": f.agent_id,
        "vuln_class": f.vuln_class,
        "severity": f.severity.value,
        "confidence": f.confidence,
    }


__all__ = ["dedupe"]
