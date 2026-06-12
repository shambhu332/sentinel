"""Delta scanning — file-level sha256 baseline + skip logic.

Two pieces:

1. `hash_tree(root, suffixes)`  — walks a decompiled tree and returns
   a `{relpath -> sha256_hex}` map. Used by the orchestrator to
   produce a per-scan manifest (later written to the `scan_file` table
   by the SaaS API layer, kept in-memory for OSS).

2. `compute_changed(baseline, current)` — returns the set of relpaths
   whose sha256 differs (new + modified). The orchestrator stamps this
   onto `ctx.changed_files` so agents that operate on a single file
   can early-skip when the file is in the baseline and unchanged.

Agents that do not have a meaningful file-level granularity (network
scope, manifest-driven, etc.) ignore `changed_files` — it's a hint,
not a contract. Adoption is opt-in: an agent that wants delta-skip
behaviour checks `ctx.changed_files` in `analyze()`.

Why this matters in CI: a typical PR touches 5–30 files. Without
delta, every PR re-runs every agent against every file in the 5k+
decompiled tree — for a 91MB APK that's ~10× the work the PR
actually changed.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Default file suffixes that participate in delta hashing
_DEFAULT_SUFFIXES = (".java", ".kt", ".xml")

# Cap files hashed to avoid pathological trees
_MAX_FILES = 20_000


def hash_tree(
    root: Path,
    suffixes: tuple[str, ...] = _DEFAULT_SUFFIXES,
) -> dict[str, str]:
    """Walk `root` and return {relpath -> sha256_hex} for matching files.

    Returns empty dict if root is missing or empty. Bounded by
    _MAX_FILES; warns if hit (suggests a corrupt or unusually
    expanded decompile).
    """
    if not root.exists() or not root.is_dir():
        return {}

    out: dict[str, str] = {}
    scanned = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if suffixes and not path.name.endswith(suffixes):
            continue
        scanned += 1
        if scanned > _MAX_FILES:
            logger.warning(
                "hash_tree: stopped at %d files (root=%s)", _MAX_FILES, root,
            )
            break
        try:
            with path.open("rb") as f:
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
                out[str(path.relative_to(root))] = h.hexdigest()
        except OSError:
            continue
    return out


def compute_changed(
    baseline: dict[str, str],
    current: dict[str, str],
) -> set[str]:
    """Return relpaths whose sha differs (new files + modified files).

    Deletions are intentionally NOT returned: an agent cannot scan a
    file that no longer exists, and the dedup/diff layer surfaces
    deletions separately via fingerprint set difference.
    """
    if not baseline:
        # No baseline → everything is "changed". Caller should signal
        # this by passing `changed_files=None` (full scan) rather than
        # a giant set, but for safety we return the full current set.
        return set(current.keys())

    changed: set[str] = set()
    for path, sha in current.items():
        if baseline.get(path) != sha:
            changed.add(path)
    return changed


def should_skip(ctx_changed_files: set[str] | None, relpath: str) -> bool:
    """Agent helper: return True when an agent should early-skip `relpath`.

    Semantics:
      - `ctx.changed_files is None`  → full-scan mode; never skip.
      - `relpath in ctx.changed_files` → file changed; do not skip.
      - else                          → file unchanged; safe to skip.

    Agents call this at the top of their per-file inner loop. Reading
    the value (not invalidating any cache) is cheap and keeps the
    decision local to the agent.
    """
    if ctx_changed_files is None:
        return False
    return relpath not in ctx_changed_files


__all__ = ["hash_tree", "compute_changed", "should_skip"]
