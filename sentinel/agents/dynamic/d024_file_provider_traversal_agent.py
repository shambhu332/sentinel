"""D_024 — FileProvider Path-Traversal / Symlink Escape.

``androidx.core.content.FileProvider`` is the canonical way to share
individual files with another app. The dev declares a set of roots in
``res/xml/paths.xml`` (``files-path``, ``cache-path``,
``external-files-path``, …) and any call to
``FileProvider.getUriForFile(context, authority, file)`` is rejected
with ``IllegalArgumentException`` when ``file`` is not under any
declared root.

The check is implemented by walking parent directories of the
``getCanonicalFile()`` of the input — so a sound check, *as long as
the input was already canonicalised*. Two real-world bypasses survive
that check:

1. **Caller-controlled relative segments.** The app builds the file
   via ``new File(rootDir, untrustedName)`` where ``untrustedName``
   contains ``..`` segments. ``getCanonicalFile`` collapses the
   ``..`` and yields a file *inside* a declared root that the dev
   never intended to expose.

2. **Symlink inside the root.** The app writes a symlink under one of
   the declared roots and ``getCanonicalFile`` resolves it to a path
   *outside* every root — but FileProvider's pre-check compares the
   *canonical* path of the user-facing root, so a symlink whose
   target was a *sibling* of the root still slips through.

Detection
---------

We consume one Frida event kind:

* ``file_provider.uri_minted`` — emitted from
  ``FileProvider.getUriForFile(Context, String authority, File file)``.
  Payload: ``{authority, input_path, canonical_path, is_symlink,
  caller_controlled_segments}``.

Classification:

* **HIGH** — ``canonical_path`` falls *outside* this app's data dir
  entirely (symlink escape) — the resulting content URI exposes a
  file the FileProvider's ``paths.xml`` was never meant to touch.
* **MEDIUM** — ``input_path`` contained a ``..`` segment but the
  canonical path still lives under the app dir. The dev's allow-list
  was honoured but caller-controlled traversal worked — likely a
  confused-deputy primitive when the basename came from an Intent
  extra.
* **MEDIUM** — input was a symlink and ``canonical_path`` is in a
  cache / temp dir the FileProvider declares but the dev probably
  did not intend to be world-readable.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class FileProviderTraversalAgent(BaseAgent):
    """D_024: catch path-traversal / symlink escapes via FileProvider."""

    AGENT_ID = "D_024"
    VULN_CLASS = "FileProvider Path-Traversal / Symlink Escape"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_024] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        own_pkg = (self._context.manifest or {}).get("package") or ""

        escape_hits: list[dict[str, Any]] = []
        traversal_hits: list[dict[str, Any]] = []
        symlink_internal_hits: list[dict[str, Any]] = []

        for ev in capture.events:
            if ev.kind != "file_provider.uri_minted":
                continue
            payload = ev.payload or {}
            input_path = str(payload.get("input_path") or "")
            canonical_path = str(payload.get("canonical_path") or "")
            is_symlink = bool(payload.get("is_symlink"))
            traversal_seen = bool(
                payload.get("caller_controlled_segments")
                or ".." in input_path.split("/")
            )
            sample = {
                "authority": str(payload.get("authority") or ""),
                "input_path": input_path[:300],
                "canonical_path": canonical_path[:300],
                "is_symlink": is_symlink,
                "stack": payload.get("stack"),
            }

            if canonical_path and not _is_inside_app_dir(canonical_path, own_pkg):
                escape_hits.append(sample)
            elif traversal_seen:
                traversal_hits.append(sample)
            elif is_symlink:
                symlink_internal_hits.append(sample)

        findings: list[Finding] = []
        if escape_hits:
            findings.append(self._escape_finding(escape_hits))
        if traversal_hits:
            findings.append(self._traversal_finding(traversal_hits))
        if symlink_internal_hits:
            findings.append(self._symlink_internal_finding(symlink_internal_hits))
        return findings

    def _escape_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="FileProvider Symlink Escape",
            severity=Severity.HIGH,
            confidence=0.92,
            evidence={
                "issue": (
                    "FileProvider.getUriForFile returned a content URI "
                    "for a file whose canonical path resolves *outside* "
                    "this application's data directory entirely. The "
                    "input was a symlink whose target sits beyond every "
                    "declared paths.xml root. Anyone the URI is shared "
                    "with can read the symlink target — typically "
                    "/data/data/<other-pkg>/, /system/, or any FS "
                    "location the app's UID can see."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on FileProvider.getUriForFile compared "
                    "input absolute path against File.getCanonicalPath()."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Resolve and canonicalise the file *before* calling "
                "getUriForFile, then verify the canonical path starts "
                "with the expected root prefix. Drop ``cache-path`` "
                "and ``external-cache-path`` from paths.xml if you "
                "don't actually need them — both are easy symlink-bait."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-4",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
        )

    def _traversal_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="FileProvider Path Traversal via Caller-Controlled Segment",
            severity=Severity.MEDIUM,
            confidence=0.78,
            evidence={
                "issue": (
                    "FileProvider.getUriForFile was called with a path "
                    "containing one or more ``..`` segments that the "
                    "canonicaliser collapsed. The resulting URI still "
                    "stayed within a declared paths.xml root, so "
                    "FileProvider accepted the request — but the "
                    "*basename* delivered to the URI was different "
                    "from the dev's intent. If the basename came from "
                    "an Intent extra, deep-link, or any external "
                    "source, the caller chose which sibling file "
                    "inside the root to expose."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on FileProvider.getUriForFile observed "
                    "``..`` segments in the input path."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Validate the untrusted basename against an allow-"
                "list before building the File. Treat any path that "
                "contains '/', '..', or starts with '.' as suspect. "
                "If the basename is an opaque identifier (UUID, "
                "row-ID), prefer storing the mapping in a database "
                "and looking up the on-disk filename server-side."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        )

    def _symlink_internal_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="FileProvider Symlink Resolved Inside App Dir",
            severity=Severity.MEDIUM,
            confidence=0.65,
            evidence={
                "issue": (
                    "FileProvider.getUriForFile was called with a "
                    "symlink. The canonical path stayed inside the "
                    "app's data directory, so no escape occurred this "
                    "run — but the symlink itself is caller-influenced "
                    "if the input filename came from an external "
                    "source, and a future capture may show a target "
                    "outside the app dir."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on FileProvider.getUriForFile observed "
                    "the input File was a symlink."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Refuse symlinks at the dev boundary: call "
                "``Files.isSymbolicLink(file.toPath())`` before "
                "getUriForFile and reject. If the input must be "
                "polymorphic, materialise it to a fresh "
                "non-symlink copy in a temp dir."
            ),
            owasp="M1: Improper Platform Usage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        )


def _is_inside_app_dir(canonical_path: str, own_pkg: str) -> bool:
    p = canonical_path.lower()
    if not p:
        return False
    if not own_pkg:
        return (
            p.startswith("/data/data/")
            or p.startswith("/data/user/")
            or p.startswith("/data/user_de/")
        )
    pkg = own_pkg.lower()
    return (
        f"/data/data/{pkg}/" in p
        or f"/data/user/0/{pkg}/" in p
        or f"/data/user_de/0/{pkg}/" in p
        # External / scoped storage owned by the package — also "the
        # app's own data" for FileProvider purposes.
        or f"/android/data/{pkg}/" in p
        or f"/android/media/{pkg}/" in p
    )
