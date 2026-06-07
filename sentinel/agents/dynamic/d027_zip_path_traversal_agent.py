"""D_027 — Zip Slip / Path-Traversal in Archive Extraction.

When an Android app downloads a ZIP / JAR / APK / AAR / OBB archive
and extracts it without validating each ``ZipEntry`` name, an
attacker who controls the archive can write entries whose name
contains ``..`` segments (``../../etc/passwd``) or an absolute path
(``/sdcard/Download/payload.dex``). The dev's loop typically does:

    File out = new File(targetDir, entry.getName());
    new FileOutputStream(out).write(...);

``new File(targetDir, "../../x")`` resolves to a path *outside*
``targetDir`` — the file lands wherever the attacker pointed it.
Real-world Android impact ranges from app-takeover via DEX overwrite
(dynamic-code-loading paths) through silent installation of a
malicious config to overwriting tokens cached on the SD card.

Detection
---------

We consume two Frida event kinds:

* ``zip.entry_observed`` — emitted on every
  ``ZipInputStream.getNextEntry`` / ``ZipFile.getEntry`` return.
  Payload: ``{name, size, source, stack}``.
* ``zip.entry_extracted`` — emitted when a ``FileOutputStream`` is
  opened while a ``ZipInputStream.read`` frame is live on the stack.
  Payload: ``{entry_name, target_path, canonical_path,
  intended_dir, escaped_intended_dir, stack}``.

Classification:

* **CRITICAL** — ``zip.entry_extracted`` with
  ``escaped_intended_dir=True`` (FileOutputStream's canonical path
  starts outside the intended target dir — confirmed Zip Slip).
* **HIGH** — ``zip.entry_observed`` whose name contains ``..`` or
  starts with ``/`` AND the same entry's ``name`` later shows up in
  a ``zip.entry_extracted`` event (the dev's loop accepted the
  suspicious entry, even if our canonical-path check couldn't
  confirm escape).
* **MEDIUM** — ``zip.entry_observed`` with a traversal-shape name
  but no matching extraction was observed (the archive carried the
  primitive but the app may or may not have written it).
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


def _is_traversal_name(name: str) -> bool:
    if not name:
        return False
    # Absolute path entry — illegal in well-formed archives.
    if name.startswith("/") or name.startswith("\\"):
        return True
    # Windows-drive entry.
    if len(name) >= 2 and name[1] == ":":
        return True
    # ".." segment anywhere.
    norm = name.replace("\\", "/")
    parts = norm.split("/")
    return ".." in parts


class ZipPathTraversalAgent(BaseAgent):
    """D_027: catch Zip-Slip primitives during archive extraction."""

    AGENT_ID = "D_027"
    VULN_CLASS = "Zip-Slip / Archive Path Traversal"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_027] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        suspicious_entries: dict[str, dict[str, Any]] = {}
        extractions: list[dict[str, Any]] = []
        escaped: list[dict[str, Any]] = []

        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "zip.entry_observed":
                name = str(payload.get("name") or "")
                if not _is_traversal_name(name):
                    continue
                suspicious_entries[name] = {
                    "name": name[:300],
                    "size": payload.get("size"),
                    "source": payload.get("source"),
                    "stack": payload.get("stack"),
                }
            elif ev.kind == "zip.entry_extracted":
                name = str(payload.get("entry_name") or "")
                sample = {
                    "entry_name": name[:300],
                    "target_path": str(payload.get("target_path") or "")[:300],
                    "canonical_path": str(
                        payload.get("canonical_path") or "",
                    )[:300],
                    "intended_dir": str(
                        payload.get("intended_dir") or "",
                    )[:300],
                    "stack": payload.get("stack"),
                }
                if payload.get("escaped_intended_dir"):
                    escaped.append(sample)
                elif _is_traversal_name(name):
                    extractions.append(sample)

        # An observed-only entry whose name later appears in an
        # extraction event is the "accepted but unconfirmed escape"
        # case. Anything still in suspicious_entries after this filter
        # is observation-only.
        accepted_names = {e["entry_name"] for e in extractions}
        accepted = [
            suspicious_entries.pop(n)
            for n in list(suspicious_entries)
            if n in accepted_names
        ]

        findings: list[Finding] = []
        if escaped:
            findings.append(self._escaped_finding(escaped))
        if accepted:
            findings.append(self._accepted_finding(accepted))
        if suspicious_entries:
            findings.append(
                self._observed_finding(list(suspicious_entries.values())),
            )
        return findings

    def _escaped_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence={
                "issue": (
                    "A FileOutputStream opened during ZIP extraction "
                    "resolved to a canonical path **outside** the "
                    "intended target directory. The archive's "
                    "``..`` / absolute-path entry was honoured by the "
                    "extractor — confirmed Zip Slip with arbitrary-"
                    "file-write impact."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on FileOutputStream.<init> compared "
                    "the file's canonical path against the intended "
                    "target dir whenever a ZipInputStream.read frame "
                    "was live on the stack."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Before writing each entry, compute "
                "``target.getCanonicalFile()`` and verify that its "
                "path starts with ``intendedDir.getCanonicalPath() + "
                "File.separator``. Reject the archive if any single "
                "entry fails. Apache Commons Compress and Okio give "
                "you `entryWithinDirectory()` helpers — prefer them "
                "to hand-rolled loops."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        )

    def _accepted_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Zip-Slip Entry Accepted by Extractor",
            severity=Severity.HIGH,
            confidence=0.80,
            evidence={
                "issue": (
                    "The extractor consumed an entry whose name "
                    "contains a traversal sequence and proceeded to "
                    "open a FileOutputStream for it. Our canonical-"
                    "path comparison could not prove the resulting "
                    "file escaped the intended dir (the hook may not "
                    "have seen the intended dir, or the path coalesced "
                    "back inside it). The primitive is real — the "
                    "missing guard rail is the only thing protecting "
                    "the app."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook saw ZipInputStream.getNextEntry "
                    "return a traversal-shape name and a matching "
                    "FileOutputStream.<init> reached the disk."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Same as the CRITICAL variant: gate every extraction "
                "with a canonical-path-prefix check against the "
                "intended directory."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        )

    def _observed_finding(self, hits: list[dict[str, Any]]) -> Finding:
        return self._make_finding(
            vuln_class="Traversal-Shape Archive Entry Observed",
            severity=Severity.MEDIUM,
            confidence=0.55,
            evidence={
                "issue": (
                    "ZipInputStream returned an entry whose name "
                    "contains a traversal sequence or an absolute "
                    "path. No matching extraction was observed in "
                    "this capture, so we cannot prove the extractor "
                    "wrote the entry — but the archive carrying such "
                    "an entry past validation indicates a missing "
                    "front-door check."
                ),
                "occurrence_count": len(hits),
                "samples": hits[:5],
                "vector": (
                    "Frida hook on ZipInputStream.getNextEntry / "
                    "ZipFile.getEntry inspected the returned name."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Validate every ``ZipEntry.getName()`` before *any* "
                "read — reject the entry if the name contains "
                "``..``, starts with ``/``, or contains "
                "back-slashes. Refusing at the entry level is "
                "cheaper than rolling back partial writes."
            ),
            owasp="M2: Insecure Data Storage",
            masvs="MSTG-PLATFORM-2",
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        )
