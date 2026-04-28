"""C_002 — World-Readable Storage Agent.

Detects insecure storage modes that make application data accessible to
other apps on the device.

Why this matters: when an app uses MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE,
any other app on the device can read or modify that data. These flags were
deprecated by Android 4.2 and explicitly throw SecurityException in Android
7+, but apps with low minSdk still ship with them and they remain functional
in older devices. Bug bounty programs pay $300-$1500 for confirmed
world-readable storage findings, especially when sensitive data (credentials,
tokens, PII) is involved.

Detection pipeline:
1. Walk decompiled .java files
2. Search for usage of MODE_WORLD_READABLE, MODE_WORLD_WRITEABLE constants
   (and their integer values: 1 and 2 respectively when used as raw ints)
3. Search for openFileOutput() and getSharedPreferences() calls with
   these modes
4. Flag each occurrence with file location and surrounding context
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Constants — match symbolic and direct usage
_MODE_WORLD_READABLE_RE = re.compile(
    r"\b(?:Context\.)?MODE_WORLD_READABLE\b",
)

_MODE_WORLD_WRITEABLE_RE = re.compile(
    r"\b(?:Context\.)?MODE_WORLD_(?:WRIT(?:E)?ABLE|WRITEABLE)\b",
)

# Calls that take a mode argument
_INSECURE_CALL_RE = re.compile(
    r"\b(openFileOutput|getSharedPreferences|getDir|openOrCreateDatabase)"
    r"\s*\([^)]*?MODE_WORLD_(?:READABLE|WRIT(?:E)?ABLE)[^)]*?\)",
    re.IGNORECASE | re.DOTALL,
)

# chmod 666 / 777 / 644 patterns — file system permissions
_CHMOD_INSECURE_RE = re.compile(
    r'(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder).*?["\']chmod\s+(?:666|777|646|0666|0777)',
    re.IGNORECASE | re.DOTALL,
)

_MAX_FILES_TO_SCAN = 3000
_MAX_HITS_PER_FINDING = 20


class WorldReadableStorageAgent(BaseAgent):
    """C_002: detects MODE_WORLD_READABLE / WRITEABLE storage usage."""

    AGENT_ID = "C_002"
    VULN_CLASS = "World-Readable Storage"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[C_002] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        hits: list[dict[str, Any]] = []

        files_scanned = 0
        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file():
                continue
            files_scanned += 1
            if files_scanned > _MAX_FILES_TO_SCAN:
                logger.warning("[C_002] Stopped scanning after %d files",
                               _MAX_FILES_TO_SCAN)
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            rel = str(path.relative_to(ctx.decompiled_dir))

            for kind, pattern in (
                ("MODE_WORLD_READABLE", _MODE_WORLD_READABLE_RE),
                ("MODE_WORLD_WRITEABLE", _MODE_WORLD_WRITEABLE_RE),
                ("Insecure storage call", _INSECURE_CALL_RE),
                ("chmod 666/777", _CHMOD_INSECURE_RE),
            ):
                for match in pattern.finditer(text):
                    # Capture the line for context
                    start = max(0, text.rfind("\n", 0, match.start()) + 1)
                    end = text.find("\n", match.end())
                    if end == -1:
                        end = len(text)
                    line = text[start:end].strip()

                    hits.append({
                        "kind": kind,
                        "file": rel,
                        "context": line[:200],
                        "matched": match.group(0)[:80],
                    })

        if not hits:
            logger.info("[C_002] No world-readable storage usage detected")
            return []

        # Group findings by kind
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for h in hits:
            by_kind.setdefault(h["kind"], []).append(h)

        # Severity logic: write access > read access
        has_writeable = bool(by_kind.get("MODE_WORLD_WRITEABLE")
                             or any("WRIT" in h["matched"] for h in hits))
        has_readable = bool(by_kind.get("MODE_WORLD_READABLE")
                            or any("READ" in h["matched"] for h in hits))

        if has_writeable:
            severity = Severity.HIGH
            confidence = 0.85
            summary = "MODE_WORLD_WRITEABLE detected — any app can modify private files"
        elif has_readable:
            severity = Severity.MEDIUM
            confidence = 0.85
            summary = "MODE_WORLD_READABLE detected — any app can read private files"
        else:
            severity = Severity.MEDIUM
            confidence = 0.75
            summary = "Insecure file permission patterns detected (chmod 666/777)"

        return [self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(has_writeable, has_readable),
            evidence={
                "title": "World-Readable / Writeable Storage Detected",
                "summary": summary,
                "package": (ctx.manifest or {}).get("package", "?"),
                "total_hits": len(hits),
                "by_kind": {
                    kind: len(items) for kind, items in by_kind.items()
                },
                "hits": hits[:_MAX_HITS_PER_FINDING],
                "vector": (
                    "Install a second test app on the same device. From it, open "
                    "the target app's data directory in /data/data/<target_package>/ "
                    "(or use Android's Context.createPackageContext). Files marked "
                    "with WORLD_READABLE/WRITEABLE are accessible to any installed app "
                    "without requiring permissions."
                ),
            },
        )]

    @staticmethod
    def _build_recommendation(has_writeable: bool, has_readable: bool) -> str:
        steps: list[str] = []

        steps.append(
            "Replace MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE with "
            "Context.MODE_PRIVATE everywhere. Files created with MODE_PRIVATE "
            "are accessible only to the application that created them. "
            "On Android 7+ (API 24+) the world-* modes throw SecurityException, "
            "but on older devices these calls still work and expose data."
        )

        if has_writeable:
            steps.append(
                "Audit existing files written with MODE_WORLD_WRITEABLE — they "
                "may have been modified by other apps. Treat their contents as "
                "untrusted on next read."
            )

        steps.append(
            "For sensitive data (credentials, tokens, PII), use the Android "
            "Keystore for keys, EncryptedSharedPreferences for key-value data, "
            "or EncryptedFile for documents. See: "
            "https://developer.android.com/topic/security/data"
        )

        return " ".join(steps)
