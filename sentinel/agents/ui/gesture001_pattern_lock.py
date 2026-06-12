"""GESTURE_001 — Custom pattern-lock weakness detector.

Many fintech / wallet apps roll their own pattern-lock screen rather
than using the platform `BiometricPrompt` + KeyStore. The custom
implementations consistently get one of three things wrong:

  1. **Plaintext storage** — pattern dots persisted to SharedPreferences
     as a CSV / JSON / String. Trivial recovery via root or backup.
  2. **Hash without salt** — `md5(pattern)` or `sha1(pattern)` with a
     stable key. Pattern space is at most ~389k for the standard 3x3
     grid — full pre-image attack runs in milliseconds.
  3. **No attempt limit** — the OnTouchListener accepts any number of
     attempts without a lockout / exponential backoff.

This agent identifies classes that look like pattern-lock UI (custom
View with `OnTouchListener` + MotionEvent + a numeric coordinate
list), then audits the storage + comparison path inside the same
class. Findings are LOW/MEDIUM — the worst case (plaintext pattern
in SharedPreferences) is HIGH.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Pattern-lock UI signal: a view that handles MotionEvent + records
# touch coordinates into a list / array — the unmistakable shape of
# pattern-grid capture.
_TOUCH_LISTENER_RE = re.compile(
    r"(?:OnTouchListener|onTouch(?:Event)?\s*\(\s*MotionEvent)"
)
_GRID_ARRAY_RE = re.compile(
    r"\b(?:int|float|double|short|byte)\s*\[\s*\]\s*\w*"
    r"(?:Cell|Dot|Pattern|Point|Pos|Grid|Coord)\w*"
)

# Persistence patterns to inspect
_SHARED_PREFS_RE = re.compile(
    r"SharedPreferences|getSharedPreferences|edit\(\)\s*\.\s*putString"
)
_PLAINTEXT_PUT_RE = re.compile(
    r"\.putString\s*\(\s*[\"'](\w*(?:pattern|pin|passcode|unlock)\w*)[\"']"
    r"\s*,\s*(\w+)\s*\)",
    re.IGNORECASE,
)
# Hash without salt — single-arg .update(...) call
_WEAK_HASH_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']\s*\)",
    re.IGNORECASE,
)
# Attempt-limit signals (we only flag absence)
_ATTEMPT_LIMIT_RE = re.compile(
    r"\b(?:attempt|tries|fail(?:ure)?s?|lockout|cooldown|backoff)\w*",
    re.IGNORECASE,
)

_MAX_FILES = 2500


class PatternLockAgent(BaseAgent):
    """GESTURE_001: weakness audit for hand-rolled pattern-lock screens."""

    AGENT_ID = "GESTURE_001"
    VULN_CLASS = "Custom Pattern-Lock Weakness"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Step 1: Is this a pattern-lock UI class?
            if not (_TOUCH_LISTENER_RE.search(text) and _GRID_ARRAY_RE.search(text)):
                continue

            rel = str(path.relative_to(root))

            # Step 2: Plaintext-to-SharedPreferences
            for m in _PLAINTEXT_PUT_RE.finditer(text):
                key, var = m.group(1), m.group(2)
                findings.append(self._make_finding(
                    vuln_class="Pattern Lock Stored In Plaintext",
                    severity=Severity.HIGH,
                    confidence=0.80,
                    recommendation=(
                        "The pattern / passcode is written to "
                        f"SharedPreferences under key `{key}` as a "
                        "plaintext value (`{var}`). Anyone with adb "
                        "backup or root access reads it. Switch to "
                        "EncryptedSharedPreferences (androidx.security) "
                        "or store only a salted Argon2id hash of the "
                        "pattern, never the pattern itself."
                    ),
                    evidence={
                        "file": rel,
                        "key": key,
                        "stored_variable": var,
                    },
                ))

            # Step 3: Weak hash family
            for m in _WEAK_HASH_RE.finditer(text):
                algo = m.group(1).upper().replace("-", "")
                findings.append(self._make_finding(
                    vuln_class=f"Pattern Lock Hashed With {algo}",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    recommendation=(
                        f"{algo} is used in the pattern-comparison "
                        "path. With a ~389k pattern space, a full "
                        "rainbow table for any unsalted hash builds "
                        "in seconds. Use Argon2id with a per-install "
                        "random salt, stored alongside the hash in "
                        "EncryptedSharedPreferences."
                    ),
                    evidence={"file": rel, "algorithm": algo},
                ))

            # Step 4: No attempt-limit code anywhere in the class
            if not _ATTEMPT_LIMIT_RE.search(text):
                findings.append(self._make_finding(
                    vuln_class="Pattern Lock Without Attempt Limit",
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    recommendation=(
                        "The pattern-lock view has no obvious attempt-"
                        "limit / lockout logic. Brute force is ~389k "
                        "patterns; an attacker with the device "
                        "iterates the whole space. Add an exponential "
                        "backoff lockout, persisted across app restarts."
                    ),
                    evidence={"file": rel},
                ))

        return findings


__all__ = ["PatternLockAgent"]
