"""Rule-based deterministic remediation patches.

Each rule is a `(matcher, builder)` pair:
  * `matcher(finding) -> bool` decides whether the rule applies.
  * `builder(finding) -> RulePatchResult` produces the unified diff.

Rules run in order; the first matching rule wins. Callers should
treat the output as a *suggestion* — the diff is generated against
decompiled output and will not literally `patch -p1`; a human must
port the change to the original source. This is the same disclaimer
the LLM module carries.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

from sentinel.core.finding import Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RulePatchResult:
    """A single rule's output."""

    rule_id: str
    confidence: float            # 0.0–1.0
    diff_body: str               # unified diff hunks (no file header)
    file_path: str               # target file relative to repo root
    rationale: str
    needs_review: bool = True    # always True — diffs are decompiled


@dataclass
class RuleBasedPatcher:
    """Stateless ordered ruleset for common Android-SAST findings."""

    _rules: list[tuple[Callable[[Finding], bool],
                        Callable[[Finding], RulePatchResult | None]]] = field(
        default_factory=list
    )

    def register(
        self,
        match: Callable[[Finding], bool],
        build: Callable[[Finding], RulePatchResult | None],
    ) -> None:
        self._rules.append((match, build))

    def patch(self, finding: Finding) -> RulePatchResult | None:
        for matcher, builder in self._rules:
            try:
                if not matcher(finding):
                    continue
            except Exception:  # noqa: BLE001
                logger.exception("Rule matcher crashed; skipping")
                continue
            try:
                result = builder(finding)
            except Exception:  # noqa: BLE001
                logger.exception("Rule builder crashed; skipping")
                continue
            if result is not None:
                return result
        return None


# ============================================================
# Rule library
# ============================================================

def _evidence(finding: Finding, *keys: str) -> str:
    """Helper: first non-empty evidence value across keys."""
    ev = finding.evidence or {}
    for k in keys:
        v = ev.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _diff_block(old: str, new: str) -> str:
    """Tiny unified-diff hunk for a single-line swap inside a snippet."""
    old_lines = old.splitlines() or [old]
    new_lines = new.splitlines() or [new]
    lines = [f"@@ -1,{len(old_lines)} +1,{len(new_lines)} @@"]
    for ol in old_lines:
        lines.append(f"-{ol}")
    for nl in new_lines:
        lines.append(f"+{nl}")
    return "\n".join(lines) + "\n"


# ---- Weak crypto: DES / 3DES → AES-GCM ----

_DES_RE = re.compile(r"\b(DES|DESede|TripleDES|3DES)\b")
_MD5_RE = re.compile(r'["\']MD5["\']')


def _match_weak_crypto(f: Finding) -> bool:
    v = f.vuln_class.lower()
    if "weak crypto" not in v and "weak hash" not in v:
        return False
    snippet = _evidence(f, "snippet", "context", "value")
    return bool(_DES_RE.search(snippet) or _MD5_RE.search(snippet))


def _build_weak_crypto(f: Finding) -> RulePatchResult | None:
    snippet = _evidence(f, "snippet", "context", "value")
    file_path = _evidence(f, "file", "path")
    if not snippet:
        return None
    new = _DES_RE.sub("AES", snippet)
    new = _MD5_RE.sub('"SHA-256"', new)
    if new == snippet:
        return None
    return RulePatchResult(
        rule_id="REM_WEAK_CRYPTO",
        confidence=0.80,
        diff_body=_diff_block(snippet, new),
        file_path=file_path or "(unknown)",
        rationale=(
            "DES/3DES/MD5 are broken primitives. Suggested swap to AES "
            "(use AES/GCM/NoPadding with a SecureRandom IV) and "
            "SHA-256. Verify call sites: key length and IV handling "
            "must change too."
        ),
    )


# ---- Missing PendingIntent FLAG_IMMUTABLE ----

_PI_RE = re.compile(
    r"PendingIntent\s*\.\s*(getActivity|getActivities|getBroadcast|getService)\s*\(([^)]*)\)"
)


def _match_pending_intent(f: Finding) -> bool:
    return "mutable" in f.vuln_class.lower() and "pendingintent" in f.vuln_class.lower()


def _build_pending_intent(f: Finding) -> RulePatchResult | None:
    snippet = _evidence(f, "snippet", "context")
    file_path = _evidence(f, "file", "path")
    if not snippet:
        return None
    m = _PI_RE.search(snippet)
    if not m:
        return None
    method, args = m.group(1), m.group(2)
    parts = [a.strip() for a in args.split(",")]
    if len(parts) < 4:
        return None
    # Replace the flags argument (index 3) with FLAG_IMMUTABLE-OR'd form
    flags_arg = parts[3]
    if "FLAG_IMMUTABLE" in flags_arg:
        return None  # already fixed
    new_flags = f"{flags_arg} | PendingIntent.FLAG_IMMUTABLE"
    parts[3] = new_flags
    new_call = f"PendingIntent.{method}({', '.join(parts)})"
    new_snippet = snippet.replace(m.group(0), new_call)
    return RulePatchResult(
        rule_id="REM_PENDING_INTENT_IMMUTABLE",
        confidence=0.90,
        diff_body=_diff_block(snippet, new_snippet),
        file_path=file_path or "(unknown)",
        rationale=(
            "Android 12+ requires PendingIntent.FLAG_IMMUTABLE on every "
            "construction. Without it the system rejects the intent at "
            "runtime. Adding FLAG_IMMUTABLE is safe in the common case "
            "(reading from the wrapped intent only); audit if you rely "
            "on filling the intent later via FillInIntent."
        ),
    )


# ---- Cleartext URL: http:// → https:// ----

_HTTP_URL_RE = re.compile(r'http://([^\s"\'<>)]+)')


def _match_cleartext(f: Finding) -> bool:
    return "cleartext" in f.vuln_class.lower()


def _build_cleartext(f: Finding) -> RulePatchResult | None:
    snippet = _evidence(f, "snippet", "context", "value", "url")
    file_path = _evidence(f, "file", "path")
    if not snippet or "http://" not in snippet:
        return None
    new = _HTTP_URL_RE.sub(r"https://\1", snippet)
    if new == snippet:
        return None
    return RulePatchResult(
        rule_id="REM_HTTPS_UPGRADE",
        confidence=0.75,
        diff_body=_diff_block(snippet, new),
        file_path=file_path or "(unknown)",
        rationale=(
            "Cleartext URL replaced with TLS-protected equivalent. "
            "Confirm the destination server accepts HTTPS; if not, the "
            "upgrade itself becomes the bug to fix server-side."
        ),
    )


# ---- Manifest android:debuggable="true" → strip ----

_DEBUGGABLE_RE = re.compile(r'\s*android:debuggable\s*=\s*"(true|1)"')


def _match_debuggable(f: Finding) -> bool:
    return "debuggable" in f.vuln_class.lower()


def _build_debuggable(f: Finding) -> RulePatchResult | None:
    snippet = _evidence(f, "snippet", "context")
    file_path = _evidence(f, "file", "path") or "AndroidManifest.xml"
    if not snippet or not _DEBUGGABLE_RE.search(snippet):
        return None
    new = _DEBUGGABLE_RE.sub("", snippet)
    return RulePatchResult(
        rule_id="REM_STRIP_DEBUGGABLE",
        confidence=0.95,
        diff_body=_diff_block(snippet, new),
        file_path=file_path,
        rationale=(
            "android:debuggable=\"true\" in a release manifest allows "
            "any app on the device to attach jdb to the process. "
            "Remove the attribute (the platform default is false)."
        ),
    )


# ---- Manifest android:allowBackup="true" → false ----

_BACKUP_RE = re.compile(r'(android:allowBackup\s*=\s*)"true"')


def _match_backup(f: Finding) -> bool:
    return "backup" in f.vuln_class.lower() and "allow" in f.vuln_class.lower()


def _build_backup(f: Finding) -> RulePatchResult | None:
    snippet = _evidence(f, "snippet", "context")
    file_path = _evidence(f, "file", "path") or "AndroidManifest.xml"
    if not snippet or not _BACKUP_RE.search(snippet):
        return None
    new = _BACKUP_RE.sub(r'\1"false"', snippet)
    return RulePatchResult(
        rule_id="REM_DISABLE_BACKUP",
        confidence=0.85,
        diff_body=_diff_block(snippet, new),
        file_path=file_path,
        rationale=(
            "allowBackup=\"true\" exposes app data to anyone with adb "
            "access. Suggested disable; if the app uses Auto Backup, "
            "use a fullBackupContent rules file to exclude sensitive "
            "files instead of disabling entirely."
        ),
    )


# ---- Default patcher with all rules registered ----

default_patcher = RuleBasedPatcher()
default_patcher.register(_match_weak_crypto, _build_weak_crypto)
default_patcher.register(_match_pending_intent, _build_pending_intent)
default_patcher.register(_match_cleartext, _build_cleartext)
default_patcher.register(_match_debuggable, _build_debuggable)
default_patcher.register(_match_backup, _build_backup)


def patch(finding: Finding) -> RulePatchResult | None:
    """Module-level convenience using the default patcher."""
    return default_patcher.patch(finding)


__all__ = [
    "RuleBasedPatcher",
    "RulePatchResult",
    "default_patcher",
    "patch",
]
