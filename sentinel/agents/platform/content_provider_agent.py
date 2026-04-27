"""P_004 — Content Provider IDOR Agent.

Detects exported Android Content Providers that lack authorization, are
vulnerable to SQL injection through the `selection` argument, or expose
arbitrary file contents through `openFile()`.

Why this matters: Content Providers are the Android equivalent of a database
server. When `android:exported="true"` is set without proper permission
guards, ANY other app on the device can call query(), update(), delete(),
insert(), or openFile() on that provider. Bounty programs pay $500-$3000
for exported provider IDOR and up to $8000 for confirmed SQL injection.

Detection pipeline:
1. Read exported_components from the manifest (parsed by Phase 1)
2. For each provider: check if it has a permission/readPermission/writePermission
3. Locate the provider's source class in decompiled output
4. Scan the class for risky patterns:
   - selection arg flowing into rawQuery() without parameterisation (SQLi)
   - openFile() that builds a path from URI segments without canonicalisation (path traversal)
   - query() that returns all rows without WHERE filtering (full table dump)
5. Emit one finding per identified weakness, with severity scaled by impact
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Regex patterns for risky code constructs in decompiled providers
# These are intentionally loose — JADX output is messy, and we want to flag
# anything suspicious for the verification phase to confirm later.

# raw SQL with selection variable interpolated (not parameterised)
_SQLI_PATTERNS = [
    # rawQuery(selection)  or  rawQuery("SELECT ... " + selection ...)
    re.compile(r"\.rawQuery\s*\([^)]*\bselection\b", re.IGNORECASE),
    # SQLiteQueryBuilder.appendWhere(selection)
    re.compile(r"appendWhere\s*\(\s*selection", re.IGNORECASE),
    # String concatenation: "WHERE id = " + selection or " + selection +
    re.compile(r'"\s*\+\s*selection\b', re.IGNORECASE),
    re.compile(r"\bselection\s*\+\s*\"", re.IGNORECASE),
]

# openFile() that doesn't canonicalise the path
_OPENFILE_RISKY = re.compile(
    r"openFile\s*\([^)]*\)\s*\{[^}]*?(getLastPathSegment|getPath|toString)",
    re.IGNORECASE | re.DOTALL,
)

# query() with no WHERE / selection enforcement (returns all rows)
_FULL_DUMP = re.compile(
    r"public\s+Cursor\s+query\s*\([^)]*\)\s*\{[^}]*?return\s+\w+\.query\s*\([^)]+null\s*,\s*null\s*,\s*null",
    re.IGNORECASE | re.DOTALL,
)

# Quick signal that the file is a ContentProvider implementation
_PROVIDER_INDICATORS = [
    "extends ContentProvider",
    "extends android.content.ContentProvider",
]


class ContentProviderIDORAgent(BaseAgent):
    """P_004: detects exposed Content Providers vulnerable to IDOR / SQLi / path traversal.

    Scope-aware: respects in_scope_packages from BountyScope.
    Conservative: emits a finding only when at least one risk indicator is found
    in the actual decompiled code (not just because the provider is exported).
    Exported but properly guarded providers produce no finding.
    """

    AGENT_ID = "P_004"
    VULN_CLASS = "Exposed Content Provider"
    PHASE = "static"

    async def is_applicable(self) -> bool:
        """P_004 applies whenever Phase 1 produced a manifest with exported components."""
        ctx = self._context
        if not ctx.manifest:
            logger.info("[P_004] No manifest — skipping")
            return False
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            logger.info("[P_004] No decompiled source — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        """Scan exported providers for missing permissions and risky implementations."""
        findings: list[Finding] = []
        ctx = self._context

        manifest = ctx.manifest or {}
        exported = manifest.get("exported_components", [])
        providers = [c for c in exported if c.get("type") == "provider"]

        if not providers:
            logger.info("[P_004] No exported Content Providers in manifest")
            return findings

        logger.info("[P_004] Found %d exported provider(s) — analysing each",
                    len(providers))

        for provider_info in providers:
            provider_name = provider_info.get("name", "")
            if not provider_name:
                continue

            # Locate the provider's decompiled .java file
            java_file = self._find_provider_source(ctx.decompiled_dir, provider_name)

            # Build a base finding even if we can't read source — exported with
            # no permission is itself a bug worth flagging, just at lower confidence
            permission = provider_info.get("permission") or ""
            read_permission = provider_info.get("readPermission") or ""
            write_permission = provider_info.get("writePermission") or ""
            has_any_guard = bool(permission or read_permission or write_permission)

            if java_file is None:
                # Source not found — probably the provider is in a library JAR
                # we couldn't decompile. Emit a Medium finding based on manifest only.
                findings.append(self._make_no_source_finding(
                    provider_name, has_any_guard, manifest.get("package", "?"),
                ))
                continue

            # Read source and look for risky patterns
            try:
                source = java_file.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                logger.warning("[P_004] Could not read %s", java_file)
                continue

            risks = self._analyse_source(source)

            findings.append(self._make_provider_finding(
                provider_name=provider_name,
                package=manifest.get("package", "?"),
                source_path=str(java_file.relative_to(ctx.decompiled_dir)),
                has_any_guard=has_any_guard,
                permission=permission,
                read_permission=read_permission,
                write_permission=write_permission,
                risks=risks,
            ))

        return findings

    # ---------- source location ----------

    def _find_provider_source(self, decompiled: Path, provider_name: str) -> Path | None:
        """Locate the .java file implementing this Content Provider.

        Provider names are fully qualified Java class names like
        `com.android.insecurebankv2.TrackUserContentProvider`. We translate
        that to a path: com/android/insecurebankv2/TrackUserContentProvider.java
        """
        if not provider_name:
            return None

        # Try the canonical path first
        path_parts = provider_name.split(".")
        canonical = decompiled.joinpath(*path_parts).with_suffix(".java")
        if canonical.exists():
            return canonical

        # JADX sometimes wraps classes in `sources/` subdirectory
        for prefix in ("sources", "src"):
            wrapped = decompiled / prefix / Path(*path_parts).with_suffix(".java")
            if wrapped.exists():
                return wrapped

        # Fallback: search by class name only (last segment), tolerant of
        # different package nesting that JADX might produce
        class_name = path_parts[-1] + ".java"
        matches = list(decompiled.rglob(class_name))
        if matches:
            return matches[0]

        return None

    # ---------- source analysis ----------

    def _analyse_source(self, source: str) -> dict[str, Any]:
        """Walk decompiled Java looking for risky patterns.

        Returns a dict describing what was found. The caller turns this into
        evidence for the finding.
        """
        is_provider = any(ind in source for ind in _PROVIDER_INDICATORS)

        sqli_matches: list[str] = []
        for pat in _SQLI_PATTERNS:
            sqli_matches.extend(pat.findall(source))

        openfile_match = _OPENFILE_RISKY.search(source)
        full_dump_match = _FULL_DUMP.search(source)

        return {
            "is_provider": is_provider,
            "sqli_indicators": len(sqli_matches),
            "sqli_samples": sqli_matches[:3],
            "openfile_risky": openfile_match is not None,
            "full_dump_risky": full_dump_match is not None,
        }

    # ---------- finding construction ----------

    def _make_provider_finding(
        self,
        provider_name: str,
        package: str,
        source_path: str,
        has_any_guard: bool,
        permission: str,
        read_permission: str,
        write_permission: str,
        risks: dict[str, Any],
    ) -> Finding:
        """Build a finding for a provider where we successfully analysed source."""

        # Severity scales with what we found
        if risks["sqli_indicators"] > 0 and not has_any_guard:
            severity = Severity.CRITICAL
            confidence = 0.90
            summary = "exported with no permission AND SQL injection patterns in source"
        elif risks["openfile_risky"] and not has_any_guard:
            severity = Severity.HIGH
            confidence = 0.85
            summary = "exported with no permission AND risky openFile() implementation"
        elif risks["full_dump_risky"] and not has_any_guard:
            severity = Severity.HIGH
            confidence = 0.85
            summary = "exported with no permission AND query() returns rows without filtering"
        elif not has_any_guard:
            severity = Severity.MEDIUM
            confidence = 0.75
            summary = "exported with no permission, but no specific exploit pattern detected"
        elif risks["sqli_indicators"] > 0:
            severity = Severity.HIGH
            confidence = 0.80
            summary = ("permission-guarded but SQL injection patterns present "
                       "— exploitable by any app holding the permission")
        else:
            severity = Severity.LOW
            confidence = 0.60
            summary = "exported but permission-guarded and no risky patterns detected"

        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            recommendation=self._build_recommendation(provider_name, has_any_guard, risks),
            evidence={
                "title": f"Exposed Content Provider: {provider_name}",
                "summary": summary,
                "package": package,
                "provider": provider_name,
                "source_file": source_path,
                "exported": True,
                "permission": permission or None,
                "read_permission": read_permission or None,
                "write_permission": write_permission or None,
                "has_any_guard": has_any_guard,
                "is_provider_class": risks["is_provider"],
                "sqli_indicators_found": risks["sqli_indicators"],
                "sqli_samples": risks["sqli_samples"],
                "openfile_risky": risks["openfile_risky"],
                "full_dump_risky": risks["full_dump_risky"],
                "vector": (
                    f"adb shell content query --uri content://"
                    f"{provider_name.lower()}/  "
                    f"# from any installed app, no permissions required"
                    if not has_any_guard
                    else f"adb shell content query --uri content://{provider_name.lower()}/  "
                    f"# requires holding {permission or read_permission}"
                ),
            },
        )

    def _make_no_source_finding(
        self, provider_name: str, has_any_guard: bool, package: str,
    ) -> Finding:
        """Manifest-only finding when we couldn't decompile the provider's class."""
        severity = Severity.MEDIUM if not has_any_guard else Severity.LOW
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.60,
            recommendation=self._build_recommendation(provider_name, has_any_guard, {}),
            evidence={
                "title": f"Exposed Content Provider (source unavailable): {provider_name}",
                "summary": ("provider declared as exported in manifest but its "
                            "decompiled source could not be located"),
                "package": package,
                "provider": provider_name,
                "exported": True,
                "has_any_guard": has_any_guard,
                "source_file": None,
                "note": "Manual review required — JADX could not decompile this class",
            },
        )

    def _build_recommendation(
        self, provider_name: str, has_any_guard: bool, risks: dict[str, Any],
    ) -> str:
        """Class-aware remediation guidance."""
        steps: list[str] = []

        if not has_any_guard:
            steps.append(
                f"Add `android:permission`, `android:readPermission`, or "
                f"`android:writePermission` to the <provider> declaration "
                f"for {provider_name} in AndroidManifest.xml. If the provider "
                f"is intended for internal use only, set `android:exported=\"false\"`."
            )

        if risks.get("sqli_indicators", 0) > 0:
            steps.append(
                "Replace string concatenation in rawQuery()/appendWhere() with "
                "parameterised queries. Pass the user-controlled `selection` and "
                "`selectionArgs` to SQLiteDatabase.query() rather than building "
                "SQL strings manually."
            )

        if risks.get("openfile_risky"):
            steps.append(
                "In openFile(), canonicalise the requested file path with "
                "File.getCanonicalPath() and verify it is contained within an "
                "expected directory before opening. Reject any path that escapes "
                "the intended sandbox."
            )

        if risks.get("full_dump_risky"):
            steps.append(
                "In query(), enforce a non-null selection that restricts results "
                "to the calling user's data. Consider using "
                "Binder.getCallingUid() to identify the caller and apply per-user "
                "row-level filtering."
            )

        if not steps:
            steps.append(
                "Audit this provider's implementation manually. While no specific "
                "exploit pattern was detected, exported providers are a high-value "
                "target and warrant a careful security review."
            )

        return " ".join(steps)
