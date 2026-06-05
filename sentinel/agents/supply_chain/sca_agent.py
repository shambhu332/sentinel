"""SCA_001 — Supply Chain Vulnerability Scanner.

Detects third-party Java/Android libraries embedded in the APK and
cross-references their versions against an offline OSV.dev Maven CVE
snapshot built by scripts/fetch_osv_db.py.

Detection runs in three tiers, highest confidence first. Each tier
attempts every coordinate independently; the first tier to identify a
coordinate wins and lower tiers are not consulted for that one.

  1. META-INF/maven/<g>/<a>/pom.properties — every Maven-built
     dependency drops a properties file with groupId, artifactId, and
     version. Authoritative when present.            Confidence 0.95.
  2. Version-marker strings — well-known libraries embed their version
     as a string constant (OkHttp's "okhttp/3.x.y", Retrofit/Gson/etc).
     A small marker table picks them out of decompiled Java + the
     Androguard string table.                         Confidence 0.80.
  3. Class-path presence — if a library's package path appears in the
     loaded DEX classes but neither tier 1 nor tier 2 identified a
     version, emit a LOW-confidence finding with version "UNKNOWN" so
     the user knows the library is present but the version (and thus
     CVE applicability) could not be determined.    Confidence 0.40.

Each detected library is queried against the OSV SQLite DB. A finding
is emitted only when the version falls inside an affected semver range
AND below the recorded `fixed_version` (proper semver match via the
`packaging` library — not lexicographic compare). Tier-3 unknowns
emit one finding per matching CVE since we can't prove the install is
patched.

Failure modes:
  * Missing DB → warning, return [] (does NOT crash the scan).
  * Zero libraries detected → info, return [].
  * Malformed pom.properties → skip that one file, continue.
  * Corrupt APK zip → warning, return [].
  * `packaging` library unavailable → is_applicable() returns False.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from packaging.version import InvalidVersion, Version
    _HAS_PACKAGING = True
except ImportError:  # pragma: no cover — dep is declared in pyproject.toml
    _HAS_PACKAGING = False

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ---------- Constants ----------

_DEFAULT_DB_PATH = Path("data/osv_maven.sqlite")

# Cap to keep tier-2 file scanning bounded on huge APKs (consistent with
# the convention in other SAST agents — C_007, A_004, etc).
_MAX_FILES_TO_SCAN = 3000

# Version-marker patterns — (groupId, artifactId, regex with version
# capture in group(1)). Conservative on purpose: only match formats the
# library is documented to embed, so a coincidental "okhttp/foo" in
# unrelated code doesn't get treated as a real version.
_VERSION_MARKERS: list[tuple[str, str, re.Pattern[str]]] = [
    ("com.squareup.okhttp3", "okhttp",
     re.compile(r"okhttp/([0-9]+\.[0-9]+\.[0-9]+)")),
    ("com.squareup.okhttp", "okhttp",
     re.compile(r"okhttp/([0-9]+\.[0-9]+\.[0-9]+)")),
    ("com.google.code.gson", "gson",
     re.compile(
         r"(?:gson|GSON)[\s_/-]+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
     )),
    ("com.squareup.retrofit2", "retrofit",
     re.compile(r"retrofit[/\s_-]+([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)),
    ("com.google.firebase", "firebase-core",
     re.compile(
         r"firebase[_-]?(?:core|common)[/\s_-]+([0-9]+\.[0-9]+\.[0-9]+)",
         re.IGNORECASE,
     )),
    ("com.bumptech.glide", "glide",
     re.compile(r"glide[/\s_-]+([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)),
]

# Class-path fingerprints for tier 3. The trailing "/" is intentional:
# we look for the prefix appearing as a directory-style match in the
# class list so e.g. "com/squareup/okhttp3/foo" matches but a chance
# string "okhttp3foo" does not.
_CLASSPATH_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("com.squareup.okhttp3", "okhttp", "com/squareup/okhttp3/"),
    ("com.squareup.okhttp", "okhttp", "com/squareup/okhttp/"),
    ("com.google.code.gson", "gson", "com/google/gson/"),
    ("com.squareup.retrofit2", "retrofit", "retrofit2/"),
    ("com.google.firebase", "firebase-core", "com/google/firebase/"),
    ("com.bumptech.glide", "glide", "com/bumptech/glide/"),
    ("com.squareup.picasso", "picasso", "com/squareup/picasso/"),
    ("org.apache.commons", "commons-lang3", "org/apache/commons/lang3/"),
]


# ---------- Helpers (module-level so tests can import) ----------

def _safe_version(s: str | None) -> Version | None:
    if not _HAS_PACKAGING or s is None:
        return None
    try:
        return Version(str(s))
    except (InvalidVersion, TypeError):
        return None


def _version_in_any_range(version: str, ranges: list[dict]) -> bool:
    """True iff `version` falls inside any OSV `range`.

    A range is a sequence of events ({"introduced": v} | {"fixed": v} |
    {"last_affected": v} | {"limit": v}). An advisory is "in" the
    half-open interval [introduced, fixed) for each fixed event, or
    [introduced, last_affected] when only last_affected is given, or
    [introduced, ∞) when neither bound appears.
    """
    if not _HAS_PACKAGING:
        return False
    try:
        v = Version(str(version))
    except (InvalidVersion, TypeError):
        return False

    for r in ranges or []:
        intro_v: Version | None = None
        fixed_v: Version | None = None
        last_aff_v: Version | None = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                intro_v = _safe_version(ev["introduced"]) or Version("0")
            elif "fixed" in ev:
                fixed_v = _safe_version(ev["fixed"])
            elif "last_affected" in ev:
                last_aff_v = _safe_version(ev["last_affected"])

        if intro_v is None:
            intro_v = Version("0")
        if v < intro_v:
            continue
        if fixed_v is not None and v >= fixed_v:
            continue
        if last_aff_v is not None and v > last_aff_v:
            continue
        return True
    return False


def _severity_for_cvss(cvss: float) -> Severity:
    """CVSS base score → SENTINEL Severity bucket."""
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass
class DetectedLibrary:
    """A single (coordinate, version, detection-source) triple."""
    group_id: str
    artifact_id: str
    version: str  # "UNKNOWN" for tier-3 fingerprint-only hits
    source: str   # "pom.properties" | "version-marker" | "classpath"
    confidence: float
    evidence_paths: list[str] = field(default_factory=list)

    @property
    def coordinate(self) -> str:
        return f"{self.group_id}:{self.artifact_id}".lower()


# ---------- Agent ----------

class SCAAgent(BaseAgent):
    """SCA_001: third-party library CVE scanner."""

    AGENT_ID = "SCA_001"
    VULN_CLASS = "VULNERABLE_DEPENDENCY"
    PHASE = "Phase 2"
    CATEGORY = "SUPPLY_CHAIN"

    async def is_applicable(self) -> bool:
        if not _HAS_PACKAGING:
            self._log.warning(
                "[SCA_001] `packaging` library not installed — semver "
                "matching unavailable; skipping",
            )
            return False
        if not self._context.apk_path.exists():
            self._log.info("[SCA_001] APK path missing — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        db_path = self._resolve_db_path()
        if not db_path.exists():
            self._log.warning(
                "[SCA_001] OSV CVE database not found at %s. Run "
                "`poetry run python scripts/fetch_osv_db.py` to build it. "
                "Supply-chain scan skipped.",
                db_path,
            )
            return []

        libs = self._extract_libraries()
        if not libs:
            self._log.info("[SCA_001] No third-party libraries detected")
            return []
        self._log.info(
            "[SCA_001] %d candidate libraries to check against OSV DB",
            len(libs),
        )

        return self._match_cves(libs, db_path)

    # ---------- DB path ----------

    def _resolve_db_path(self) -> Path:
        configured: str | None = None
        if isinstance(self._config, dict):
            configured = self._config.get("osv_db_path")
        envvar = os.environ.get("SENTINEL_OSV_DB")
        return Path(configured or envvar or _DEFAULT_DB_PATH)

    # ---------- Library extraction (tiers) ----------

    def _extract_libraries(self) -> list[DetectedLibrary]:
        """Run tiers 1 → 3, dedupe by coordinate (higher tier wins)."""
        results: dict[str, DetectedLibrary] = {}
        for lib in self._extract_pom_properties():
            results[lib.coordinate] = lib
        for lib in self._extract_version_markers():
            results.setdefault(lib.coordinate, lib)
        for lib in self._extract_classpath_presence():
            results.setdefault(lib.coordinate, lib)
        return list(results.values())

    # Tier 1 ----------

    def _extract_pom_properties(self) -> Iterable[DetectedLibrary]:
        try:
            with zipfile.ZipFile(self._context.apk_path) as z:
                names = [
                    n for n in z.namelist()
                    if n.startswith("META-INF/maven/")
                    and n.endswith("/pom.properties")
                ]
                for name in names:
                    try:
                        raw = z.read(name).decode(
                            "utf-8", errors="replace",
                        )
                    except (KeyError, OSError) as e:
                        self._log.debug(
                            "[SCA_001] Cannot read %s: %s", name, e,
                        )
                        continue
                    props = self._parse_properties(raw)
                    gid = (props.get("groupId") or "").strip()
                    aid = (props.get("artifactId") or "").strip()
                    ver = (props.get("version") or "").strip()
                    if not (gid and aid and ver):
                        self._log.debug(
                            "[SCA_001] Malformed pom.properties %s; "
                            "skipping (groupId=%r artifactId=%r "
                            "version=%r)",
                            name, gid, aid, ver,
                        )
                        continue
                    yield DetectedLibrary(
                        group_id=gid,
                        artifact_id=aid,
                        version=ver,
                        source="pom.properties",
                        confidence=0.95,
                        evidence_paths=[name],
                    )
        except (zipfile.BadZipFile, FileNotFoundError, OSError) as e:
            self._log.warning(
                "[SCA_001] APK zip access failed: %s", e,
            )

    @staticmethod
    def _parse_properties(text: str) -> dict[str, str]:
        """Minimal Java .properties parser — key=value, # / ! comments.

        We do NOT implement line-continuations or full unicode escape
        decoding; pom.properties files are simple key=value (Maven
        writes them this way deterministically), so the simple parser
        is sufficient and harder to crash.
        """
        out: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            if "=" in line:
                sep = "="
            elif ":" in line:
                sep = ":"
            else:
                continue
            k, _, v = line.partition(sep)
            out[k.strip()] = v.strip()
        return out

    # Tier 2 ----------

    def _extract_version_markers(self) -> Iterable[DetectedLibrary]:
        text_sources: list[tuple[str, str]] = []
        ctx = self._context
        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            scanned = 0
            for path in ctx.decompiled_dir.rglob("*.java"):
                if not path.is_file():
                    continue
                scanned += 1
                if scanned > _MAX_FILES_TO_SCAN:
                    self._log.warning(
                        "[SCA_001] tier-2: stopped after %d files",
                        _MAX_FILES_TO_SCAN,
                    )
                    break
                try:
                    text_sources.append((
                        str(path.relative_to(ctx.decompiled_dir)),
                        path.read_text(
                            encoding="utf-8", errors="replace",
                        ),
                    ))
                except (OSError, UnicodeDecodeError):
                    continue
        if ctx.has_androguard():
            try:
                strings = ctx.sources["androguard"].get_all_strings()
                text_sources.append((
                    "(androguard strings)", "\n".join(strings),
                ))
            except Exception as e:  # noqa: BLE001
                self._log.debug(
                    "[SCA_001] Androguard string scan failed: %s", e,
                )

        seen: set[str] = set()
        for src_path, body in text_sources:
            for gid, aid, pattern in _VERSION_MARKERS:
                key = f"{gid}:{aid}"
                if key in seen:
                    continue
                m = pattern.search(body)
                if not m:
                    continue
                seen.add(key)
                yield DetectedLibrary(
                    group_id=gid,
                    artifact_id=aid,
                    version=m.group(1),
                    source="version-marker",
                    confidence=0.80,
                    evidence_paths=[src_path],
                )

    # Tier 3 ----------

    def _extract_classpath_presence(self) -> Iterable[DetectedLibrary]:
        ctx = self._context
        seen: set[str] = set()

        if ctx.has_androguard():
            try:
                # Androguard returns class names as strings of the form
                # "Lcom/foo/Bar;". Normalise to "com/foo/Bar/" so a
                # prefix-startswith check matches a package path.
                classes = ctx.sources["androguard"].get_all_classes()
                paths: list[str] = []
                for raw in classes:
                    name = raw
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    if not isinstance(name, str):
                        # Fall back to a .name attribute for older
                        # androguard versions that returned objects.
                        name = (
                            getattr(raw, "name", "") or ""
                        )
                        if isinstance(name, bytes):
                            name = name.decode(
                                "utf-8", errors="replace",
                            )
                    if not isinstance(name, str) or not name:
                        continue
                    if name.startswith("L"):
                        name = name[1:]
                    if name.endswith(";"):
                        name = name[:-1]
                    paths.append(name)
                joined = "\n".join(paths)
                for gid, aid, prefix in _CLASSPATH_FINGERPRINTS:
                    key = f"{gid}:{aid}"
                    if key in seen:
                        continue
                    # Match either at a line start or as a substring; the
                    # \n-joined haystack ensures the prefix only matches
                    # at directory boundaries.
                    if (
                        joined.startswith(prefix)
                        or ("\n" + prefix) in joined
                    ):
                        seen.add(key)
                        yield DetectedLibrary(
                            group_id=gid,
                            artifact_id=aid,
                            version="UNKNOWN",
                            source="classpath",
                            confidence=0.40,
                            evidence_paths=[
                                f"DEX class prefix: {prefix}",
                            ],
                        )
            except Exception as e:  # noqa: BLE001
                self._log.debug(
                    "[SCA_001] Androguard class scan failed: %s", e,
                )

        if ctx.decompiled_dir and ctx.decompiled_dir.exists():
            for gid, aid, prefix in _CLASSPATH_FINGERPRINTS:
                key = f"{gid}:{aid}"
                if key in seen:
                    continue
                candidate = ctx.decompiled_dir / prefix.rstrip("/")
                if candidate.exists():
                    seen.add(key)
                    yield DetectedLibrary(
                        group_id=gid,
                        artifact_id=aid,
                        version="UNKNOWN",
                        source="classpath",
                        confidence=0.40,
                        evidence_paths=[
                            f"decompiled dir: {prefix}",
                        ],
                    )

    # ---------- CVE matching ----------

    def _match_cves(
        self,
        libs: list[DetectedLibrary],
        db_path: Path,
    ) -> list[Finding]:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        except sqlite3.Error as e:
            self._log.warning("[SCA_001] Cannot open OSV DB: %s", e)
            return []

        findings: list[Finding] = []
        try:
            for lib in libs:
                rows = conn.execute(
                    "SELECT vuln_id, cvss, summary, affected_ranges, "
                    "fixed_version FROM vulns WHERE group_artifact = ?",
                    (lib.coordinate,),
                ).fetchall()
                for vuln_id, cvss, summary, affected_json, fixed in rows:
                    try:
                        ranges = json.loads(affected_json)
                    except (json.JSONDecodeError, TypeError):
                        self._log.debug(
                            "[SCA_001] Malformed affected_ranges for %s/%s",
                            lib.coordinate, vuln_id,
                        )
                        continue
                    if lib.version != "UNKNOWN":
                        if not _version_in_any_range(lib.version, ranges):
                            continue
                    findings.append(self._build_finding(
                        lib, vuln_id, float(cvss),
                        summary or "", fixed,
                    ))
        finally:
            conn.close()

        if findings:
            self._log.info(
                "[SCA_001] %d vulnerable dependencies detected",
                len(findings),
            )
        return findings

    def _build_finding(
        self,
        lib: DetectedLibrary,
        vuln_id: str,
        cvss: float,
        summary: str,
        fixed: str | None,
    ) -> Finding:
        severity = _severity_for_cvss(cvss)
        coord = f"{lib.group_id}:{lib.artifact_id}"

        if fixed:
            recommendation = (
                f"Upgrade {coord} to {fixed} or later. Tracked as "
                f"{vuln_id} (CVSS {cvss:.1f})."
            )
        else:
            recommendation = (
                f"Upgrade {coord} away from {lib.version}. No fixed "
                f"version recorded in OSV — check the upstream "
                f"advisory for {vuln_id}."
            )

        evidence: dict[str, Any] = {
            "title": f"{coord} {lib.version} → {vuln_id}",
            "library": coord,
            "version": lib.version,
            "cve": vuln_id,
            "cvss": round(cvss, 1),
            "osv_id": vuln_id,
            "fixed_version": fixed or "unknown",
            "detection_method": lib.source,
            "evidence_paths": lib.evidence_paths[:10],
            "summary": (summary or "")[:500],
            "vector": (
                f"The application bundles {coord} {lib.version}, which "
                f"contains a publicly disclosed vulnerability ({vuln_id}). "
                f"An attacker who can reach the affected code path may be "
                f"able to exploit the issue without modifying the app."
            ),
        }
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=lib.confidence,
            recommendation=recommendation,
            evidence=evidence,
            owasp="M11: Outdated Components",
            masvs="MSTG-CODE-5",
        )
