"""LEARN_001 — App-specific learning profile store.

Goal: a repeat scan of the same app should be *better* than the first
scan, not just faster. We persist three classes of signal per APK
(keyed by `apk_sha256`, fall back to manifest `package`):

  1. **Custom-obfuscation fingerprints.** When the profiler detects an
     unusual obfuscation tier (e.g. a tier above ProGuard with custom
     class-renaming patterns), we record the unique short-name
     distribution. Next scan: agents that fingerprint obfuscation can
     short-circuit re-derivation.

  2. **Triage outcomes.** Findings that a human marked TRUE_POSITIVE
     or FALSE_POSITIVE are remembered by their fingerprint (the same
     fingerprint already used by `sentinel diff`). On the next scan,
     findings matching a prior FP fingerprint are auto-marked
     NEEDS_VERIFICATION with the prior decision attached, sparing the
     reviewer from re-triaging.

  3. **Confidence priors.** Per `(agent_id, vuln_class)` running
     average of "the human accepted the finding." Used by
     FEEDBACK_001 to bump or trim future scan confidences.

Storage layout:

  data/learning/<apk_sha256>.json    schema-versioned JSON; no DB
                                      dependency. Round-trip via
                                      Pydantic-free dict + json.

The dataclass `AppLearningProfile` is the in-memory view; the store
is a thin pickle-free file backend. SaaS / multi-tenant deployments
prefix the path with `<tenant_id>/`.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1


@dataclass
class AppLearningProfile:
    """Everything we've learned about a specific APK."""

    apk_sha256: str
    package: str = ""
    schema_version: int = _SCHEMA_VERSION
    scans_count: int = 0
    obfuscation_fingerprint: dict[str, Any] = field(default_factory=dict)
    # fingerprint -> {"triage": "...", "vuln_class": "...", "seen_at": "..."}
    triage_decisions: dict[str, dict[str, Any]] = field(default_factory=dict)
    # (agent_id, vuln_class) -> {"n": int, "tp": int, "fp": int}
    # Stored as "agent_id|vuln_class" string keys so we can JSON-round-trip.
    confidence_priors: dict[str, dict[str, int]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    # ---------- mutators ----------

    def record_triage(
        self, fingerprint: str, vuln_class: str, agent_id: str,
        triage: str,
    ) -> None:
        """Record a single human-triage decision."""
        self.triage_decisions[fingerprint] = {
            "triage": triage,
            "vuln_class": vuln_class,
            "agent_id": agent_id,
        }
        key = f"{agent_id}|{vuln_class}"
        prior = self.confidence_priors.setdefault(
            key, {"n": 0, "tp": 0, "fp": 0},
        )
        prior["n"] = prior["n"] + 1
        if triage == "True Positive":
            prior["tp"] = prior["tp"] + 1
        elif triage == "False Positive":
            prior["fp"] = prior["fp"] + 1

    def prior_accept_rate(self, agent_id: str, vuln_class: str) -> float | None:
        """Return historical accept rate (TP / N) or None when unknown."""
        key = f"{agent_id}|{vuln_class}"
        prior = self.confidence_priors.get(key)
        if not prior or prior["n"] < 3:
            return None  # Not enough samples to trust
        return prior["tp"] / prior["n"]

    def is_known_false_positive(self, fingerprint: str) -> bool:
        d = self.triage_decisions.get(fingerprint)
        return bool(d and d.get("triage") == "False Positive")

    # ---------- serialisation ----------

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk_sha256": self.apk_sha256,
            "package": self.package,
            "schema_version": self.schema_version,
            "scans_count": self.scans_count,
            "obfuscation_fingerprint": self.obfuscation_fingerprint,
            "triage_decisions": self.triage_decisions,
            "confidence_priors": self.confidence_priors,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppLearningProfile:
        return cls(
            apk_sha256=data.get("apk_sha256", ""),
            package=data.get("package", ""),
            schema_version=int(data.get("schema_version", _SCHEMA_VERSION)),
            scans_count=int(data.get("scans_count", 0)),
            obfuscation_fingerprint=data.get("obfuscation_fingerprint") or {},
            triage_decisions=data.get("triage_decisions") or {},
            confidence_priors=data.get("confidence_priors") or {},
            notes=data.get("notes") or [],
        )


@dataclass
class AppProfileStore:
    """File-backed store under `data_dir/learning/<apk_sha256>.json`."""

    root: Path

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    # ---------- I/O ----------

    def load(self, apk_sha256: str) -> AppLearningProfile:
        if not apk_sha256:
            return AppLearningProfile(apk_sha256="")
        path = self._path_for(apk_sha256)
        if not path.is_file():
            return AppLearningProfile(apk_sha256=apk_sha256)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Failed to load profile %s: %s", apk_sha256, e)
            return AppLearningProfile(apk_sha256=apk_sha256)
        return AppLearningProfile.from_dict(data)

    def save(self, profile: AppLearningProfile) -> None:
        if not profile.apk_sha256:
            return
        path = self._path_for(profile.apk_sha256)
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(
                json.dumps(profile.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            tmp.replace(path)
        except OSError as e:
            logger.warning("Failed to save profile %s: %s", profile.apk_sha256, e)

    # ---------- lifecycle helpers ----------

    def record_scan_start(self, apk_sha256: str, package: str = "") -> AppLearningProfile:
        """Atomic 'increment scan count + load profile' for the orchestrator."""
        profile = self.load(apk_sha256)
        if not profile.package and package:
            profile.package = package
        profile.scans_count += 1
        self.save(profile)
        return profile

    def merge_triage(
        self, apk_sha256: str,
        decisions: list[dict[str, str]],
    ) -> None:
        """Bulk triage import for end-of-scan persistence."""
        if not decisions:
            return
        profile = self.load(apk_sha256)
        for d in decisions:
            fingerprint = d.get("fingerprint")
            if not fingerprint:
                continue
            profile.record_triage(
                fingerprint=fingerprint,
                vuln_class=d.get("vuln_class", ""),
                agent_id=d.get("agent_id", ""),
                triage=d.get("triage", ""),
            )
        self.save(profile)

    # ---------- helpers ----------

    def _path_for(self, apk_sha256: str) -> Path:
        # First two hex chars as fan-out dir to avoid 100k-file directories
        sub = self.root / apk_sha256[:2]
        sub.mkdir(parents=True, exist_ok=True)
        return sub / f"{apk_sha256}.json"


# Default store rooted at ./data/learning — caller overrides via constructor.
default_store = AppProfileStore(root=Path("./data/learning"))


__all__ = ["AppLearningProfile", "AppProfileStore", "default_store"]
