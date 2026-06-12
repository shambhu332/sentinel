"""Compliance citation mapper — agent_id → list[Citation].

Reads the curated YAML at `sentinel/compliance/mappings.yaml`. The
file is parsed once at import time of `default_mapper`; callers can
construct their own `ComplianceMapper(path=...)` for tests.

Citation shape is deliberately loose (`framework` + `field` + `note`)
so the YAML can carry "Art. 32", "164.312", "Requirement 3.4" without
forcing a discriminated union per framework. Renderers format the
display string.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from sentinel.core.finding import Finding

logger = logging.getLogger(__name__)

_DEFAULT_YAML = Path(__file__).parent / "mappings.yaml"


@dataclass(frozen=True)
class Citation:
    """A single regulatory reference attached to a finding."""

    framework: str
    reference: str            # e.g. "Art. 32(1)(a)", "164.312(a)", "3.4"
    note: str = ""

    def render(self) -> str:
        base = f"{self.framework} {self.reference}"
        return f"{base} — {self.note}" if self.note else base


class ComplianceMapper:
    """Apply the YAML mapping table to Finding objects."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_YAML
        self._exact: dict[str, list[Citation]] = {}
        self._glob: list[tuple[str, list[Citation]]] = []
        self._load()

    # ---------- loading ----------

    def _load(self) -> None:
        if not self._path.is_file():
            logger.warning(
                "Compliance mappings not found at %s — citations disabled",
                self._path,
            )
            return
        try:
            import yaml  # pyyaml is already a project dep
        except ImportError:
            logger.warning("PyYAML missing — compliance mapper disabled")
            return
        try:
            data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            logger.error("Compliance YAML parse failed: %s", e)
            return

        for key, body in data.items():
            cites = list(self._parse_citations(body))
            if not cites:
                continue
            if isinstance(key, str) and key.endswith("*"):
                self._glob.append((key[:-1], cites))
            else:
                self._exact[str(key)] = cites

    @staticmethod
    def _parse_citations(body: Any) -> Iterable[Citation]:
        if not isinstance(body, dict):
            return []
        raw = body.get("citations") or []
        out: list[Citation] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            framework = str(entry.get("framework", "")).strip()
            if not framework:
                continue
            # Accept article / requirement / rule / section keys
            ref = ""
            for k in ("article", "requirement", "rule", "section", "reference"):
                v = entry.get(k)
                if v:
                    ref = str(v)
                    break
            note = str(entry.get("note", "")).strip()
            out.append(Citation(framework=framework, reference=ref, note=note))
        return out

    # ---------- query ----------

    def cite(self, finding: Finding) -> list[Citation]:
        """Return citations attached to this finding, or empty list."""
        cites = list(self._exact.get(finding.agent_id, ()))
        for prefix, group in self._glob:
            if finding.agent_id.startswith(prefix):
                cites.extend(group)
        return cites

    def cite_by_agent_id(self, agent_id: str) -> list[Citation]:
        """Convenience for renderers that don't have a Finding handy."""
        cites = list(self._exact.get(agent_id, ()))
        for prefix, group in self._glob:
            if agent_id.startswith(prefix):
                cites.extend(group)
        return cites


# Module-level default — loaded once.
default_mapper = ComplianceMapper()


def cite(finding: Finding) -> list[Citation]:
    """Module-level convenience using the default mapper."""
    return default_mapper.cite(finding)


__all__ = ["Citation", "ComplianceMapper", "cite", "default_mapper"]
