"""Profile loader.

A profile reorders the agent roster so the agents most relevant to a given
app category (banking, e-learning, e-commerce, ...) run first. Non-priority
agents still execute — the profile guides emphasis, not coverage.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_BUILTIN_DIR = Path(__file__).resolve().parent / "data"


@dataclass(frozen=True)
class AppProfile:
    name: str
    label: str
    description: str
    priority_agents: tuple[str, ...]

    def reorder(self, agent_classes: list[Any]) -> list[Any]:
        """Return ``agent_classes`` with priority agents first.

        Priority IDs that aren't present in the roster are silently skipped
        (a profile may list agents that haven't been implemented yet). Agents
        without an ``AGENT_ID`` class attribute keep their original position.
        """
        by_id: dict[str, Any] = {}
        for cls in agent_classes:
            aid = getattr(cls, "AGENT_ID", None)
            if aid:
                by_id[aid] = cls

        prioritized: list[Any] = []
        used: set[str] = set()
        for aid in self.priority_agents:
            cls = by_id.get(aid)
            if cls is not None and aid not in used:
                prioritized.append(cls)
                used.add(aid)
        for cls in agent_classes:
            aid = getattr(cls, "AGENT_ID", None)
            if aid not in used:
                prioritized.append(cls)
        return prioritized

    def missing_from(self, agent_classes: list[Any]) -> list[str]:
        """Priority IDs declared by the profile but absent from the roster."""
        roster_ids = {getattr(c, "AGENT_ID", None) for c in agent_classes}
        return [aid for aid in self.priority_agents if aid not in roster_ids]


def list_builtin_profiles() -> list[str]:
    if not _BUILTIN_DIR.exists():
        return []
    return sorted(p.stem for p in _BUILTIN_DIR.glob("*.json"))


def load_profile(name_or_path: str) -> AppProfile:
    """Load a profile by built-in name (``banking``) or filesystem path."""
    path = Path(name_or_path)
    if path.suffix == ".json" and path.exists():
        data = json.loads(path.read_text())
    else:
        candidate = _BUILTIN_DIR / f"{name_or_path}.json"
        if not candidate.exists():
            available = ", ".join(list_builtin_profiles()) or "(none)"
            raise FileNotFoundError(
                f"Unknown profile '{name_or_path}'. Built-in profiles: {available}",
            )
        data = json.loads(candidate.read_text())

    for required in ("name", "label", "description", "priority_agents"):
        if required not in data:
            raise ValueError(f"Profile missing required field: {required}")
    if not isinstance(data["priority_agents"], list):
        raise ValueError("priority_agents must be a list of agent IDs")

    return AppProfile(
        name=str(data["name"]),
        label=str(data["label"]),
        description=str(data["description"]),
        priority_agents=tuple(str(x) for x in data["priority_agents"]),
    )
