"""Profile loader.

A profile reorders the agent roster so the agents most relevant to a given
app category (banking, e-learning, e-commerce, ...) run first. Non-priority
agents still execute — the profile guides emphasis, not coverage.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


def _builtin_dir() -> Path:
    """Locate the bundled `data/` directory robustly.

    `Path(__file__).resolve().parent / "data"` works for editable
    source-tree installs but breaks on wheels that drop non-Python
    files. `importlib.resources.files()` returns the right path in
    both cases. Falls back to the source-tree path on any failure
    so the function never blows up at import time.
    """
    try:
        return Path(str(resources.files("sentinel.profiles") / "data"))
    except (ModuleNotFoundError, AttributeError):
        return Path(__file__).resolve().parent / "data"


_BUILTIN_DIR = _builtin_dir()


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
    if _BUILTIN_DIR.exists():
        return sorted(p.stem for p in _BUILTIN_DIR.glob("*.json"))
    # Fall back to the embedded copy when the data dir is missing
    # (some Poetry wheel installs drop non-Python files).
    return sorted(_EMBEDDED_PROFILES.keys())


def _load_builtin(name: str) -> dict[str, Any] | None:
    """Read a built-in profile, preferring the JSON file then falling back
    to the embedded copy."""
    candidate = _BUILTIN_DIR / f"{name}.json"
    if candidate.exists():
        return json.loads(candidate.read_text())
    return _EMBEDDED_PROFILES.get(name)


def load_profile(name_or_path: str) -> AppProfile:
    """Load a profile by built-in name (``banking``) or filesystem path."""
    path = Path(name_or_path)
    if path.suffix == ".json" and path.exists():
        data = json.loads(path.read_text())
    else:
        data = _load_builtin(name_or_path)
        if data is None:
            available = ", ".join(list_builtin_profiles()) or "(none)"
            raise FileNotFoundError(
                f"Unknown profile '{name_or_path}'. Built-in profiles: {available}",
            )

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


# ---------------------------------------------------------------------
# Embedded copy of the built-in profiles. Kept in lock-step with the
# JSON files under data/. These survive any wheel-build edge case that
# drops non-Python files from the package, so list_builtin_profiles()
# and load_profile() always return the three canonical profiles.
# ---------------------------------------------------------------------
_EMBEDDED_PROFILES: dict[str, dict[str, Any]] = {
    "banking": {
        "name": "banking",
        "label": "Banking / Fintech",
        "description": (
            "Attacker objective: account takeover, fraudulent transactions, "
            "balance tampering. Prioritize key storage, biometric/auth strength, "
            "TLS pinning, transaction race conditions, and runtime hardening (RASP)."
        ),
        "priority_agents": [
            "C_011", "C_005", "A_008", "A_001", "N_001", "N_003", "N_002",
            "B_003", "B_001", "RES_001", "A_003", "N_005", "C_007", "C_006",
            "A_004", "A_007", "STG_006",
        ],
    },
    "ecommerce": {
        "name": "ecommerce",
        "label": "E-commerce / Retail",
        "description": (
            "Attacker objective: price manipulation, coupon/refund fraud, "
            "order IDOR, IAP bypass. Prioritize business-logic agents (IDOR, "
            "race, IAP), GraphQL surface, and API-key leakage to payment "
            "processors."
        ),
        "priority_agents": [
            "B_001", "B_003", "B_004", "N_007", "N_011", "N_006", "C_005",
            "A_001", "A_008", "P_001", "P_004", "N_001", "N_002", "STG_006",
            "F_001",
        ],
    },
    "edu": {
        "name": "edu",
        "label": "Educational / e-Learning",
        "description": (
            "Attacker objective: bypass login, access paid content, tamper "
            "grades, impersonate peers. Prioritize token storage, REST IDOR "
            "on student/grade resources, deep-link hijacks to admin views, "
            "and API-key leakage in traffic."
        ),
        "priority_agents": [
            "A_001", "A_008", "B_001", "P_001", "P_004", "N_006", "A_004",
            "A_007", "STG_006", "C_002", "N_002", "N_001", "F_001", "IPC_001",
        ],
    },
}
