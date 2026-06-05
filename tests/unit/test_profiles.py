"""Tests for the app-category profile loader."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.profiles import AppProfile, list_builtin_profiles, load_profile


class _StubAgent:
    def __init__(self, agent_id: str) -> None:
        self.AGENT_ID = agent_id

    def __repr__(self) -> str:
        return f"<StubAgent {self.AGENT_ID}>"


def _roster(*ids: str) -> list:
    return [_StubAgent(i) for i in ids]


def test_builtin_profiles_present() -> None:
    names = list_builtin_profiles()
    assert {"banking", "edu", "ecommerce"}.issubset(set(names))


def test_each_builtin_profile_loads_and_has_priority_agents() -> None:
    for name in list_builtin_profiles():
        profile = load_profile(name)
        assert profile.name == name
        assert profile.label
        assert profile.description
        assert len(profile.priority_agents) > 0


def test_reorder_promotes_priority_agents_to_front() -> None:
    profile = AppProfile(
        name="t",
        label="T",
        description="",
        priority_agents=("B_001", "A_008"),
    )
    roster = _roster("A_001", "B_001", "C_001", "A_008", "D_001")
    reordered = profile.reorder(roster)
    ordered_ids = [c.AGENT_ID for c in reordered]
    assert ordered_ids[:2] == ["B_001", "A_008"]
    assert set(ordered_ids) == {"A_001", "B_001", "C_001", "A_008", "D_001"}


def test_reorder_preserves_non_priority_relative_order() -> None:
    profile = AppProfile(
        name="t", label="T", description="",
        priority_agents=("C_001",),
    )
    roster = _roster("A_001", "B_001", "C_001", "D_001")
    reordered = [c.AGENT_ID for c in profile.reorder(roster)]
    assert reordered == ["C_001", "A_001", "B_001", "D_001"]


def test_reorder_silently_skips_unknown_priority_ids() -> None:
    profile = AppProfile(
        name="t", label="T", description="",
        priority_agents=("X_999", "A_001"),
    )
    roster = _roster("A_001", "B_001")
    reordered = [c.AGENT_ID for c in profile.reorder(roster)]
    assert reordered == ["A_001", "B_001"]


def test_missing_from_reports_absent_priority_ids() -> None:
    profile = AppProfile(
        name="t", label="T", description="",
        priority_agents=("A_001", "X_999"),
    )
    roster = _roster("A_001", "B_001")
    assert profile.missing_from(roster) == ["X_999"]


def test_load_profile_unknown_name_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_profile("nonexistent_profile_xyz")


def test_load_profile_from_custom_path(tmp_path: Path) -> None:
    custom = tmp_path / "custom.json"
    custom.write_text(json.dumps({
        "name": "custom",
        "label": "Custom",
        "description": "Test profile",
        "priority_agents": ["A_001", "C_005"],
    }))
    profile = load_profile(str(custom))
    assert profile.name == "custom"
    assert profile.priority_agents == ("A_001", "C_005")


def test_load_profile_rejects_missing_required_field(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "x", "label": "X"}))
    with pytest.raises(ValueError):
        load_profile(str(bad))


def test_banking_profile_prioritizes_keystore_and_rasp() -> None:
    profile = load_profile("banking")
    assert "C_011" in profile.priority_agents
    assert "RES_001" in profile.priority_agents
    assert "N_001" in profile.priority_agents


def test_ecommerce_profile_prioritizes_business_logic_agents() -> None:
    profile = load_profile("ecommerce")
    for aid in ("B_001", "B_003", "B_004"):
        assert aid in profile.priority_agents
