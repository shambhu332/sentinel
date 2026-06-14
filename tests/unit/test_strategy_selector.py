"""Tests for ADAPT_001 StrategySelector + LEARN_001 FeedbackAgent."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.learning import (
    AppLearningProfile,
    AppProfileStore,
    FeedbackAgent,
    StrategySelector,
    applies_strategy,
)


def _profile(tag: str, strategy: str = "") -> AppLearningProfile:
    p = AppLearningProfile(apk_sha256="a" * 64, package="com.acme")
    p.record_failure_context(
        agent_id="D_063", context_tag=tag, suggested_strategy=strategy,
    )
    return p


# ============================================================
# Profile failure-context round trip
# ============================================================

def test_record_failure_context_roundtrip(tmp_path: Path) -> None:
    store = AppProfileStore(root=tmp_path / "learning")
    p = AppLearningProfile(apk_sha256="b" * 64)
    p.record_failure_context(
        "D_063", "custom_orm",
        context_note="ROOM @Query detected",
        suggested_strategy="custom_orm_fuzzing",
        scan_session="sess_abcd1234",
    )
    store.save(p)
    loaded = store.load("b" * 64)
    ctxs = loaded.get_failure_contexts("D_063")
    assert len(ctxs) == 1
    assert ctxs[0]["context_tag"] == "custom_orm"
    assert ctxs[0]["suggested_strategy"] == "custom_orm_fuzzing"
    assert ctxs[0]["occurrences"] == 1


def test_duplicate_context_coalesces_into_occurrences() -> None:
    p = AppLearningProfile(apk_sha256="c" * 64)
    for _ in range(3):
        p.record_failure_context(
            "D_072", "obfuscation_tier_2",
            suggested_strategy="extended_payload_set",
        )
    ctxs = p.get_failure_contexts("D_072")
    assert len(ctxs) == 1
    assert ctxs[0]["occurrences"] == 3


# ============================================================
# StrategySelector
# ============================================================

def test_selector_returns_recorded_strategy() -> None:
    p = _profile("custom_orm", "custom_orm_fuzzing")
    selector = StrategySelector()
    records = selector.strategies_for("D_063", p)
    assert len(records) == 1
    assert records[0].strategy == "custom_orm_fuzzing"
    assert records[0].source_context == "custom_orm"


def test_selector_falls_back_to_curated_map() -> None:
    # Suggested strategy not set; selector should resolve via
    # _FAILURE_STRATEGY_MAP using the context_tag.
    p = AppLearningProfile(apk_sha256="d" * 64)
    p.record_failure_context("D_063", "custom_orm")
    selector = StrategySelector()
    records = selector.strategies_for("D_063", p)
    assert any(r.strategy == "custom_orm_fuzzing" for r in records)


def test_selector_empty_when_profile_is_none() -> None:
    selector = StrategySelector()
    assert selector.strategies_for("D_063", None) == []


def test_selector_dedupes_strategies_by_occurrences() -> None:
    p = AppLearningProfile(apk_sha256="e" * 64)
    p.record_failure_context(
        "D_063", "custom_orm",
        suggested_strategy="custom_orm_fuzzing",
    )
    p.record_failure_context(
        "D_063", "selection_argument_bound",
        suggested_strategy="custom_orm_fuzzing",  # same strategy, diff source
    )
    # Re-record the first to bump occurrences
    p.record_failure_context(
        "D_063", "custom_orm",
        suggested_strategy="custom_orm_fuzzing",
    )
    selector = StrategySelector()
    records = selector.strategies_for("D_063", p)
    strats = [r.strategy for r in records]
    assert strats.count("custom_orm_fuzzing") == 1
    # Higher-occurrences source wins
    rec = next(r for r in records if r.strategy == "custom_orm_fuzzing")
    assert rec.source_context == "custom_orm"
    assert rec.occurrences == 2


def test_applies_strategy_one_liner() -> None:
    from sentinel.learning.strategy import StrategyRecord
    records = [
        StrategyRecord(agent_id="D_063", strategy="custom_orm_fuzzing",
                       source_context="custom_orm"),
    ]
    assert applies_strategy(records, "custom_orm_fuzzing") is True
    assert applies_strategy(records, "skip_iap_spoof") is False


# ============================================================
# FeedbackAgent
# ============================================================

def test_feedback_agent_records_to_store(tmp_path: Path) -> None:
    store = AppProfileStore(root=tmp_path / "learning")
    fa = FeedbackAgent(store=store)
    fa.record_probe_failure(
        apk_sha256="f" * 64,
        agent_id="D_063",
        context_tag="custom_orm",
        context_note="ROOM @Query placeholder rejected our probes",
        scan_session="sess_fb000001",
    )
    p = store.load("f" * 64)
    ctxs = p.get_failure_contexts("D_063")
    assert len(ctxs) == 1
    # FeedbackAgent resolved the suggested_strategy from the curated map.
    assert ctxs[0]["suggested_strategy"] == "custom_orm_fuzzing"


def test_feedback_agent_noop_without_apk_sha256(tmp_path: Path) -> None:
    store = AppProfileStore(root=tmp_path / "learning")
    fa = FeedbackAgent(store=store)
    # Empty sha256 -> no-op (silent skip)
    fa.record_probe_failure(
        apk_sha256="", agent_id="D_063", context_tag="custom_orm",
    )
    # Nothing was written
    assert not any((tmp_path / "learning").rglob("*.json"))


def test_feedback_agent_override_strategy(tmp_path: Path) -> None:
    store = AppProfileStore(root=tmp_path / "learning")
    fa = FeedbackAgent(store=store)
    fa.record_probe_failure(
        apk_sha256="0" * 64,
        agent_id="D_063",
        context_tag="custom_orm",
        suggested_strategy="some_explicit_override",
    )
    p = store.load("0" * 64)
    assert p.get_failure_contexts("D_063")[0]["suggested_strategy"] == \
        "some_explicit_override"


# ============================================================
# D_063 + D_072 adaptive behaviour
# ============================================================

def test_d063_payload_includes_custom_orm_probes_when_strategy_applies() -> None:
    from sentinel.agents.dynamic.d063_provider_sqli import (
        _CUSTOM_ORM_PROBES,
        _PROBE_PAYLOADS,
        ProviderSqliAgent,
    )
    plain = ProviderSqliAgent._build_frida_payload(
        "com.x.auth", ["users"], adaptive_strategies=None,
    )
    adapted = ProviderSqliAgent._build_frida_payload(
        "com.x.auth", ["users"],
        adaptive_strategies=["custom_orm_fuzzing"],
    )
    assert len(plain["probe_payloads"]) == len(_PROBE_PAYLOADS)
    assert len(adapted["probe_payloads"]) == \
        len(_PROBE_PAYLOADS) + len(_CUSTOM_ORM_PROBES)
    assert adapted["adaptive_strategies_applied"] == ["custom_orm_fuzzing"]


def test_d072_skip_oversize_drops_oversize_probe() -> None:
    from sentinel.agents.dynamic.d072_jni_shadow import JniShadowAgent
    plain = JniShadowAgent._build_payload(
        "Java_com_x_Foo_bar", "java.lang.String", ["libfoo.so"],
        adaptive_strategies=None,
    )
    skipped = JniShadowAgent._build_payload(
        "Java_com_x_Foo_bar", "java.lang.String", ["libfoo.so"],
        adaptive_strategies=["skip_oversize_probes"],
    )
    plain_kinds = {p["kind"] for p in plain["probes"]}
    skipped_kinds = {p["kind"] for p in skipped["probes"]}
    assert "oversize" in plain_kinds
    assert "oversize" not in skipped_kinds


def test_d072_extended_strategy_adds_more_probes() -> None:
    from sentinel.agents.dynamic.d072_jni_shadow import JniShadowAgent
    plain = JniShadowAgent._build_payload(
        "Java_x_Y_z", "", [],
    )
    extended = JniShadowAgent._build_payload(
        "Java_x_Y_z", "", [],
        adaptive_strategies=["extended_payload_set"],
    )
    assert len(extended["probes"]) > len(plain["probes"])
    kinds = {p["kind"] for p in extended["probes"]}
    assert "format_string_long" in kinds
    assert "format_string_arg_walk" in kinds


def test_d072_module_export_scan_flag() -> None:
    from sentinel.agents.dynamic.d072_jni_shadow import JniShadowAgent
    plain = JniShadowAgent._build_payload("Java_x_Y_z", "", [])
    scan = JniShadowAgent._build_payload(
        "Java_x_Y_z", "", [],
        adaptive_strategies=["module_export_scan"],
    )
    assert plain["module_export_scan"] is False
    assert scan["module_export_scan"] is True
