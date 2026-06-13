"""Tests for D_052 symbolic intent + D_046 race-condition target + SafetyBudget."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from sentinel.agents.dynamic.d046_race_condition_target import (
    RaceConditionTargetAgent,
)
from sentinel.agents.dynamic.d052_symbolic_intent import SymbolicIntentAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.safety import SafetyBudget, SafetyConfig


def _apk(p: Path) -> Path:
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return p


def _ctx(tmp_path: Path) -> tuple[ScanContext, Path]:
    apk = _apk(tmp_path / "t.apk")
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    return ctx, decompiled


@pytest.fixture
async def memory(tmp_path):
    from sentinel.memory import LightweightMemory
    m = LightweightMemory(data_dir=tmp_path / "data")
    await m.connect()
    yield m
    await m.close()


# ============================================================
# D_052 SymbolicIntentAgent
# ============================================================

@pytest.mark.asyncio
async def test_d052_solves_boolean_premium_guard(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "PremiumReceiver.java").write_text(
        "public class PremiumReceiver extends BroadcastReceiver {\n"
        "  public void onReceive(Context c, Intent intent) {\n"
        '    boolean isPremium = intent.getBooleanExtra("isPremium", false);\n'
        "    if (isPremium) {\n"
        "      grantPremium();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    findings = await SymbolicIntentAgent(context=ctx, memory=memory).analyze()
    assert any(
        f.evidence.get("satisfying_extras", {}).get("isPremium") is True
        for f in findings
    )
    assert any(
        f.evidence.get("sink") == "grantPermission"
        and f.evidence.get("dynamic_target") is True
        for f in findings
    )


@pytest.mark.asyncio
async def test_d052_solves_string_role_check(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "AdminReceiver.java").write_text(
        "public class AdminReceiver extends BroadcastReceiver {\n"
        "  public void onReceive(Context c, Intent intent) {\n"
        '    String role = intent.getStringExtra("role");\n'
        '    if (role.equals("admin")) {\n'
        "      startActivity(adminIntent);\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    findings = await SymbolicIntentAgent(context=ctx, memory=memory).analyze()
    witness = next(
        (f.evidence.get("satisfying_extras") for f in findings),
        None,
    )
    assert witness is not None
    assert witness.get("role") == "admin"


@pytest.mark.asyncio
async def test_d052_no_finding_when_no_guarded_sink(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Plain.java").write_text(
        "public class Plain extends BroadcastReceiver {\n"
        "  public void onReceive(Context c, Intent intent) {\n"
        "    log(\"hi\");\n"
        "  }\n"
        "}\n"
    )
    findings = await SymbolicIntentAgent(context=ctx, memory=memory).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d052_int_threshold_solved(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "DebugReceiver.java").write_text(
        "public class DebugReceiver extends BroadcastReceiver {\n"
        "  public void onReceive(Context c, Intent intent) {\n"
        '    int level = intent.getIntExtra("debug_level", 0);\n'
        "    if (level >= 5) {\n"
        "      enableDebug();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    findings = await SymbolicIntentAgent(context=ctx, memory=memory).analyze()
    witness = next(
        (f.evidence.get("satisfying_extras") for f in findings),
        None,
    )
    assert witness is not None
    assert witness.get("debug_level") >= 5


# ============================================================
# D_046 RaceConditionTargetAgent
# ============================================================

@pytest.mark.asyncio
async def test_d046_flags_unsynchronised_balance_update(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Wallet.java").write_text(
        "public class Wallet {\n"
        "  int balance = 100;\n"
        "  public void updateBalance(int delta) {\n"
        "    balance = balance + delta;\n"
        "  }\n"
        "}\n"
    )
    findings = await RaceConditionTargetAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert any(
        f.evidence.get("method") == "updateBalance"
        and f.evidence.get("dynamic_target") is True
        for f in findings
    )
    payload = findings[0].evidence.get("frida_payload") or {}
    assert payload.get("class_simple_name") == "Wallet"
    assert payload.get("method_name") == "updateBalance"
    assert "frida_script_hint" in payload


@pytest.mark.asyncio
async def test_d046_skips_synchronised_method(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Wallet.java").write_text(
        "public class Wallet {\n"
        "  int balance = 100;\n"
        "  public synchronized void updateBalance(int delta) {\n"
        "    balance = balance + delta;\n"
        "  }\n"
        "}\n"
    )
    findings = await RaceConditionTargetAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d046_skips_atomic_variant(tmp_path, memory):
    ctx, root = _ctx(tmp_path)
    (root / "Wallet.java").write_text(
        "public class Wallet {\n"
        "  AtomicInteger balance = new AtomicInteger(100);\n"
        "  public void claimReward(int delta) {\n"
        "    balance.compareAndSet(balance.get(), balance.get() + delta);\n"
        "  }\n"
        "}\n"
    )
    findings = await RaceConditionTargetAgent(
        context=ctx, memory=memory,
    ).analyze()
    assert findings == []


# ============================================================
# SafetyBudget
# ============================================================

@pytest.mark.asyncio
async def test_safety_budget_caps_total_actions():
    budget = SafetyBudget(SafetyConfig(
        max_actions_total=5,
        max_actions_per_sec=0,  # disable rate to focus on total cap
        wall_clock_budget_s=60.0,
    ))
    fired = 0
    for _ in range(20):
        if not await budget.acquire():
            break
        fired += 1
    assert fired == 5
    assert budget.tripped


@pytest.mark.asyncio
async def test_safety_budget_consecutive_crashes_trip():
    budget = SafetyBudget(SafetyConfig(
        max_actions_total=100,
        max_actions_per_sec=0,
        max_consecutive_crashes=3,
    ))
    for _ in range(2):
        assert await budget.acquire()
        budget.record_failure()
    assert not budget.tripped
    assert await budget.acquire()
    budget.record_failure()
    # Now tripped — next acquire returns False
    assert not await budget.acquire()


@pytest.mark.asyncio
async def test_safety_budget_success_resets_streak():
    budget = SafetyBudget(SafetyConfig(
        max_actions_total=100,
        max_actions_per_sec=0,
        max_consecutive_crashes=3,
    ))
    for _ in range(2):
        assert await budget.acquire()
        budget.record_failure()
    assert await budget.acquire()
    budget.record_success()
    # Streak reset — now 2 more failures shouldn't trip
    for _ in range(2):
        assert await budget.acquire()
        budget.record_failure()
    assert not budget.tripped


@pytest.mark.asyncio
async def test_safety_budget_rate_limits():
    budget = SafetyBudget(SafetyConfig(
        max_actions_total=10,
        max_actions_per_sec=50.0,
        wall_clock_budget_s=10.0,
    ))
    start = time.monotonic()
    for _ in range(10):
        assert await budget.acquire()
    elapsed = time.monotonic() - start
    # 10 actions at 50/s should take ~0.18s. Generous bound.
    assert elapsed >= 0.05
