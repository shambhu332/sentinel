"""Unit tests for the Tier-3 follow-up modules.

Covers (one section per module):

* sentinel/learning/ml_strategy.py — classifier predicts strategies
* sentinel/fuzz/runner.py        — toolchain detection + crash triage
* sentinel/devices/redis_pool.py — Redis lease acquisition + release

The Redis tests use ``fakeredis`` so the suite stays self-contained.
The AFL++ tests mock subprocess so we never actually run afl-fuzz.
"""
from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.finding import Finding, Severity

# ----------------------------- ml_strategy ---------------------------------


def _mk_profile_with_failures(failures: list[tuple[str, str, str]]):
    """Build an AppLearningProfile with (agent_id, context_tag, strategy)."""
    from sentinel.learning.profile_store import AppLearningProfile
    p = AppLearningProfile(apk_sha256="a" * 64, package="com.test.app")
    for agent_id, tag, strategy in failures:
        p.record_failure_context(
            agent_id=agent_id,
            context_tag=tag,
            context_note="test",
            suggested_strategy=strategy,
            scan_session="t0",
        )
    return p


def test_ml_selector_predicts_known_strategy():
    from sentinel.learning.ml_strategy import MLStrategySelector

    p = _mk_profile_with_failures([
        ("D_072", "obfuscation_tier_2", "extended_payload_set"),
    ])
    sel = MLStrategySelector()
    out = sel.strategies_for("D_072", p)
    assert any(r.strategy == "extended_payload_set" for r in out)


def test_ml_selector_handles_unknown_context_tag():
    """Unknown tag → classifier still returns a label or falls back cleanly."""
    from sentinel.learning.ml_strategy import MLStrategySelector

    p = _mk_profile_with_failures([
        ("D_072", "wildly_novel_tag", ""),    # no suggested_strategy
    ])
    sel = MLStrategySelector()
    # Whatever the classifier predicts must be one of the known strategy
    # labels — i.e. _not_ an empty string and _not_ the input tag verbatim.
    out = sel.strategies_for("D_072", p)
    for rec in out:
        assert rec.strategy != ""
        assert rec.strategy != "wildly_novel_tag"


def test_ml_selector_empty_profile_returns_nothing():
    from sentinel.learning.ml_strategy import MLStrategySelector

    sel = MLStrategySelector()
    assert sel.strategies_for("D_072", None) == []


def test_ml_selector_train_and_persist(tmp_path: Path):
    # Drop one synthetic profile under tmp_path so training has data.
    import json

    from sentinel.learning.ml_strategy import (
        MLStrategySelector,
        train_from_profiles,
    )
    (tmp_path / "abc.json").write_text(json.dumps({
        "apk_sha256": "a" * 64,
        "package": "com.x.app",
        "failure_contexts": {
            "D_063": [{
                "context_tag": "custom_orm",
                "suggested_strategy": "custom_orm_fuzzing",
                "occurrences": 5,
            }],
        },
    }))
    model_path = tmp_path / "model.pkl"
    count = train_from_profiles(tmp_path, model_path)
    assert count > 0
    assert model_path.exists()
    # Loaded model predicts custom_orm_fuzzing.
    sel = MLStrategySelector(model_path=model_path)
    p = _mk_profile_with_failures([("D_063", "custom_orm", "")])
    out = sel.strategies_for("D_063", p)
    assert any(r.strategy == "custom_orm_fuzzing" for r in out)


# ----------------------------- fuzz/runner.py -----------------------------


def test_fuzz_detect_toolchain_returns_status():
    from sentinel.fuzz.runner import detect_toolchain
    status = detect_toolchain()
    # Whatever the host has, the function never raises.
    assert isinstance(status.available, bool)
    assert isinstance(status.reason, str)


def test_fuzz_triage_classifies_asan_crash(tmp_path: Path):
    from sentinel.fuzz.runner import triage_crashes

    # Build a realistic crash artifact: ASAN-style stderr dump.
    out = tmp_path / "out" / "harness_a"
    out.mkdir(parents=True)
    (out / "crash_001").write_bytes(
        b"==12345==ERROR: AddressSanitizer: heap-buffer-overflow on "
        b"address 0xdeadbeef at pc 0x123\n"
        b"  #0 0x123 in Java_com_x_Native_doIt\n"
    )
    (out / "fuzzer_stats").write_bytes(b"ignored")
    (out / "README").write_bytes(b"ignored")
    crashes = triage_crashes(tmp_path)
    assert len(crashes) == 1
    c = crashes[0]
    assert c.signal == "SIGSEGV"
    assert "heap-buffer-overflow" in c.asan_signature
    # The base64 reproducer fits in evidence.
    decoded = base64.b64decode(c.input_bytes_b64)
    assert decoded[:5] == b"==123"


def test_fuzz_crashes_to_findings_shape():
    from sentinel.fuzz.runner import FuzzCrash, crashes_to_findings

    crashes = [
        FuzzCrash(
            harness="Java_com_x_Native_doIt_fuzz",
            artifact_path=Path("/tmp/crash_001"),
            signal="SIGSEGV",
            asan_signature="ASAN/heap-buffer-overflow",
            input_bytes_b64="AAAA",
        ),
    ]
    findings = crashes_to_findings(crashes, session_id="abc12345")
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "D_072"
    assert f.severity == Severity.CRITICAL
    assert f.evidence["dynamic_target"] is True
    assert f.evidence["afl_signal"] == "SIGSEGV"
    assert f.evidence["cwe"] == "CWE-787"


def test_fuzz_run_for_session_skips_when_toolchain_absent(
    tmp_path: Path, monkeypatch,
):
    """When detect_toolchain says unavailable, runner returns ([], status)."""
    from sentinel.fuzz import runner as runner_mod

    def fake_detect():
        return runner_mod.ToolchainStatus(
            available=False, reason="no clang on PATH (test fake)",
        )
    monkeypatch.setattr(runner_mod, "detect_toolchain", fake_detect)
    findings, status = runner_mod.run_for_session(
        workspace=tmp_path, session_id="abc12345", time_per_harness_s=1,
    )
    assert findings == []
    assert status.available is False


# ----------------------------- devices/redis_pool -------------------------


@pytest.mark.asyncio
async def test_redis_device_manager_acquires_and_releases(monkeypatch):
    """Two leases on the same serial sequentially must both succeed.

    fakeredis backs the test so no Redis server is required.
    """
    fakeredis = pytest.importorskip("fakeredis", reason="fakeredis missing")
    from sentinel.devices import pool as pool_mod
    from sentinel.devices.pool import DeviceInfo
    from sentinel.devices.redis_pool import RedisDeviceManager

    fake_devices = [
        DeviceInfo(serial="emu-x", state="device", is_emulator=True),
    ]
    monkeypatch.setattr(pool_mod, "_parse_devices_output",
                        lambda txt: fake_devices)
    monkeypatch.setattr(pool_mod, "_run_adb", lambda *a, **k: "")
    monkeypatch.setattr(pool_mod, "_enrich", lambda d: None)

    mgr = RedisDeviceManager(redis_url="redis://localhost:6379/0")
    # Replace the real Redis client with the fakeredis async client.
    mgr._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    assert mgr.is_distributed

    async with mgr.lease() as first:
        assert first.serial == "emu-x"
    # Released → second lease succeeds without timing out.
    async with mgr.lease() as second:
        assert second.serial == "emu-x"


@pytest.mark.asyncio
async def test_redis_lease_blocks_when_held(monkeypatch):
    """A second concurrent lease on the only available device must
    timeout when Redis lock is already held by another 'process'."""
    fakeredis = pytest.importorskip("fakeredis", reason="fakeredis missing")
    from sentinel.devices import pool as pool_mod
    from sentinel.devices.pool import DeviceInfo, DeviceUnavailable
    from sentinel.devices.redis_pool import RedisDeviceManager

    monkeypatch.setattr(pool_mod, "_parse_devices_output",
                        lambda txt: [DeviceInfo(serial="emu-y", state="device",
                                                is_emulator=True)])
    monkeypatch.setattr(pool_mod, "_run_adb", lambda *a, **k: "")
    monkeypatch.setattr(pool_mod, "_enrich", lambda d: None)

    shared = fakeredis.aioredis.FakeRedis(decode_responses=True)
    mgr_a = RedisDeviceManager(redis_url="redis://x/0")
    mgr_a._redis = shared
    mgr_b = RedisDeviceManager(redis_url="redis://x/0")
    mgr_b._redis = shared

    async def first():
        async with mgr_a.lease(timeout_s=5.0):
            # Hold the lease long enough that the second attempt times out.
            await asyncio.sleep(2.0)

    async def second():
        await asyncio.sleep(0.2)
        with pytest.raises(DeviceUnavailable):
            async with mgr_b.lease(timeout_s=1.0):
                pass

    await asyncio.gather(first(), second())


def test_get_device_manager_falls_back_when_no_redis(monkeypatch):
    """Without SENTINEL_REDIS_URL we always get the in-process manager."""
    from sentinel.devices import DeviceManager, get_device_manager

    monkeypatch.delenv("SENTINEL_REDIS_URL", raising=False)
    mgr = get_device_manager()
    assert isinstance(mgr, DeviceManager)
    # Specifically NOT a RedisDeviceManager.
    from sentinel.devices import RedisDeviceManager
    assert not isinstance(mgr, RedisDeviceManager)
