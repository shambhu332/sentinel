"""Unit tests for sentinel.tools.ui_driver."""
from __future__ import annotations

import asyncio

import pytest

from sentinel.tools.ui_driver import (
    AppiumUIDriver,
    MonkeyUIDriver,
    NoOpUIDriver,
    UICredentials,
    UIDriverResult,
    build_driver,
)


# ---------- NoOp driver ----------

@pytest.mark.asyncio
async def test_noop_full_lifecycle_is_a_success():
    d = NoOpUIDriver(target_package="com.example")
    assert await d.setup() is True
    assert await d.launch_and_login(None) is True
    result = await d.execute_flow(3)
    assert isinstance(result, UIDriverResult)
    assert result.ok is True
    assert result.driver_name == "noop"
    await d.teardown()


@pytest.mark.asyncio
async def test_noop_reports_duration_in_events():
    d = NoOpUIDriver(target_package="com.example")
    result = await d.execute_flow(7)
    assert any("7s" in ev for ev in result.events)


# ---------- Factory ----------

def test_build_driver_off_returns_noop():
    d = build_driver("off", target_package="com.example")
    assert isinstance(d, NoOpUIDriver)


def test_build_driver_monkey_returns_monkey():
    d = build_driver("monkey", target_package="com.example")
    assert isinstance(d, MonkeyUIDriver)


def test_build_driver_case_insensitive():
    assert isinstance(build_driver("MoNkEy", target_package="x"), MonkeyUIDriver)


def test_build_driver_unknown_falls_back_to_noop():
    """A typo in the CLI flag must not kill the scan."""
    d = build_driver("typo-does-not-exist", target_package="com.example")
    assert isinstance(d, NoOpUIDriver)


# ---------- Monkey driver — command shape ----------

@pytest.mark.asyncio
async def test_monkey_setup_returns_false_when_no_device(monkeypatch):
    """setup() reports False (never raises) when no device is visible."""
    d = MonkeyUIDriver(target_package="com.example")

    async def fake_visible(_self):
        return False

    monkeypatch.setattr(MonkeyUIDriver, "_device_visible", fake_visible)
    assert await d.setup() is False


@pytest.mark.asyncio
async def test_monkey_execute_flow_uses_safe_flags(monkeypatch):
    """Every monkey invocation must carry the non-destructive flag set."""
    seen: list[list[str]] = []

    async def fake_adb(self, args, *, timeout=30.0):
        seen.append(list(args))
        return 0, "Events injected: 12", ""

    monkeypatch.setattr(MonkeyUIDriver, "_adb", fake_adb)
    d = MonkeyUIDriver(target_package="com.acme.app", throttle_ms=300)
    result = await d.execute_flow(duration_sec=5)
    assert result.ok is True
    # A single call — the monkey subprocess itself.
    assert len(seen) == 1
    cmd = seen[0]
    # Non-destructive knobs are present with zero values.
    assert "--pct-syskeys" in cmd and cmd[cmd.index("--pct-syskeys") + 1] == "0"
    assert "--pct-anyevent" in cmd and cmd[cmd.index("--pct-anyevent") + 1] == "0"
    assert "--throttle" in cmd
    assert "--kill-process-after-error" in cmd
    # Scoped to the target package.
    assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "com.acme.app"


@pytest.mark.asyncio
async def test_monkey_execute_flow_reports_failure_reason(monkeypatch):
    """Non-zero adb exit code produces ok=False with a reason string."""
    async def fake_adb(self, args, *, timeout=30.0):
        return 1, "", "monkey aborted"

    monkeypatch.setattr(MonkeyUIDriver, "_adb", fake_adb)
    d = MonkeyUIDriver(target_package="com.example")
    result = await d.execute_flow(duration_sec=3)
    assert result.ok is False
    assert result.reason and "monkey" in result.reason.lower()


@pytest.mark.asyncio
async def test_monkey_event_count_bounded_by_max(monkeypatch):
    """Long duration must not exceed MAX_EVENTS."""
    captured: list[list[str]] = []

    async def fake_adb(self, args, *, timeout=30.0):
        captured.append(list(args))
        return 0, "", ""

    monkeypatch.setattr(MonkeyUIDriver, "_adb", fake_adb)
    d = MonkeyUIDriver(
        target_package="com.example", throttle_ms=300, event_count=None,
    )
    # 10 minutes at 300ms → 2000 events would be requested without the cap.
    await d.execute_flow(duration_sec=600)
    events_arg = int(captured[0][-1])
    assert events_arg <= MonkeyUIDriver.MAX_EVENTS


@pytest.mark.asyncio
async def test_monkey_throttle_floor_enforced():
    """Values below MIN_THROTTLE_MS get bumped up so mitmproxy has time."""
    d = MonkeyUIDriver(target_package="x", throttle_ms=10)
    assert d._throttle_ms >= MonkeyUIDriver.MIN_THROTTLE_MS


@pytest.mark.asyncio
async def test_monkey_launch_and_login_ignores_credentials(monkeypatch):
    """Monkey can't type, so credentials are noted but not sent."""
    calls: list[list[str]] = []

    async def fake_adb(self, args, *, timeout=30.0):
        calls.append(list(args))
        return 0, "", ""

    monkeypatch.setattr(MonkeyUIDriver, "_adb", fake_adb)
    d = MonkeyUIDriver(target_package="com.example")
    ok = await d.launch_and_login(UICredentials("u", "p"))
    assert ok is True
    # Credentials never appear in the shell invocation.
    for args in calls:
        joined = " ".join(args)
        assert "u" not in joined.split() or "com.example" in joined
        assert "p" not in joined.split()


# ---------- Appium placeholder ----------

@pytest.mark.asyncio
async def test_appium_placeholder_raises_not_implemented():
    d = AppiumUIDriver(target_package="com.example")
    with pytest.raises(NotImplementedError):
        await d.setup()
