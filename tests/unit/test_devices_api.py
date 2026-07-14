"""Device dynamic-lab route tests."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from sentinel.api.routes import devices
from sentinel.api.routes.devices import LaunchRequest
from sentinel.tools.result import ToolResult


@dataclass
class _Check:
    name: str
    ok: bool
    detail: str


class _Upload:
    def __init__(self, filename: str, data: bytes) -> None:
        self.filename = filename
        self._data = data
        self._offset = 0
        self.closed = False

    async def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._data) - self._offset
        start = self._offset
        end = min(len(self._data), start + size)
        self._offset = end
        return self._data[start:end]

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_device_preflight_returns_structured_checks(monkeypatch):
    async def _fake_preflight(serial: str):
        return [
            _Check("adb device reachable", True, f"{serial} responsive"),
            _Check("frida-server on device", False, "not reachable"),
        ]

    monkeypatch.setattr(devices, "run_preflight", _fake_preflight)

    body = await devices.device_preflight("127.0.0.1:6562", current_user={})

    assert body["serial"] == "127.0.0.1:6562"
    assert body["ok"] is False
    assert body["checks"][0]["name"] == "adb device reachable"
    assert body["checks"][1]["ok"] is False


@pytest.mark.asyncio
async def test_install_endpoint_uses_install_multiple_for_split_apks(monkeypatch):
    calls = {}

    async def _fake_install_multiple(
        self,
        apk_paths: list[Path],
        serial: str | None = None,
        replace: bool = True,
        grant_permissions: bool = False,
    ):
        calls["paths"] = apk_paths
        calls["serial"] = serial
        calls["replace"] = replace
        calls["grant_permissions"] = grant_permissions
        return ToolResult.ok("Success")

    monkeypatch.setattr(devices.AdbRunner, "install_multiple_apks", _fake_install_multiple)

    uploads = [
        _Upload("base.apk", b"PK\x03\x04base"),
        _Upload("config.x86_64.apk", b"PK\x03\x04split"),
    ]

    body = await devices.install_uploaded_apks(
        "emulator-5554",
        apks=uploads,
        replace=True,
        grant_permissions=False,
        current_user={},
    )

    assert body["ok"] is True
    assert body["mode"] == "split"
    assert body["files"] == ["base.apk", "config.x86_64.apk"]
    assert calls["serial"] == "emulator-5554"
    assert calls["replace"] is True
    assert calls["grant_permissions"] is False
    assert len(calls["paths"]) == 2


@pytest.mark.asyncio
async def test_launch_endpoint_builds_explicit_activity_command(monkeypatch):
    calls = []

    async def _fake_action(
        name: str,
        args: list[str],
        *,
        serial: str,
        timeout: int = 30,
    ):
        calls.append((name, args, serial, timeout))
        return {
            "name": name,
            "ok": True,
            "exit_code": 0,
            "stdout": "ok",
            "stderr": "",
            "duration_seconds": 0.0,
        }

    monkeypatch.setattr(devices, "_run_adb_action", _fake_action)

    body = await devices.launch_package(
        "emulator-5554",
        LaunchRequest(package="com.example.app", activity=".MainActivity"),
        current_user={},
    )

    assert body["ok"] is True
    assert calls[0] == (
        "am start",
        ["shell", "am", "start", "-W", "-n", "com.example.app/.MainActivity"],
        "emulator-5554",
        20,
    )
    assert calls[1][0] == "pidof package"
