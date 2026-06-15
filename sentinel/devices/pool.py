"""Async device-leasing pool over ``adb devices``."""
from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class DeviceUnavailable(RuntimeError):
    """Raised when the pool has no eligible device for a lease."""


@dataclass
class DeviceInfo:
    serial: str
    state: str = "device"           # device | offline | unauthorized | emulator
    is_emulator: bool = False
    manufacturer: str = ""
    model: str = ""
    sdk: str = ""
    abi: str = ""
    fingerprint: str = ""
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, str]:
        return {
            "serial": self.serial, "state": self.state,
            "is_emulator": "true" if self.is_emulator else "false",
            "manufacturer": self.manufacturer, "model": self.model,
            "sdk": self.sdk, "abi": self.abi,
            "fingerprint": self.fingerprint[:64],
        }


def _adb_path() -> str:
    return shutil.which("adb") or "adb"


def _run_adb(args: list[str], timeout: float = 8.0) -> str:
    try:
        p = subprocess.run(
            [_adb_path(), *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return p.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _parse_devices_output(text: str) -> list[DeviceInfo]:
    out: list[DeviceInfo] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        out.append(DeviceInfo(
            serial=serial, state=state,
            is_emulator=serial.startswith("emulator-"),
        ))
    return out


def _enrich(d: DeviceInfo) -> None:
    """Pull manufacturer / model / sdk via getprop. Best effort."""
    def gp(k: str) -> str:
        return _run_adb(["-s", d.serial, "shell", "getprop", k]).strip()
    d.manufacturer = gp("ro.product.manufacturer")
    d.model = gp("ro.product.model")
    d.sdk = gp("ro.build.version.sdk")
    d.abi = gp("ro.product.cpu.abi")
    d.fingerprint = gp("ro.build.fingerprint")


class DeviceManager:
    """Discover + lease attached Android devices."""

    def __init__(self) -> None:
        self._devices: dict[str, DeviceInfo] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._rr_index = 0
        self._discovery_lock = asyncio.Lock()

    async def refresh(self) -> list[DeviceInfo]:
        """Re-scan ``adb devices`` and update the cache."""
        async with self._discovery_lock:
            text = await asyncio.to_thread(_run_adb, ["devices"])
            now = time.time()
            current = {d.serial: d for d in _parse_devices_output(text)}
            # Enrich freshly-seen devices.
            for serial, info in current.items():
                if serial not in self._devices:
                    await asyncio.to_thread(_enrich, info)
                    self._locks[serial] = asyncio.Lock()
                else:
                    # Preserve old enrichment, just bump last_seen + state.
                    prior = self._devices[serial]
                    info.manufacturer = prior.manufacturer
                    info.model = prior.model
                    info.sdk = prior.sdk
                    info.abi = prior.abi
                    info.fingerprint = prior.fingerprint
                info.last_seen = now
            self._devices = current
            return list(current.values())

    def list(self) -> list[DeviceInfo]:
        return list(self._devices.values())

    def get(self, serial: str) -> DeviceInfo | None:
        return self._devices.get(serial)

    @asynccontextmanager
    async def lease(self, prefer_serial: str | None = None,
                    timeout_s: float = 60.0):
        """Lease a device for the duration of the ``async with`` block.

        Picks ``prefer_serial`` if free; otherwise round-robins across
        eligible (state == "device") devices. Raises ``DeviceUnavailable``
        if nothing is leasable within ``timeout_s``.
        """
        await self.refresh()
        eligible = [
            d for d in self._devices.values()
            if d.state == "device"
        ]
        if not eligible:
            raise DeviceUnavailable(
                "No usable Android device found via `adb devices`. "
                "Plug in or boot one with USB-debugging enabled.",
            )

        # Prefer a specific serial if asked.
        ordered = []
        if prefer_serial and prefer_serial in self._devices:
            ordered.append(self._devices[prefer_serial])
        # Round-robin everyone else.
        n = len(eligible)
        for i in range(n):
            d = eligible[(self._rr_index + i) % n]
            if d not in ordered:
                ordered.append(d)
        self._rr_index = (self._rr_index + 1) % max(1, n)

        deadline = time.time() + timeout_s
        chosen = None
        for d in ordered:
            lock = self._locks.setdefault(d.serial, asyncio.Lock())
            try:
                await asyncio.wait_for(
                    lock.acquire(), timeout=max(0.1, deadline - time.time()),
                )
                chosen = d
                logger.info("DeviceManager: leased %s (%s/%s)",
                            d.serial, d.manufacturer or "?", d.model or "?")
                break
            except asyncio.TimeoutError:
                continue
        if chosen is None:
            raise DeviceUnavailable(
                "All attached devices are currently leased by other scans.",
            )
        try:
            yield chosen
        finally:
            try:
                self._locks[chosen.serial].release()
            except Exception:  # noqa: BLE001
                pass


__all__ = ["DeviceInfo", "DeviceManager", "DeviceUnavailable"]
