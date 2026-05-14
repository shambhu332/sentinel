"""ADB wrapper — interacts with connected Android devices.

Provides async access to adb commands (device list, install APK, start app,
log capture, proxy configuration). All operations return ToolResult.

This module assumes adb is installed and on PATH. It does NOT manage
adb-server lifecycle — that's adb's own job.

Used by Phase 4 (DAST) to:
1. List connected devices
2. Install the target APK
3. Start the app via its package name
4. Configure the device's WiFi proxy to point at the laptop's mitmproxy
5. Capture logcat for any sensitive data exposure
6. Tear down: uninstall the APK, reset proxy
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)


@dataclass
class AdbDevice:
    """A connected Android device discovered via `adb devices`."""
    serial: str           # e.g., "R9ZR900AEJT"
    state: str            # "device", "offline", "unauthorized", etc.
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class AdbCommandResult:
    """Output of a single adb command."""
    stdout: str
    stderr: str
    exit_code: int


class AdbRunner:
    """Async wrapper for adb commands. Crash-proof: returns ToolResult."""

    def __init__(self, adb_path: Optional[str] = None, default_timeout: int = 30) -> None:
        self._adb_path = adb_path or shutil.which("adb")
        self._default_timeout = default_timeout
        self._missing_reason: Optional[str] = None
        if self._adb_path is None:
            self._missing_reason = "adb not found in PATH. Install android-tools."

    # ---------- Device management ----------

    async def list_devices(self) -> ToolResult[list[AdbDevice]]:
        """Return all devices currently connected via adb.

        Filters out devices in 'offline' or 'unauthorized' state by default
        (still returned but caller can check .state).
        """
        result = await self._run_adb(["devices", "-l"])
        if not result.success:
            return ToolResult.fail(
                f"adb devices failed: {result.error}",
                duration=result.duration_seconds,
            )

        devices: list[AdbDevice] = []
        for line in result.data.stdout.splitlines()[1:]:  # skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial = parts[0]
            state = parts[1]
            # Parse extra properties like 'model:SM-A037U' from rest of line
            props: dict[str, str] = {}
            for p in parts[2:]:
                if ":" in p:
                    k, v = p.split(":", 1)
                    props[k] = v
            devices.append(AdbDevice(serial=serial, state=state, properties=props))

        return ToolResult.ok(devices, duration=result.duration_seconds)

    async def get_first_device(self) -> ToolResult[AdbDevice]:
        """Return the first device in 'device' state."""
        list_result = await self.list_devices()
        if not list_result.success:
            return ToolResult.fail(list_result.error or "list_devices failed")

        for d in list_result.data:
            if d.state == "device":
                return ToolResult.ok(d)
        return ToolResult.fail("No connected devices in 'device' state")

    # ---------- APK install / start / stop ----------

    async def install_apk(self, apk_path: Path, serial: Optional[str] = None,
                          replace: bool = True) -> ToolResult[str]:
        """Install an APK on the device. `-r` replaces existing."""
        args = ["install"]
        if replace:
            args.append("-r")
        args.append(str(apk_path))
        result = await self._run_adb(args, serial=serial, timeout=120)
        if not result.success:
            return ToolResult.fail(
                f"install failed: {result.error}",
                duration=result.duration_seconds,
            )
        # adb sometimes returns success but stdout shows "Failure"
        out = result.data.stdout + result.data.stderr
        if "Success" not in out:
            return ToolResult.fail(
                f"install reported failure: {out[:300]}",
                duration=result.duration_seconds,
            )
        return ToolResult.ok(out.strip(), duration=result.duration_seconds)

    async def uninstall(self, package: str,
                        serial: Optional[str] = None) -> ToolResult[str]:
        """Uninstall a package by name."""
        result = await self._run_adb(["uninstall", package], serial=serial)
        if not result.success:
            return ToolResult.fail(
                f"uninstall failed: {result.error}",
                duration=result.duration_seconds,
            )
        return ToolResult.ok(result.data.stdout.strip(),
                             duration=result.duration_seconds)

    async def start_app(self, package: str, activity: Optional[str] = None,
                        serial: Optional[str] = None) -> ToolResult[str]:
        """Launch an app. If activity not given, uses MAIN/LAUNCHER intent."""
        if activity:
            component = f"{package}/{activity}"
            args = ["shell", "am", "start", "-n", component]
        else:
            args = [
                "shell", "monkey", "-p", package, "-c",
                "android.intent.category.LAUNCHER", "1",
            ]
        result = await self._run_adb(args, serial=serial, timeout=15)
        if not result.success:
            return ToolResult.fail(
                f"start_app failed: {result.error}",
                duration=result.duration_seconds,
            )
        return ToolResult.ok(result.data.stdout.strip(),
                             duration=result.duration_seconds)

    async def force_stop(self, package: str,
                         serial: Optional[str] = None) -> ToolResult[str]:
        """Force-stop a package."""
        result = await self._run_adb(
            ["shell", "am", "force-stop", package],
            serial=serial,
        )
        return ToolResult.ok("", duration=result.duration_seconds)

    # ---------- Proxy configuration ----------

    async def set_global_proxy(self, host: str, port: int,
                                serial: Optional[str] = None) -> ToolResult[str]:
        """Route ALL device WiFi traffic through host:port.

        This is the magic that makes mitmproxy work. After this call,
        every HTTP/HTTPS request from any app on the device goes through
        the laptop's mitmproxy instance.
        """
        proxy = f"{host}:{port}"
        result = await self._run_adb(
            ["shell", "settings", "put", "global", "http_proxy", proxy],
            serial=serial,
        )
        if not result.success:
            return ToolResult.fail(
                f"set_global_proxy failed: {result.error}",
                duration=result.duration_seconds,
            )
        logger.info("Device proxy set to %s", proxy)
        return ToolResult.ok(proxy, duration=result.duration_seconds)

    async def clear_global_proxy(self,
                                  serial: Optional[str] = None) -> ToolResult[str]:
        """Remove the WiFi proxy. Call this in teardown."""
        result = await self._run_adb(
            ["shell", "settings", "put", "global", "http_proxy", ":0"],
            serial=serial,
        )
        return ToolResult.ok("", duration=result.duration_seconds)

    # ---------- Log capture ----------

    async def logcat_clear(self,
                           serial: Optional[str] = None) -> ToolResult[str]:
        """Wipe the logcat ring buffer so subsequent captures are clean."""
        result = await self._run_adb(["logcat", "-c"], serial=serial)
        return ToolResult.ok("", duration=result.duration_seconds)

    async def logcat_dump(self, duration_seconds: float = 10,
                          serial: Optional[str] = None) -> ToolResult[str]:
        """Capture logcat output for a fixed duration, then return it.

        Uses `-d` to dump current buffer then exits — good for short captures.
        For longer or streaming captures, use logcat_stream() (TODO).
        """
        await asyncio.sleep(duration_seconds)
        result = await self._run_adb(
            ["logcat", "-d", "-v", "time"],
            serial=serial, timeout=30,
        )
        if not result.success:
            return ToolResult.fail(
                f"logcat dump failed: {result.error}",
                duration=result.duration_seconds,
            )
        return ToolResult.ok(result.data.stdout,
                             duration=result.duration_seconds)

    # ---------- Inner runner ----------

    async def _run_adb(
        self,
        args: list[str],
        serial: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult[AdbCommandResult]:
        """Execute an adb command. Captures stdout/stderr/exit_code."""
        start = time.monotonic()

        if self._missing_reason:
            return ToolResult.fail(
                self._missing_reason, duration=time.monotonic() - start,
            )

        cmd = [self._adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(args)

        effective_timeout = timeout or self._default_timeout
        logger.debug("Running: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult.fail(
                    f"adb command timed out after {effective_timeout}s",
                    duration=time.monotonic() - start,
                )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            exit_code = proc.returncode or 0

            return ToolResult.ok(
                AdbCommandResult(stdout=stdout, stderr=stderr, exit_code=exit_code),
                duration=time.monotonic() - start,
            )

        except FileNotFoundError as e:
            return ToolResult.fail(
                f"adb not found: {e}", duration=time.monotonic() - start,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("adb command crashed")
            return ToolResult.from_exception(
                e, duration=time.monotonic() - start,
            )
