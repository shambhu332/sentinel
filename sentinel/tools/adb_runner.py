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
6. Tear down: uninstall the APK, reset proxy, restore network state
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

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


@dataclass
class RuntimeResult:
    """Deterministic runtime verification result.

    This is the "truth engine" payload: every field is derived from ADB
    output or a screenshot capture. LLM code can consume this object to
    write rationale, but must not override the booleans.
    """

    command: str
    stdout: str
    stderr: str
    exit_code: int
    observed_result: str
    resumed_activity: str | None = None
    target_reached: bool = False
    is_auth_gated: bool = False
    blocking_state_screenshot: str | None = None
    verification_screenshot: str | None = None
    test_credentials_used: bool = False
    verified_exploited: bool = False


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

    async def install_apk(
        self,
        apk_path: Path,
        serial: Optional[str] = None,
        replace: bool = True,
        grant_permissions: bool = False,
    ) -> ToolResult[str]:
        """Install an APK on the device. `-r` replaces existing."""
        args = ["install"]
        if replace:
            args.append("-r")
        if grant_permissions:
            args.append("-g")
        args.append("-t")
        apk = str(apk_path)

        preferred_args = [*args, "--bypass-low-target-sdk-block", apk]
        result = await self._run_adb(preferred_args, serial=serial, timeout=120)
        if not result.success:
            return ToolResult.fail(
                f"install failed: {result.error}",
                duration=result.duration_seconds,
            )
        # adb sometimes returns success but stdout shows "Failure"
        out = result.data.stdout + result.data.stderr
        if "Success" not in out:
            if "Unknown option --bypass-low-target-sdk-block" in out:
                logger.info(
                    "adb install does not support "
                    "--bypass-low-target-sdk-block; retrying without it",
                )
                fallback_result = await self._run_adb(
                    [*args, apk],
                    serial=serial,
                    timeout=120,
                )
                if not fallback_result.success:
                    return ToolResult.fail(
                        f"install failed: {fallback_result.error}",
                        duration=(
                            result.duration_seconds
                            + fallback_result.duration_seconds
                        ),
                    )
                fallback_out = (
                    fallback_result.data.stdout + fallback_result.data.stderr
                )
                if "Success" in fallback_out:
                    return ToolResult.ok(
                        fallback_out.strip(),
                        duration=(
                            result.duration_seconds
                            + fallback_result.duration_seconds
                        ),
                    )
                out = fallback_out
            return ToolResult.fail(
                f"install reported failure: {out[:300]}",
                duration=result.duration_seconds,
            )
        return ToolResult.ok(out.strip(), duration=result.duration_seconds)

    async def install_multiple_apks(
        self,
        apk_paths: list[Path],
        serial: Optional[str] = None,
        replace: bool = True,
        grant_permissions: bool = False,
    ) -> ToolResult[str]:
        """Install a base APK plus split APKs using `adb install-multiple`."""
        if not apk_paths:
            return ToolResult.fail("install_multiple_apks requires at least one APK")

        args = ["install-multiple"]
        if replace:
            args.append("-r")
        if grant_permissions:
            args.append("-g")
        args.append("-t")

        apks = [str(p) for p in apk_paths]
        preferred_args = [*args, "--bypass-low-target-sdk-block", *apks]
        result = await self._run_adb(preferred_args, serial=serial, timeout=180)
        if not result.success:
            return ToolResult.fail(
                f"install-multiple failed: {result.error}",
                duration=result.duration_seconds,
            )

        out = result.data.stdout + result.data.stderr
        if "Success" not in out:
            if "Unknown option --bypass-low-target-sdk-block" in out:
                logger.info(
                    "adb install-multiple does not support "
                    "--bypass-low-target-sdk-block; retrying without it",
                )
                fallback_result = await self._run_adb(
                    [*args, *apks],
                    serial=serial,
                    timeout=180,
                )
                if not fallback_result.success:
                    return ToolResult.fail(
                        f"install-multiple failed: {fallback_result.error}",
                        duration=(
                            result.duration_seconds
                            + fallback_result.duration_seconds
                        ),
                    )
                fallback_out = (
                    fallback_result.data.stdout + fallback_result.data.stderr
                )
                if "Success" in fallback_out:
                    return ToolResult.ok(
                        fallback_out.strip(),
                        duration=(
                            result.duration_seconds
                            + fallback_result.duration_seconds
                        ),
                    )
                out = fallback_out
            return ToolResult.fail(
                f"install-multiple reported failure: {out[:300]}",
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

    async def is_installed(
        self, package: str, serial: Optional[str] = None,
    ) -> ToolResult[bool]:
        """Check whether a package is currently installed on the device.

        Uses `pm list packages <name>` which returns 'package:<name>' if
        installed, empty otherwise. The orchestrator uses this to decide
        whether to attempt install — calling `adb install -r` on an
        already-installed app force-stops it as a side effect (Android
        does this before staging the new APK), and if the install then
        fails partway through (split APKs, signature mismatch, etc.) the
        app is left in a killed state with no replacement installed.
        Checking first lets us skip install entirely when not needed.
        """
        result = await self._run_adb(
            ["shell", "pm", "list", "packages", package],
            serial=serial,
        )
        if not result.success:
            return ToolResult.fail(
                f"pm list packages failed: {result.error}",
                duration=result.duration_seconds,
            )
        # `pm list packages org.foo` returns "package:org.foo\n" if installed.
        # The package name might match as a substring of another package
        # (e.g. searching "org.foo" matches "org.foo.bar"), so we look for
        # the exact form.
        lines = result.data.stdout.strip().split("\n")
        installed = any(line.strip() == f"package:{package}" for line in lines)
        return ToolResult.ok(installed, duration=result.duration_seconds)

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

        Also broadcasts PROXY_CHANGE so apps pick up the new proxy
        without having to wait for a reconnect.
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

        # Broadcast PROXY_CHANGE so the system + apps re-read the value
        # immediately. Best-effort — not fatal if it fails.
        await self._broadcast_proxy_change(serial=serial)

        logger.info("Device proxy set to %s", proxy)
        return ToolResult.ok(proxy, duration=result.duration_seconds)

    async def clear_global_proxy(
        self,
        serial: Optional[str] = None,
        force_refresh: bool = True,
    ) -> ToolResult[str]:
        """Remove the WiFi proxy and restore working network state.

        Modern Android caches network connectivity state. Just clearing
        the proxy setting can leave the device unable to reach the
        internet until something nudges the network stack. This method:

        1. Sets http_proxy to ":0" (Android's canonical no-proxy value)
        2. Deletes legacy proxy keys (host/port/exclusion list) — idempotent
        3. Broadcasts PROXY_CHANGE to wake the connectivity service
        4. If force_refresh: cycles WiFi to force a clean re-read
        5. Verifies the proxy is actually cleared by reading it back

        Returns ToolResult.fail (not ok) if any verification step shows
        the proxy is still set — so the orchestrator's warning is
        actually meaningful instead of a silent no-op.

        Args:
            serial: device serial; None = default device
            force_refresh: if True, cycle WiFi after clearing for
                guaranteed network state recovery (~3s connectivity gap).
                Default True is the safe choice; pass False only if you
                have another reason to avoid the WiFi blip.
        """
        # Step 1: set proxy to no-op
        set_result = await self._run_adb(
            ["shell", "settings", "put", "global", "http_proxy", ":0"],
            serial=serial,
        )
        if not set_result.success:
            return ToolResult.fail(
                f"clear_global_proxy: failed to set http_proxy=:0: "
                f"{set_result.error}",
                duration=set_result.duration_seconds,
            )

        # Step 2: best-effort delete of legacy keys (idempotent — safe
        # to delete things that don't exist; returns "Deleted 0 rows")
        for key in (
            "global_http_proxy_host",
            "global_http_proxy_port",
            "global_http_proxy_exclusion_list",
        ):
            await self._run_adb(
                ["shell", "settings", "delete", "global", key],
                serial=serial,
            )

        # Step 3: broadcast PROXY_CHANGE — wakes the connectivity service
        await self._broadcast_proxy_change(serial=serial)

        # Step 4: optional WiFi cycle for stuck network state
        if force_refresh:
            cycle_result = await self._cycle_wifi(serial=serial)
            if not cycle_result.success:
                # Not fatal — proxy is cleared, but the device may take
                # longer to recover internet on its own.
                logger.warning(
                    "WiFi cycle failed during proxy cleanup: %s",
                    cycle_result.error,
                )

        # Step 5: verify the proxy is actually empty
        verify_result = await self.get_global_proxy(serial=serial)
        if verify_result.success:
            current = verify_result.data.strip()
            # Acceptable empty states: ":0", "null", empty string
            if current and current not in (":0", "null"):
                return ToolResult.fail(
                    f"clear_global_proxy: proxy still set after cleanup: "
                    f"{current!r} — manual intervention required",
                    duration=set_result.duration_seconds,
                )

        logger.info(
            "Device proxy cleared (force_refresh=%s, verified=%s)",
            force_refresh, verify_result.success,
        )
        return ToolResult.ok("", duration=set_result.duration_seconds)

    async def get_global_proxy(
        self,
        serial: Optional[str] = None,
    ) -> ToolResult[str]:
        """Read the current global http_proxy value.

        Returns the raw value as Android reports it. When no proxy is
        set, Android typically returns ":0" or "null" depending on
        version/skin — both are acceptable empty states.
        """
        result = await self._run_adb(
            ["shell", "settings", "get", "global", "http_proxy"],
            serial=serial,
        )
        if not result.success:
            return ToolResult.fail(
                f"get_global_proxy failed: {result.error}",
                duration=result.duration_seconds,
            )
        return ToolResult.ok(
            result.data.stdout.strip(),
            duration=result.duration_seconds,
        )

    async def _broadcast_proxy_change(
        self,
        serial: Optional[str] = None,
    ) -> ToolResult[str]:
        """Send PROXY_CHANGE broadcast so apps re-read proxy state.

        Best-effort. Some Android versions/skins don't honor this but
        it's cheap to send and helps on the ones that do.
        """
        result = await self._run_adb(
            ["shell", "am", "broadcast", "-a",
             "android.intent.action.PROXY_CHANGE"],
            serial=serial,
        )
        return ToolResult.ok(
            "broadcast sent" if result.success else "",
            duration=result.duration_seconds,
        )

    async def _cycle_wifi(
        self,
        serial: Optional[str] = None,
        wait_seconds: float = 2.0,
    ) -> ToolResult[str]:
        """Toggle WiFi off then on to force Android to re-read network config.

        This is the reliable hammer for clearing stuck network state.
        Costs ~3-5 seconds of connectivity. Use only when the lighter
        PROXY_CHANGE broadcast isn't enough.
        """
        disable = await self._run_adb(
            ["shell", "svc", "wifi", "disable"],
            serial=serial,
        )
        if not disable.success:
            return ToolResult.fail(
                f"WiFi disable failed: {disable.error}",
                duration=disable.duration_seconds,
            )

        await asyncio.sleep(wait_seconds)

        enable = await self._run_adb(
            ["shell", "svc", "wifi", "enable"],
            serial=serial,
        )
        if not enable.success:
            return ToolResult.fail(
                f"WiFi enable failed: {enable.error}",
                duration=enable.duration_seconds,
            )

        return ToolResult.ok(
            "WiFi cycled",
            duration=disable.duration_seconds + enable.duration_seconds,
        )

    # ---------- Visual evidence ----------

    async def screenshot(
        self,
        out_dir: Path,
        label: str = "screen",
        serial: Optional[str] = None,
    ) -> ToolResult[Path]:
        """Capture a device screenshot and save it under ``out_dir``.

        Uses ``adb exec-out screencap -p`` which streams the PNG bytes
        directly over the adb socket — avoids the legacy /sdcard/
        round-trip and works on devices without external storage.

        Args:
            out_dir: directory to write into; created if missing.
            label: short tag for the filename (e.g. "before_exploit").
                Combined with a millisecond timestamp to guarantee
                uniqueness across rapid captures.
            serial: device serial; None = default device.

        Returns ToolResult[Path] with the absolute screenshot path on
        success. Captures never raise — failure is reported via
        ToolResult so the agent pipeline keeps running.
        """
        start = time.monotonic()
        if self._missing_reason:
            return ToolResult.fail(
                self._missing_reason, duration=time.monotonic() - start,
            )

        out_dir.mkdir(parents=True, exist_ok=True)
        safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
        ts_ms = int(time.time() * 1000)
        out_path = out_dir / f"{safe_label}_{ts_ms}.png"

        cmd = [self._adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(["exec-out", "screencap", "-p"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self._default_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult.fail(
                    "screencap timed out",
                    duration=time.monotonic() - start,
                )

            if proc.returncode or not stdout_bytes:
                return ToolResult.fail(
                    f"screencap failed: {stderr_bytes.decode('utf-8', errors='replace')[:200]}",
                    duration=time.monotonic() - start,
                )

            out_path.write_bytes(stdout_bytes)
            logger.info("Captured screenshot → %s (%d bytes)", out_path, len(stdout_bytes))
            return ToolResult.ok(out_path, duration=time.monotonic() - start)

        except FileNotFoundError as e:
            return ToolResult.fail(
                f"adb not found: {e}", duration=time.monotonic() - start,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("screencap crashed")
            return ToolResult.from_exception(
                e, duration=time.monotonic() - start,
            )

    async def capture_evidence(
        self,
        out_dir: Path,
        label: str,
        *,
        step_index: int | None = None,
        caption: str | None = None,
        serial: Optional[str] = None,
        webp: bool = True,
    ) -> dict:
        """Capture a checkpoint screenshot and return a Finding-ready dict.

        Convenience wrapper around ``screenshot()`` for the dynamic
        analysis pipeline. Always returns a dict — never raises and
        never returns None — so an agent can ``finding.screenshots.append(...)``
        without conditional logic.

        Success shape::

            {"path": "evidence/screenshots/after_resume_<ts>.webp",
             "caption": "App home screen after deep-link trigger",
             "step_index": 2,
             "label": "after_resume",
             "captured_at": "<iso8601>"}

        Failure shape (use to document blocking states explicitly so the
        UI can render the "Unverified due to ..." callout instead of
        silently dropping the step)::

            {"path": None, "failed": True,
             "reason": "screencap timed out", "label": label,
             "step_index": step_index, "caption": caption}

        Args:
            out_dir: directory to write into (typically
                ``workspace/<session>/evidence/screenshots/``).
            label: short tag for the filename + UI lookup.
            step_index: optional 0-based index of the repro step this
                screenshot evidences. The frontend uses this to inline
                the image under the matching step.
            caption: human-readable description rendered under the image.
            serial: device serial; None = default device.
            webp: if True (default) and Pillow is available, transcode
                the PNG to WebP for ~30% smaller payloads. Falls back
                to the raw PNG on any encoder failure.
        """
        from datetime import datetime, timezone

        base = {
            "label": label,
            "caption": caption or "",
            "step_index": step_index,
        }

        shot = await self.screenshot(out_dir, label=label, serial=serial)
        if not shot.success or shot.data is None:
            base["path"] = None
            base["failed"] = True
            base["reason"] = shot.error or "screenshot capture failed"
            return base

        png_path: Path = shot.data
        final_path: Path = png_path

        if webp:
            webp_path = png_path.with_suffix(".webp")
            try:
                # Pillow is optional — if it's not installed we just keep PNG.
                from PIL import Image  # type: ignore[import-not-found]

                with Image.open(png_path) as im:
                    im.save(webp_path, format="WEBP", quality=82, method=4)
                # Only replace if the WebP is genuinely smaller.
                if webp_path.exists() and webp_path.stat().st_size < png_path.stat().st_size:
                    try:
                        png_path.unlink()
                    except OSError:
                        pass
                    final_path = webp_path
                else:
                    try:
                        webp_path.unlink()
                    except OSError:
                        pass
            except Exception as exc:  # noqa: BLE001
                logger.debug("WebP transcode skipped: %s", exc)

        try:
            relative = final_path.relative_to(out_dir.parent.parent)
        except ValueError:
            relative = final_path  # absolute fallback

        base["path"] = str(relative)
        base["captured_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return base

    async def capture_evidence_for_session(
        self,
        session_id: str,
        context: str,
        *,
        workspace: Path,
        caption: str | None = None,
        step_index: int | None = None,
        serial: Optional[str] = None,
    ) -> dict:
        """Djini-spec alias for ``capture_screenshot``.

        The public spec calls this ``capture_evidence(session_id, context)``
        — that name already belongs to the lower-level (out_dir, label)
        method, so this thin wrapper carries the session-aware
        signature under a non-clashing name. Delegates to
        ``capture_screenshot`` so the underlying behaviour stays in
        exactly one place.
        """
        return await self.capture_screenshot(
            session_id=session_id,
            filename=context,
            workspace=workspace,
            caption=caption,
            step_index=step_index,
            serial=serial,
        )

    async def capture_screenshot(
        self,
        session_id: str,
        filename: str,
        *,
        workspace: Path,
        caption: str | None = None,
        step_index: int | None = None,
        serial: Optional[str] = None,
    ) -> dict:
        """Session-aware convenience wrapper over ``capture_evidence``.

        Resolves the per-session evidence directory
        (``<workspace>/<session_id>/evidence/screenshots/``) so dynamic
        agents and the Phase 4.5 dispatcher don't recompute that path.

        ``filename`` is used as the underlying label — it goes through
        the same safe-character sanitisation as ``screenshot()`` and is
        combined with a millisecond timestamp to keep captures unique.
        """
        out_dir = workspace / session_id / "evidence" / "screenshots"
        return await self.capture_evidence(
            out_dir,
            label=filename,
            step_index=step_index,
            caption=caption,
            serial=serial,
        )

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

    async def execute_adb_command_and_capture(
        self,
        cmd: str | list[str],
        session_id: str,
        context: str,
        *,
        workspace: Path,
        timeout: float = 10.0,
        settle_seconds: float = 2.0,
        caption: str | None = None,
        step_index: int | None = None,
        serial: Optional[str] = None,
    ) -> tuple[str, str, str | None]:
        """Run an adb command, let the UI settle, then snapshot the screen.

        Used by autonomous verifiers like D_090 that need to correlate
        a runtime stimulus (e.g. ``am start -a VIEW -d ...``) with the
        UI state it produced. Always returns a tuple — never raises —
        so the caller can keep flowing on adb or screencap failure.

        Args:
            cmd: adb command — string ("shell am start ...") or
                argv list. Anything before the implicit ``adb`` binary
                must NOT be included; this method prepends the runner's
                adb path itself.
            session_id: scan session id for the evidence directory.
            context: short tag for the screenshot filename (e.g.
                ``intent_auth_logged_out``).
            workspace: scan workspace root; the evidence directory
                resolves to ``<workspace>/<session_id>/evidence/
                screenshots/``.
            timeout: per-command timeout in seconds.
            settle_seconds: how long to wait between command return
                and screenshot capture so the UI can transition.

        Returns: ``(stdout, stderr, screenshot_relpath_or_None)``.
        ``screenshot_relpath_or_None`` is ``None`` when the screencap
        failed; ``stderr`` carries the adb error (if any) regardless.
        """
        import shlex

        args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        result = await self._run_adb(args, serial=serial, timeout=int(timeout))
        if result.success and result.data is not None:
            stdout, stderr = result.data.stdout, result.data.stderr
        else:
            stdout, stderr = "", result.error or "adb command failed"

        if settle_seconds > 0:
            await asyncio.sleep(settle_seconds)

        shot = await self.capture_screenshot(
            session_id=session_id,
            filename=context,
            workspace=workspace,
            caption=caption,
            step_index=step_index,
            serial=serial,
        )
        return stdout, stderr, shot.get("path")

    async def execute_and_capture(
        self,
        cmd: str | list[str],
        *,
        serial: Optional[str] = None,
        timeout: float = 10.0,
    ) -> ToolResult[str]:
        """Run an adb command and return formatted stdout/stderr.

        This is intentionally screenshot-free; use
        ``execute_adb_command_and_capture`` when the command should be
        paired with visual evidence.
        """
        import shlex

        args = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        result = await self._run_adb(args, serial=serial, timeout=int(timeout))
        if not result.success or result.data is None:
            return ToolResult.fail(
                result.error or "adb command failed",
                duration=result.duration_seconds,
            )
        output = (
            f"$ adb {' '.join(args)}\n"
            f"[exit_code={result.data.exit_code}]\n"
            f"stdout:\n{result.data.stdout.strip()}\n"
            f"stderr:\n{result.data.stderr.strip()}"
        ).strip()
        return ToolResult.ok(output, duration=result.duration_seconds)

    async def capture_auth_block(
        self,
        package_name: str,
        session_id: str,
        *,
        workspace: Path = Path("workspace"),
        filename: str = "login_block.png",
        serial: Optional[str] = None,
    ) -> ToolResult[str]:
        """Capture the auth/blocking UI state to a deterministic path.

        Saves ``adb exec-out screencap -p`` to
        ``<workspace>/<session_id>/evidence/<filename>`` and returns the
        path relative to ``<workspace>/<session_id>`` so it can be placed
        directly in ``Finding.blocking_state_screenshot``.
        """
        start = time.monotonic()
        if self._missing_reason:
            return ToolResult.fail(
                self._missing_reason, duration=time.monotonic() - start,
            )

        safe_name = Path(filename).name or "login_block.png"
        if not safe_name.lower().endswith(".png"):
            safe_name = f"{safe_name}.png"
        out_dir = workspace / session_id / "evidence"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / safe_name

        cmd = [self._adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(["exec-out", "screencap", "-p"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self._default_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult.fail(
                    "screencap timed out",
                    duration=time.monotonic() - start,
                )
            if proc.returncode or not stdout_bytes:
                return ToolResult.fail(
                    "screencap failed for auth block "
                    f"({package_name}): "
                    f"{stderr_bytes.decode('utf-8', errors='replace')[:200]}",
                    duration=time.monotonic() - start,
                )
            out_path.write_bytes(stdout_bytes)
            rel = out_path.relative_to(workspace / session_id)
            return ToolResult.ok(str(rel), duration=time.monotonic() - start)
        except FileNotFoundError as exc:
            return ToolResult.fail(
                f"adb not found: {exc}", duration=time.monotonic() - start,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("auth-block screencap crashed")
            return ToolResult.from_exception(
                exc, duration=time.monotonic() - start,
            )

    async def verify_deep_link(
        self,
        package: str,
        scheme: str,
        url: str,
        session_id: str,
        *,
        workspace: Path = Path("workspace"),
        serial: Optional[str] = None,
        path: str = "showPage",
        param: str = "url",
        require_auth: bool = False,
        credential_manager: Any = None,
        frida: Any = None,
        settle_seconds: float = 1.0,
        timeout: float = 15.0,
    ) -> ToolResult[RuntimeResult]:
        """Fire a deep link and capture deterministic runtime truth.

        The method intentionally returns booleans instead of prose:
        ``target_reached`` and ``is_auth_gated`` are derived from ADB
        output only. Report/LLM layers may write narrative from these
        hard facts, but should not reinterpret them.
        """
        start = time.monotonic()
        if not package:
            return ToolResult.fail("verify_deep_link requires package")
        if not scheme:
            return ToolResult.fail("verify_deep_link requires scheme")

        if require_auth:
            auth_result = await self._verify_auth_preflight(
                package=package,
                session_id=session_id,
                workspace=workspace,
                serial=serial,
                credential_manager=credential_manager,
                frida=frida,
                timeout=timeout,
                intent_label="deep link",
            )
            if auth_result is not None:
                auth_result.duration_seconds = time.monotonic() - start
                return auth_result

        deep_link = self._build_deep_link_uri(scheme, url, path=path, param=param)
        args = [
            "shell", "am", "start", "-W",
            "-a", "android.intent.action.VIEW",
            "-d", deep_link,
            package,
        ]
        command = f"adb {' '.join(args)}"

        launch = await self._run_adb(args, serial=serial, timeout=int(timeout))
        stdout = launch.data.stdout if launch.success and launch.data else ""
        stderr = launch.data.stderr if launch.success and launch.data else (
            launch.error or "adb am start failed"
        )
        exit_code = launch.data.exit_code if launch.success and launch.data else 1

        if settle_seconds > 0:
            await asyncio.sleep(settle_seconds)

        dumpsys = await self._run_adb(
            ["shell", "dumpsys", "activity", "activities"],
            serial=serial,
            timeout=int(timeout),
        )
        dumpsys_text = dumpsys.data.stdout if dumpsys.success and dumpsys.data else ""
        resumed = self._parse_resumed_activity(dumpsys_text)
        if resumed is None:
            resumed = self._parse_activity_from_am_start(stdout + "\n" + stderr)

        is_auth_gated = self._is_auth_gate_activity(resumed or "")
        target_reached = bool(
            launch.success
            and resumed
            and package in resumed
            and not is_auth_gated
        )
        observed = f"Activity: {resumed}" if resumed else (
            "Activity: <unknown>; "
            f"am_start_stdout={stdout.strip()[:200]}; "
            f"am_start_stderr={stderr.strip()[:200]}"
        )

        screenshot_path: str | None = None
        verification_screenshot: str | None = None
        if is_auth_gated:
            shot = await self.capture_auth_block(
                package,
                session_id,
                workspace=workspace,
                filename="login_block.png",
                serial=serial,
            )
            if shot.success:
                screenshot_path = shot.data
        elif target_reached:
            shot = await self.capture_screenshot(
                session_id=session_id,
                filename="verified_exploited",
                workspace=workspace,
                caption="Runtime target reached after proof command.",
                step_index=1,
                serial=serial,
            )
            verification_screenshot = shot.get("path")

        result = RuntimeResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            observed_result=observed,
            resumed_activity=resumed,
            target_reached=target_reached,
            is_auth_gated=is_auth_gated,
            blocking_state_screenshot=screenshot_path,
            verification_screenshot=verification_screenshot,
            test_credentials_used=bool(require_auth and credential_manager is not None),
            verified_exploited=target_reached,
        )
        success = launch.success and (dumpsys.success or resumed is not None)
        if not success:
            return ToolResult.fail(
                stderr or dumpsys.error or "deep-link verification failed",
                duration=time.monotonic() - start,
            )
        return ToolResult.ok(result, duration=time.monotonic() - start)

    async def verify_component(
        self,
        package: str,
        component: str,
        session_id: str,
        *,
        workspace: Path = Path("workspace"),
        serial: Optional[str] = None,
        action: str | None = None,
        data_uri: str | None = None,
        require_auth: bool = False,
        credential_manager: Any = None,
        frida: Any = None,
        settle_seconds: float = 1.0,
        timeout: float = 15.0,
    ) -> ToolResult[RuntimeResult]:
        """Start an explicit component and capture deterministic proof."""
        start = time.monotonic()
        if not package:
            return ToolResult.fail("verify_component requires package")
        if not component:
            return ToolResult.fail("verify_component requires component")

        if require_auth:
            auth_result = await self._verify_auth_preflight(
                package=package,
                session_id=session_id,
                workspace=workspace,
                serial=serial,
                credential_manager=credential_manager,
                frida=frida,
                timeout=timeout,
                intent_label="component",
            )
            if auth_result is not None:
                auth_result.duration_seconds = time.monotonic() - start
                return auth_result

        component_name = self._normalise_component(package, component)
        args = ["shell", "am", "start", "-W", "-n", component_name]
        if action:
            args.extend(["-a", action])
        if data_uri:
            args.extend(["-d", data_uri])
        command = f"adb {' '.join(args)}"

        launch = await self._run_adb(args, serial=serial, timeout=int(timeout))
        stdout = launch.data.stdout if launch.success and launch.data else ""
        stderr = launch.data.stderr if launch.success and launch.data else (
            launch.error or "adb am start failed"
        )
        exit_code = launch.data.exit_code if launch.success and launch.data else 1

        if settle_seconds > 0:
            await asyncio.sleep(settle_seconds)

        dumpsys = await self._run_adb(
            ["shell", "dumpsys", "activity", "activities"],
            serial=serial,
            timeout=int(timeout),
        )
        dumpsys_text = dumpsys.data.stdout if dumpsys.success and dumpsys.data else ""
        resumed = self._parse_resumed_activity(dumpsys_text)
        if resumed is None:
            resumed = self._parse_activity_from_am_start(stdout + "\n" + stderr)

        is_auth_gated = self._is_auth_gate_activity(resumed or "")
        target_reached = bool(
            launch.success
            and resumed
            and package in resumed
            and not is_auth_gated
        )
        observed = f"Activity: {resumed}" if resumed else (
            "Activity: <unknown>; "
            f"am_start_stdout={stdout.strip()[:200]}; "
            f"am_start_stderr={stderr.strip()[:200]}"
        )

        blocking_screenshot: str | None = None
        verification_screenshot: str | None = None
        if is_auth_gated:
            shot = await self.capture_auth_block(
                package,
                session_id,
                workspace=workspace,
                filename="login_block.png",
                serial=serial,
            )
            if shot.success:
                blocking_screenshot = shot.data
        elif target_reached:
            shot = await self.capture_screenshot(
                session_id=session_id,
                filename="verified_exploited",
                workspace=workspace,
                caption="Runtime component reached after proof command.",
                step_index=1,
                serial=serial,
            )
            verification_screenshot = shot.get("path")

        result = RuntimeResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            observed_result=observed,
            resumed_activity=resumed,
            target_reached=target_reached,
            is_auth_gated=is_auth_gated,
            blocking_state_screenshot=blocking_screenshot,
            verification_screenshot=verification_screenshot,
            test_credentials_used=bool(require_auth and credential_manager is not None),
            verified_exploited=target_reached,
        )
        success = launch.success and (dumpsys.success or resumed is not None)
        if not success:
            return ToolResult.fail(
                stderr or dumpsys.error or "component verification failed",
                duration=time.monotonic() - start,
            )
        return ToolResult.ok(result, duration=time.monotonic() - start)

    async def _verify_auth_preflight(
        self,
        *,
        package: str,
        session_id: str,
        workspace: Path,
        serial: Optional[str],
        credential_manager: Any,
        frida: Any,
        timeout: float,
        intent_label: str,
    ) -> ToolResult[RuntimeResult] | None:
        """Return an Auth_Gated runtime result when auto-login fails."""
        if credential_manager is None:
            return await self._auth_gated_preflight_result(
                package=package,
                session_id=session_id,
                workspace=workspace,
                serial=serial,
                timeout=timeout,
                reason="auto-login required but no credential manager was provided",
                intent_label=intent_label,
                test_credentials_used=False,
            )

        try:
            auth = await credential_manager.auto_login(package, frida=frida)
        except Exception as exc:  # noqa: BLE001
            logger.exception("auto-login preflight crashed")
            return await self._auth_gated_preflight_result(
                package=package,
                session_id=session_id,
                workspace=workspace,
                serial=serial,
                timeout=timeout,
                reason=f"auto-login crashed: {str(exc)[:160]}",
                intent_label=intent_label,
                test_credentials_used=True,
            )

        if getattr(auth, "succeeded", False):
            return None

        reason = str(getattr(auth, "reason", "") or "auto-login did not succeed")
        return await self._auth_gated_preflight_result(
            package=package,
            session_id=session_id,
            workspace=workspace,
            serial=serial,
            timeout=timeout,
            reason=reason,
            intent_label=intent_label,
            test_credentials_used=True,
        )

    async def _auth_gated_preflight_result(
        self,
        *,
        package: str,
        session_id: str,
        workspace: Path,
        serial: Optional[str],
        timeout: float,
        reason: str,
        intent_label: str,
        test_credentials_used: bool,
    ) -> ToolResult[RuntimeResult]:
        dumpsys = await self._run_adb(
            ["shell", "dumpsys", "activity", "activities"],
            serial=serial,
            timeout=int(timeout),
        )
        dumpsys_text = dumpsys.data.stdout if dumpsys.success and dumpsys.data else ""
        resumed = self._parse_resumed_activity(dumpsys_text)
        shot = await self.capture_auth_block(
            package,
            session_id,
            workspace=workspace,
            filename="login_block.png",
            serial=serial,
        )
        screenshot = shot.data if shot.success else None
        activity = resumed or "<unknown>"
        result = RuntimeResult(
            command="",
            stdout=dumpsys_text,
            stderr=reason,
            exit_code=1,
            observed_result=(
                f"Auth_Gated before firing {intent_label}: {reason}; "
                f"Activity: {activity}"
            ),
            resumed_activity=resumed,
            target_reached=False,
            is_auth_gated=True,
            blocking_state_screenshot=screenshot,
            test_credentials_used=test_credentials_used,
        )
        return ToolResult.ok(result)

    @staticmethod
    def _build_deep_link_uri(
        scheme: str,
        url: str,
        *,
        path: str = "showPage",
        param: str = "url",
    ) -> str:
        scheme = scheme.strip()
        normalized_path = (path or "showPage").strip().lstrip("/") or "showPage"
        normalized_param = (param or "url").strip() or "url"
        if "://" in scheme:
            scheme_name, rest = scheme.split("://", 1)
            rest = rest.strip("/")
            prefix = f"{scheme_name}://"
            if rest:
                if rest == normalized_path or rest.endswith(f"/{normalized_path}"):
                    return f"{prefix}{rest}?{normalized_param}={url}"
                return f"{prefix}{rest}/{normalized_path}?{normalized_param}={url}"
            return f"{prefix}{normalized_path}?{normalized_param}={url}"
        return f"{scheme}://{normalized_path}?{normalized_param}={url}"

    @staticmethod
    def _normalise_component(package: str, component: str) -> str:
        component = component.strip()
        if "/" in component:
            return component
        if component.startswith("."):
            return f"{package}/{component}"
        return f"{package}/{component}"

    @staticmethod
    def _parse_resumed_activity(dumpsys_output: str) -> str | None:
        """Extract the foreground component from dumpsys activity output."""
        if not dumpsys_output:
            return None
        patterns = (
            r"mResumedActivity:.*?\s([A-Za-z0-9_.]+/[A-Za-z0-9_.$/]+)",
            r"Resumed:.*?\s([A-Za-z0-9_.]+/[A-Za-z0-9_.$/]+)",
            r"mCurrentFocus=.*?\s([A-Za-z0-9_.]+/[A-Za-z0-9_.$/]+)",
            r"mFocusedApp=.*?\s([A-Za-z0-9_.]+/[A-Za-z0-9_.$/]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, dumpsys_output)
            if match:
                return match.group(1).rstrip("}")
        return None

    @staticmethod
    def _parse_activity_from_am_start(output: str) -> str | None:
        if not output:
            return None
        match = re.search(
            r"(?:cmp=|Activity:\s*)([A-Za-z0-9_.]+/[A-Za-z0-9_.$/]+)",
            output,
        )
        return match.group(1).rstrip("}") if match else None

    @staticmethod
    def _is_auth_gate_activity(activity: str) -> bool:
        return bool(re.search(r"(login|auth|splash)", activity or "", re.I))

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
