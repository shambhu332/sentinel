"""Autonomous UI driver — exercises a target app so DAST agents see traffic.

Without a driver, SENTINEL's dynamic phase depends on a human touching the
device to generate API calls that mitmproxy can capture. The
:class:`UIDriver` protocol lets the orchestrator drive the app itself so
Phase 4 (mitmproxy + Frida) and Phase 7.5 (API replay + exploitation)
have real traffic to work with.

Three implementations ship today:

* :class:`NoOpUIDriver` — the default. Does nothing; relies on a human
  or a pre-captured JSONL. Guaranteed side-effect-free.
* :class:`MonkeyUIDriver` — invokes ``adb shell monkey`` with a bounded,
  non-destructive event mix (no syskey / anyevent presses, high
  throttle). Cheap to run against any Android build, but blind — it
  can't log in or navigate to a specific screen.
* :class:`AppiumUIDriver` — placeholder. Raises ``NotImplementedError``;
  the real Appium wiring is a follow-up.

**Safety invariants** encoded in the base class:

* Every method is best-effort. ``launch_and_login`` and ``execute_flow``
  return ``bool`` and swallow exceptions so a driver crash falls back to
  ``Auth_Gated`` instead of killing the scan.
* No driver may write to the device beyond the operations the concrete
  implementation names. ``MonkeyUIDriver`` is scoped to a specific
  package via ``-p`` so events can't leak into other apps.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Sequence

logger = logging.getLogger(__name__)


# ---------- Public data types ----------

@dataclass
class UICredentials:
    """Test credentials for automated login.

    ``username`` / ``password`` are the plain values; the credential
    manager already redacts them from logs. ``extra`` lets flow scripts
    carry MFA seeds or per-app metadata without needing new fields.
    """

    username: str
    password: str
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class UIDriverResult:
    """Structured outcome of a driver run.

    ``ok`` is the summary bit the orchestrator branches on. ``events``
    stores a short human-readable trace (script name, step count, monkey
    seed) so the report can attribute captured traffic to a specific
    driver invocation.
    """

    ok: bool
    driver_name: str
    events: list[str] = field(default_factory=list)
    reason: str | None = None


# ---------- Base class ----------

class UIDriver(ABC):
    """Protocol every UI driver implementation follows.

    Lifecycle:
        1. ``setup()`` — one-shot pre-run checks (adb present, device
           available, target package installed).
        2. ``launch_and_login()`` — bring the app to a state where API
           calls can flow. Optional; drivers without credentials just
           launch the main activity.
        3. ``execute_flow(duration_sec)`` — the actual driving. Runs
           concurrently with mitmproxy so every action generates traffic.
        4. ``teardown()`` — always called, even on failure. Ensures the
           device is left in a clean state.
    """

    #: Human-readable name for reports / events. Subclasses override.
    name: str = "ui-driver"

    def __init__(
        self,
        *,
        target_package: str,
        serial: str | None = None,
        adb_path: str | None = None,
    ) -> None:
        self._target_package = target_package
        self._serial = serial
        self._adb_path = adb_path or shutil.which("adb") or "adb"
        self._events: list[str] = []

    # ---------- Lifecycle ----------

    async def setup(self) -> bool:
        """Return True when the driver is ready.

        Base implementation confirms adb is on PATH and a device is
        visible. Subclasses that need more (e.g. Appium server, WebDriver
        session) override and call ``super().setup()`` first.
        """
        if not self._adb_path:
            logger.info("[ui-driver] adb not found; falling back to no-op")
            return False
        available = await self._device_visible()
        if not available:
            logger.info("[ui-driver] no adb device visible; falling back to no-op")
        return available

    @abstractmethod
    async def launch_and_login(
        self, credentials: UICredentials | None,
    ) -> bool:
        """Bring the app to an authenticated (or at least launched) state.

        Return True on success; False (never raise) if login couldn't be
        completed. A False here is what causes the orchestrator to mark
        affected findings ``Auth_Gated``.
        """

    @abstractmethod
    async def execute_flow(self, duration_sec: int) -> UIDriverResult:
        """Exercise the app for ``duration_sec`` seconds.

        Return a :class:`UIDriverResult` describing what happened. Runs
        concurrently with mitmproxy, so cheap network-generating actions
        (form fills, list scrolls) matter more than depth.
        """

    async def teardown(self) -> None:
        """Best-effort cleanup. Never raises."""
        # Base has no state to clean; subclasses override if needed.
        return

    # ---------- Helpers ----------

    async def _device_visible(self) -> bool:
        """True if ``adb devices`` reports at least one online device."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._adb_path, "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            return False
        for line in stdout.decode("utf-8", errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                if self._serial is None or parts[0] == self._serial:
                    return True
        return False

    async def _adb(self, args: Sequence[str], *, timeout: float = 30.0) -> tuple[int, str, str]:
        """Run ``adb [-s serial] ...`` and return (code, stdout, stderr).

        Never raises. Timeout returns exit code ``-1`` with a stderr
        note; missing binary returns ``-1`` with a "not found" note.
        """
        cmd: list[str] = [self._adb_path]
        if self._serial:
            cmd.extend(["-s", self._serial])
        cmd.extend(list(args))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            return -1, "", f"adb spawn failed: {exc}"
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, "", f"adb timed out after {timeout}s"
        return (
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )


# ---------- Concrete implementations ----------

class NoOpUIDriver(UIDriver):
    """Driver that does nothing.

    Correct choice when the operator will exercise the app manually or
    when the capture is being replayed from a pre-recorded JSONL. Every
    method returns successfully so the orchestrator's happy path stays
    unchanged.
    """

    name = "noop"

    async def setup(self) -> bool:
        return True

    async def launch_and_login(
        self, credentials: UICredentials | None,
    ) -> bool:
        return True

    async def execute_flow(self, duration_sec: int) -> UIDriverResult:
        return UIDriverResult(
            ok=True,
            driver_name=self.name,
            events=[
                f"noop driver: waiting {duration_sec}s for external activity",
            ],
        )


class MonkeyUIDriver(UIDriver):
    """Fires ``adb shell monkey`` with a bounded, non-destructive event mix.

    Trade-off spelled out for the reader: monkey generates blind
    pseudo-random events — cheap, wide, but unable to log in or navigate
    to a specific screen. Use it to shake out easy API calls; for real
    depth wire :class:`AppiumUIDriver` later.

    Safety flags baked in:

    * ``-p <target_package>`` scopes events to the target — nothing leaks
      into other apps.
    * ``--pct-syskeys 0`` — no volume/back/power key spam.
    * ``--pct-anyevent 0`` — no crash-inducing raw events.
    * ``--throttle`` (ms between events) — set to a floor of 300 ms so
      even a 500-event run gives mitmproxy time to complete flows.
    * ``--kill-process-after-error`` — stop cleanly on the first crash so
      we don't spend a full ``duration_sec`` firing into a dead process.
    """

    name = "monkey"

    #: Cap on total event count regardless of duration. Keeps runs
    #: bounded even when ``duration_sec`` is set aggressively.
    MAX_EVENTS = 500
    #: Floor on inter-event delay (ms). Below this, monkey outpaces
    #: mitmproxy's async pipeline and traffic gets truncated.
    MIN_THROTTLE_MS = 300

    def __init__(
        self,
        *,
        target_package: str,
        serial: str | None = None,
        adb_path: str | None = None,
        seed: int | None = None,
        throttle_ms: int | None = None,
        event_count: int | None = None,
    ) -> None:
        super().__init__(
            target_package=target_package,
            serial=serial,
            adb_path=adb_path,
        )
        self._seed = seed
        self._throttle_ms = max(
            self.MIN_THROTTLE_MS,
            throttle_ms or self.MIN_THROTTLE_MS,
        )
        self._event_count = min(
            self.MAX_EVENTS,
            event_count or self.MAX_EVENTS,
        )

    async def launch_and_login(
        self, credentials: UICredentials | None,
    ) -> bool:
        """Bring the app to the foreground via the launcher intent.

        Monkey can't type credentials — if ``credentials`` is provided we
        note it but leave login to the caller (typically the Frida-driven
        ``credential_manager``). The activity launch itself is enough to
        get network calls flowing.
        """
        code, _, stderr = await self._adb([
            "shell", "monkey",
            "-p", self._target_package,
            "-c", "android.intent.category.LAUNCHER",
            "1",
        ])
        if code != 0:
            logger.info(
                "[monkey] launcher intent failed: %s",
                (stderr or "").strip()[:200],
            )
            return False
        if credentials is not None:
            self._events.append(
                "monkey cannot type credentials — login left to credential_manager",
            )
        return True

    async def execute_flow(self, duration_sec: int) -> UIDriverResult:
        """Fire a bounded monkey run against the target package.

        The event count is capped by :attr:`MAX_EVENTS`, but effectively
        also by ``duration_sec * 1000 / throttle_ms`` — whichever comes
        first. If adb crashes mid-run we mark the result not-ok but keep
        the trace so the report can explain what happened.
        """
        # Derive event count from duration so the driver respects the
        # dynamic-phase budget; still cap at MAX_EVENTS.
        events_from_duration = max(
            10, int((duration_sec * 1000) / self._throttle_ms),
        )
        events = min(self._event_count, events_from_duration)
        cmd: list[str] = [
            "shell", "monkey",
            "-p", self._target_package,
            "--throttle", str(self._throttle_ms),
            "--pct-syskeys", "0",
            "--pct-anyevent", "0",
            "--kill-process-after-error",
            "-v",
        ]
        if self._seed is not None:
            cmd.extend(["-s", str(self._seed)])
        cmd.append(str(events))
        code, stdout, stderr = await self._adb(
            cmd, timeout=duration_sec + 30.0,
        )
        summary = f"monkey fired {events} events (throttle {self._throttle_ms}ms)"
        self._events.append(summary)
        if code != 0:
            reason = (stderr or stdout).strip().splitlines()[-1:] or [
                f"monkey exited {code}"
            ]
            return UIDriverResult(
                ok=False,
                driver_name=self.name,
                events=self._events,
                reason=reason[0][:200],
            )
        return UIDriverResult(
            ok=True,
            driver_name=self.name,
            events=self._events,
        )


class AppiumUIDriver(UIDriver):
    """Appium-backed UI driver — not yet implemented.

    ``setup()`` returns False so the orchestrator falls back to no-op
    traffic capture instead of crashing the scan. Swap in a real
    Appium client here when the wiring lands.
    """

    name = "appium"

    async def setup(self) -> bool:
        logger.warning(
            "[ui-driver] AppiumUIDriver is not yet implemented. "
            "Falling back to no-op capture. Use --ui-driver monkey for automated traffic."
        )
        return False

    async def launch_and_login(
        self, credentials: UICredentials | None,
    ) -> bool:
        return False

    async def execute_flow(self, duration_sec: int) -> UIDriverResult:
        return UIDriverResult(
            ok=False,
            driver_name=self.name,
            reason="AppiumUIDriver not implemented — no traffic generated",
        )


# ---------- Factory ----------

_DRIVER_REGISTRY: dict[str, type[UIDriver]] = {
    "off": NoOpUIDriver,
    "noop": NoOpUIDriver,
    "monkey": MonkeyUIDriver,
    "appium": AppiumUIDriver,
}


def build_driver(
    kind: str,
    *,
    target_package: str,
    serial: str | None = None,
    **kwargs: Any,
) -> UIDriver:
    """Instantiate the driver named by ``kind`` (``"off"|"monkey"|"appium"``).

    Unknown values fall through to :class:`NoOpUIDriver` so a typo in the
    CLI flag never kills the scan; the orchestrator logs the fallback so
    operators notice.
    """
    cls = _DRIVER_REGISTRY.get(kind.lower())
    if cls is None:
        logger.warning(
            "[ui-driver] unknown driver %r; falling back to noop", kind,
        )
        cls = NoOpUIDriver
    return cls(target_package=target_package, serial=serial, **kwargs)
