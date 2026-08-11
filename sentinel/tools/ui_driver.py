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
* :class:`AppiumUIDriver` — full Appium + UIAutomator2 driver. Works
  across any Android app without app-specific scripts. Detects login
  fields automatically, types credentials, navigates and scrolls. Requires
  ``Appium-Python-Client`` (``pip install Appium-Python-Client``) and an
  Appium server running on localhost (``appium --port 4723``).

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
    """Appium + UIAutomator2 driver — works across any Android app.

    Does not need app-specific scripts. UIAutomator2 is system-level so it
    can inspect and interact with any installed app's UI hierarchy.

    Login strategy (tried in order for each field):
      1. XPath attribute match (hint, content-desc, text) against known labels
      2. Resource-id substring match against known labels
      3. Position fallback (first / second EditText, etc.)

    Navigation strategy:
      Alternates between scroll-down, tap-button, scroll-up, and
      tap-random-interactive on a fixed cadence so mitmproxy sees a broad
      variety of API calls during the dynamic phase.

    Prerequisites:
      * ``pip install Appium-Python-Client``
      * Appium server: ``npm install -g appium && appium driver install uiautomator2``
      * Start server: ``appium --port 4723``
    """

    name = "appium"

    DEFAULT_SERVER_URL = "http://127.0.0.1:4723"

    # UIAutomator2 class names
    _CLASS_EDIT   = "android.widget.EditText"
    _CLASS_BUTTON = "android.widget.Button"
    _CLASS_TEXT   = "android.widget.TextView"
    _CLASS_IMGBTN = "android.widget.ImageButton"
    _CLASS_VIEW   = "android.view.View"

    # Keywords used to identify login fields across different apps
    _USERNAME_HINTS: frozenset[str] = frozenset({
        "email", "username", "user name", "user_name", "phone",
        "login", "user", "userid", "account", "mobile", "id",
        "identifier", "number",
    })
    _PASSWORD_HINTS: frozenset[str] = frozenset({
        "password", "passwd", "pass", "pin", "secret",
        "passcode", "passphrase",
    })
    _LOGIN_BUTTON_TEXTS: frozenset[str] = frozenset({
        "log in", "login", "sign in", "signin", "submit",
        "continue", "next", "enter", "proceed", "go",
        "connect", "access",
    })

    # Swipe geometry as fractions of screen height
    _SCROLL_START_FRAC = 0.75
    _SCROLL_END_FRAC   = 0.25

    # Seconds between explore actions
    _EXPLORE_STEP_INTERVAL = 1.5

    def __init__(
        self,
        *,
        target_package: str,
        serial: str | None = None,
        adb_path: str | None = None,
        server_url: str | None = None,
        connect_timeout: int = 30,
        appium_caps: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            target_package=target_package,
            serial=serial,
            adb_path=adb_path,
        )
        self._server_url    = server_url or self.DEFAULT_SERVER_URL
        self._connect_timeout = connect_timeout
        self._extra_caps    = appium_caps or {}
        self._appium_driver: Any = None   # appium.webdriver.Remote session
        self._screen_w      = 0
        self._screen_h      = 0

    # ------------------------------------------------------------------ setup

    async def setup(self) -> bool:
        """Connect to Appium server and create a UIAutomator2 session."""
        try:
            import appium  # noqa: F401 — presence check only
        except ImportError:
            logger.warning(
                "[appium] Appium-Python-Client not installed. "
                "Run: pip install Appium-Python-Client"
            )
            return False

        if not await self._ping_appium():
            logger.warning(
                "[appium] Server not reachable at %s. "
                "Start it with: appium --port 4723",
                self._server_url,
            )
            return False

        if not await self._device_visible():
            logger.warning("[appium] No adb device visible")
            return False

        loop = asyncio.get_event_loop()
        try:
            session = await loop.run_in_executor(None, self._create_session)
        except Exception as exc:
            logger.warning("[appium] Session creation failed: %s", exc)
            return False

        self._appium_driver = session
        size = await loop.run_in_executor(
            None, session.get_window_size,
        )
        self._screen_w = size.get("width", 1080)
        self._screen_h = size.get("height", 1920)
        logger.info(
            "[appium] Session ready. Screen: %dx%d package=%s",
            self._screen_w, self._screen_h, self._target_package,
        )
        return True

    def _create_session(self) -> Any:
        """Synchronous — runs in executor thread."""
        from appium import webdriver as appium_wd
        from appium.options.android import UiAutomator2Options

        opts = UiAutomator2Options()
        opts.platform_name        = "Android"
        opts.automation_name      = "UiAutomator2"
        opts.app_package          = self._target_package
        opts.no_reset             = True
        opts.auto_launch          = True
        opts.new_command_timeout  = 120
        if self._serial:
            opts.udid = self._serial
        for key, val in self._extra_caps.items():
            setattr(opts, key, val)

        return appium_wd.Remote(
            self._server_url,
            options=opts,
            keep_alive=True,
        )

    async def _ping_appium(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self._server_url}/status")
                return r.status_code == 200
        except Exception:
            return False

    # ---------------------------------------------------------------- teardown

    async def teardown(self) -> None:
        if self._appium_driver is not None:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._appium_driver.quit)
            except Exception:
                pass
            self._appium_driver = None

    # --------------------------------------------------------- launch_and_login

    async def launch_and_login(
        self, credentials: UICredentials | None,
    ) -> bool:
        """Auto-detect login fields, type credentials, tap the login button.

        Works against any app — no hardcoded resource IDs needed.
        """
        if self._appium_driver is None:
            return False
        if credentials is None:
            self._events.append("no credentials — launching without login")
            return True

        loop = asyncio.get_event_loop()
        try:
            ok = await loop.run_in_executor(
                None, self._sync_login, credentials,
            )
            return ok
        except Exception as exc:
            logger.warning("[appium] launch_and_login crashed: %s", exc)
            self._events.append(f"login crashed: {exc!s:.120}")
            return False

    def _sync_login(self, creds: UICredentials) -> bool:
        """Synchronous login flow — runs in executor thread."""
        import time
        from appium.webdriver.common.appiumby import AppiumBy

        drv = self._appium_driver

        # Let the app settle after launch
        time.sleep(2)

        # --- username ---
        u_field = self._locate_username_field(drv, AppiumBy)
        if u_field is None:
            logger.warning("[appium] username field not found")
            self._events.append("login: username field not found")
            return False
        try:
            u_field.clear()
            u_field.send_keys(creds.username)
            self._events.append("login: username entered")
        except Exception as exc:
            logger.warning("[appium] username input failed: %s", exc)
            return False

        self._safe_hide_keyboard(drv)

        # --- password ---
        p_field = self._locate_password_field(drv, AppiumBy)
        if p_field is None:
            logger.warning("[appium] password field not found")
            self._events.append("login: password field not found")
            return False
        try:
            p_field.click()
            p_field.clear()
            p_field.send_keys(creds.password)
            self._events.append("login: password entered")
        except Exception as exc:
            logger.warning("[appium] password input failed: %s", exc)
            return False

        self._safe_hide_keyboard(drv)

        # --- login button ---
        btn = self._locate_login_button(drv, AppiumBy)
        if btn is not None:
            try:
                btn.click()
                self._events.append("login: login button tapped")
            except Exception as exc:
                logger.warning("[appium] login button tap failed: %s", exc)
                # Fall through to Enter key
                btn = None

        if btn is None:
            try:
                from selenium.webdriver.common.keys import Keys
                p_field.send_keys(Keys.ENTER)
                self._events.append("login: sent Enter key (no button found)")
            except Exception:
                return False

        # Wait for post-login screen transition
        time.sleep(3)
        self._events.append("login: done — waiting for authenticated screen")
        return True

    # --- element finders -------------------------------------------------------

    @staticmethod
    def _xpath_contains_lower(attr: str, value: str) -> str:
        """XPATH 1.0 case-insensitive contains expression."""
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower = "abcdefghijklmnopqrstuvwxyz"
        return (
            f'contains(translate(@{attr},"{upper}","{lower}"),"{value}")'
        )

    def _locate_username_field(self, drv: Any, AppiumBy: Any) -> Any:
        """Multi-strategy username field detection."""
        # 1. Match by visible text attributes (hint / content-desc / text)
        for hint in self._USERNAME_HINTS:
            for attr in ("hint", "content-desc", "text"):
                expr = self._xpath_contains_lower(attr, hint)
                try:
                    el = drv.find_element(
                        AppiumBy.XPATH,
                        f"//android.widget.EditText[{expr}]",
                    )
                    return el
                except Exception:
                    pass

        # 2. Match by resource-id substring
        for hint in self._USERNAME_HINTS:
            expr = self._xpath_contains_lower("resource-id", hint)
            try:
                els = drv.find_elements(
                    AppiumBy.XPATH,
                    f"//android.widget.EditText[{expr}]",
                )
                if els:
                    return els[0]
            except Exception:
                pass

        # 3. First non-password EditText on screen
        try:
            fields = drv.find_elements(AppiumBy.CLASS_NAME, self._CLASS_EDIT)
            for f in fields:
                if f.get_attribute("password") != "true" and f.is_displayed():
                    return f
        except Exception:
            pass

        return None

    def _locate_password_field(self, drv: Any, AppiumBy: Any) -> Any:
        """Multi-strategy password field detection."""
        # 1. inputType = password (most reliable)
        try:
            el = drv.find_element(
                AppiumBy.XPATH,
                '//android.widget.EditText[@password="true"]',
            )
            if el.is_displayed():
                return el
        except Exception:
            pass

        # 2. Match by hint / content-desc / text
        for hint in self._PASSWORD_HINTS:
            for attr in ("hint", "content-desc", "text"):
                expr = self._xpath_contains_lower(attr, hint)
                try:
                    el = drv.find_element(
                        AppiumBy.XPATH,
                        f"//android.widget.EditText[{expr}]",
                    )
                    return el
                except Exception:
                    pass

        # 3. Resource-id substring
        for hint in self._PASSWORD_HINTS:
            expr = self._xpath_contains_lower("resource-id", hint)
            try:
                els = drv.find_elements(
                    AppiumBy.XPATH,
                    f"//android.widget.EditText[{expr}]",
                )
                if els:
                    return els[0]
            except Exception:
                pass

        # 4. Second EditText (username=1st, password=2nd is the most common layout)
        try:
            fields = drv.find_elements(AppiumBy.CLASS_NAME, self._CLASS_EDIT)
            visible = [f for f in fields if f.is_displayed()]
            if len(visible) >= 2:
                return visible[1]
        except Exception:
            pass

        return None

    def _locate_login_button(self, drv: Any, AppiumBy: Any) -> Any:
        """Multi-strategy login button detection."""
        for text in self._LOGIN_BUTTON_TEXTS:
            for cls in (self._CLASS_BUTTON, self._CLASS_TEXT):
                for attr in ("text", "content-desc"):
                    expr = self._xpath_contains_lower(attr, text)
                    try:
                        el = drv.find_element(
                            AppiumBy.XPATH,
                            f"//{cls}[{expr}]",
                        )
                        if el.is_displayed() and el.is_enabled():
                            return el
                    except Exception:
                        pass
        return None

    @staticmethod
    def _safe_hide_keyboard(drv: Any) -> None:
        try:
            drv.hide_keyboard()
        except Exception:
            pass

    # ----------------------------------------------------------- execute_flow

    async def execute_flow(self, duration_sec: int) -> UIDriverResult:
        """Smart scroll + tap loop for ``duration_sec`` seconds.

        Alternates between four actions so the app exposes a broad
        surface of API calls to mitmproxy:
          0 → scroll down (reveal more content / lazy-loaded API calls)
          1 → tap a visible Button
          2 → scroll up  (trigger refresh / pull-to-refresh endpoints)
          3 → tap a random interactive element (TextView, ImageButton, etc.)
        """
        if self._appium_driver is None:
            return UIDriverResult(
                ok=False,
                driver_name=self.name,
                reason="Appium session not initialised",
            )

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: self._sync_explore(duration_sec),
            )
            return UIDriverResult(
                ok=True,
                driver_name=self.name,
                events=list(self._events),
            )
        except Exception as exc:
            logger.warning("[appium] execute_flow crashed: %s", exc)
            return UIDriverResult(
                ok=False,
                driver_name=self.name,
                events=list(self._events),
                reason=str(exc)[:200],
            )

    def _sync_explore(self, duration_sec: int) -> None:
        import time
        from appium.webdriver.common.appiumby import AppiumBy
        import random

        deadline = time.monotonic() + duration_sec
        step = 0

        while time.monotonic() < deadline:
            action = step % 4
            try:
                if action == 0:
                    self._scroll_down()
                    self._events.append(f"step {step}: scrolled down")
                elif action == 1:
                    tapped = self._tap_visible_button(AppiumBy, random)
                    label = "tapped button" if tapped else "no button found"
                    self._events.append(f"step {step}: {label}")
                elif action == 2:
                    self._scroll_up()
                    self._events.append(f"step {step}: scrolled up")
                elif action == 3:
                    tapped = self._tap_random_interactive(AppiumBy, random)
                    label = "tapped element" if tapped else "no element found"
                    self._events.append(f"step {step}: {label}")
            except Exception as exc:
                logger.debug("[appium] explore step %d skipped: %s", step, exc)

            step += 1
            time.sleep(self._EXPLORE_STEP_INTERVAL)

    # --- scroll / tap helpers --------------------------------------------------

    def _scroll_down(self) -> None:
        if not self._screen_h:
            return
        mid_x  = self._screen_w // 2
        start_y = int(self._screen_h * self._SCROLL_START_FRAC)
        end_y   = int(self._screen_h * self._SCROLL_END_FRAC)
        self._appium_driver.swipe(mid_x, start_y, mid_x, end_y, duration=600)

    def _scroll_up(self) -> None:
        if not self._screen_h:
            return
        mid_x  = self._screen_w // 2
        start_y = int(self._screen_h * self._SCROLL_END_FRAC)
        end_y   = int(self._screen_h * self._SCROLL_START_FRAC)
        self._appium_driver.swipe(mid_x, start_y, mid_x, end_y, duration=600)

    def _tap_visible_button(self, AppiumBy: Any, rng: Any) -> bool:
        btns = self._appium_driver.find_elements(
            AppiumBy.CLASS_NAME, self._CLASS_BUTTON,
        )
        visible = [b for b in btns if b.is_displayed() and b.is_enabled()]
        if not visible:
            return False
        rng.choice(visible).click()
        return True

    def _tap_random_interactive(self, AppiumBy: Any, rng: Any) -> bool:
        candidates: list[Any] = []
        for cls in (self._CLASS_TEXT, self._CLASS_IMGBTN, self._CLASS_VIEW):
            els = self._appium_driver.find_elements(AppiumBy.CLASS_NAME, cls)
            candidates.extend(
                e for e in els if e.is_displayed() and e.is_enabled()
            )
        if not candidates:
            return False
        rng.choice(candidates).click()
        return True


# ---------- Factory ----------

_DRIVER_REGISTRY: dict[str, type[UIDriver]] = {
    "off": NoOpUIDriver,
    "noop": NoOpUIDriver,
    "monkey": MonkeyUIDriver,
    "appium": AppiumUIDriver,
}

# kwargs accepted only by specific drivers; stripped before passing to others
_APPIUM_KWARGS = frozenset({"server_url", "connect_timeout", "appium_caps"})
_MONKEY_KWARGS = frozenset({"seed", "throttle_ms", "event_count"})


def build_driver(
    kind: str,
    *,
    target_package: str,
    serial: str | None = None,
    **kwargs: Any,
) -> UIDriver:
    """Instantiate the driver named by ``kind`` (``"off"|"monkey"|"appium"``).

    Driver-specific kwargs (e.g. ``server_url`` for Appium, ``seed`` for
    Monkey) are forwarded only to the matching driver so callers can pass
    a merged config dict without worrying about unknown-kwarg errors.

    Unknown ``kind`` values fall through to :class:`NoOpUIDriver` — a typo
    in the CLI flag never kills the scan; the orchestrator logs the fallback.
    """
    key = kind.lower()
    cls = _DRIVER_REGISTRY.get(key)
    if cls is None:
        logger.warning(
            "[ui-driver] unknown driver %r; falling back to noop", kind,
        )
        cls = NoOpUIDriver
        key = "noop"

    # Strip kwargs that don't belong to this driver to avoid TypeError
    if key == "appium":
        filtered = {k: v for k, v in kwargs.items() if k in _APPIUM_KWARGS}
    elif key == "monkey":
        filtered = {k: v for k, v in kwargs.items() if k in _MONKEY_KWARGS}
    else:
        filtered = {}

    return cls(target_package=target_package, serial=serial, **filtered)
