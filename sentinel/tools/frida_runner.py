"""Frida wrapper — runtime instrumentation of Android apps.

Frida lets us hook arbitrary Java/native methods at runtime, observing
(and optionally modifying) values that static analysis cannot see:
- Actual algorithm passed to Cipher.getInstance() at runtime
- Whether cert pinning code paths execute
- Sensitive data flowing through methods that never appear in logs

Architecture:
1. We use the USB-connected Android device (frida.get_usb_device)
2. A standalone frida-server runs at /data/local/tmp/frida-server on
   the phone (Frida 16.x — Frida 17 removed the built-in Java bridge)
3. We attach to the target app's process AFTER it has been started
4. We inject a JS hook script; the script sends events back via the
   message protocol; each event is recorded in a FridaCapture

Frida version note: this project targets the Frida 16.x line.
Frida 17 (April 2025) removed the built-in Java bridge from the
default agent. Moving to Frida 17 with a bundled frida-java-bridge
is a future enhancement.

PID lookup strategy (in order):
1. Device.enumerate_applications() — primary, gives identifier + pid
2. Device.enumerate_processes() — fallback for daemons/sub-processes
3. `adb shell pidof <package>` — tertiary, bypasses Frida enumeration
   entirely. Necessary on Samsung kernels with strict YAMA ptrace
   restrictions where Frida's full-process iteration trips on a single
   ptrace-protected process and fails the whole enumerate call, even
   when attaching to a single known PID would work fine.

Attach retry note: frida-server can occasionally drop a connection
during attach, especially under load. We retry the attach call a few
times before giving up.

Hook script note: each hook script is wrapped in an IIFE that polls
for Java bridge availability before calling Java.perform(). This makes
the script resilient to runtime-init timing on slow targets and
forward-compatible with bundled-bridge setups on Frida 17+.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)


# Path to the compiled Frida agent (frida_agent/dist/_agent.js).
# Resolved at import time; sentinel/tools/frida_runner.py -> repo root
# is parents[2].
_AGENT_PATH = (
    Path(__file__).resolve().parents[2] / "frida_agent" / "dist" / "_agent.js"
)


@dataclass
class FridaHookEvent:
    """A single event captured from a Frida hook.

    The 'kind' field discriminates between hook types so agents can filter:
    - "crypto.cipher": from Cipher.getInstance hook (A_003)
    - "crypto.digest": from MessageDigest.getInstance hook (A_003)
    - "crypto.keygen": from KeyGenerator.getInstance hook (A_003)
    - "crypto.hooks_installed": diagnostic, crypto hooks loaded successfully
    - "tls.pin_check": from cert pinning check hooks (N_005)
    - "tls.bypass": when a pin check is bypassed by our script (N_005)
    - "tls.bypass_failed": pinning library present but bypass setup failed
    - "tls.hooks_installed": diagnostic, lists pinning libraries hooked
    - "clipboard.write": ClipboardManager.setPrimaryClip (D_001)
    - "clipboard.read": ClipboardManager.getPrimaryClip (D_001)
    - "ui.sensitive_input_seen": EditText with password/PIN input type (D_002)
    - "ui.window_flags": Window.setFlags/addFlags with secure flag state (D_002)
    - "biometric.prompt": BiometricPrompt.Builder configuration (D_003)
    - "tamper.root_check": File.exists/Runtime.exec for root indicators (D_004)
    - "tamper.emulator_check": Build.* / SystemProperties.get reads (D_004)
    - "tamper.integrity_check": PackageManager.getPackageInfo signatures (D_004)
    - "tamper.debugger_check": Debug.isDebuggerConnected (D_004)
    - "code_loading.dex_load": Dex/Path/InMemoryDexClassLoader (D_005)
    - "code_loading.native_load": System.load (D_005)
    - "code_loading.exec": Runtime.exec (D_005)
    - "crypto.iv_constructed": IvParameterSpec/GCMParameterSpec ctor (D_006)
    - "crypto.secret_key_created": SecretKeySpec ctor (D_006)
    - "billing.purchase_observed": Purchase ctor seen (D_008)
    - "billing.feature_unlock": acknowledgePurchase / feature unlock (D_008)
    - "webview.js_interface_added": WebView.addJavascriptInterface (D_011)
    - "webview.load": WebView.loadUrl (D_011)
    - "webview.settings": WebSettings setters of interest (D_011)
    - "webview.debugging": setWebContentsDebuggingEnabled (D_011)
    - "notification.posted": NotificationManager.notify (D_012)
    - "intent.dispatched": Context.startActivity / sendBroadcast / etc (D_015)
    - "a11y.event_observed": AccessibilityService.onAccessibilityEvent (D_016)
    - "a11y.action_performed": AccessibilityNodeInfo.performAction (D_016)
    - "notif_listener.notification_received": NotificationListener.onNotificationPosted (D_016)
    - "sms.broadcast_received": BroadcastReceiver.onReceive on SMS_RECEIVED (D_018)
    - "sms.content_provider_query": ContentResolver.query on content://sms (D_018)
    - "sms.retriever_started": SmsRetrieverClient.startSmsRetriever (D_018)
    - "screen.projection_started": MediaProjectionManager.getMediaProjection (D_019)
    - "screen.virtual_display_created": MediaProjection.createVirtualDisplay (D_019)
    - "screen.image_reader_used": ImageReader.acquireLatestImage / Next (D_019)
    - "screen.media_recorder_set_video_source": MediaRecorder.setVideoSource (D_019)
    - "receiver.dynamic_registered": Context.registerReceiver (D_020)
    - "pending_intent.created": PendingIntent.getActivity / etc. (D_021)
    - "local_socket.server_created": LocalServerSocket.<init> (D_022)
    - "provider.uri_opened": ContentResolver.openFileDescriptor (D_023)
    - "provider.query_returned": ContentResolver.query cursor leak (D_023)
    - "file_provider.uri_minted": FileProvider.getUriForFile (D_024)
    - "location.update_requested": requestLocationUpdates (D_025)
    - "keystore.key_spec_built": KeyGenParameterSpec$Builder.build (D_026)
    - "zip.entry_observed": ZipInputStream.getNextEntry / ZipFile.getEntry (D_027)
    - "zip.entry_extracted": FileOutputStream.<init> in a Zip read stack (D_027)
    - "random.observation": Random / Math RNG consumption (D_028)
    - "tls.hostname_verifier_invoked": custom HostnameVerifier.verify (D_029)
    - "apk_install.committed": PackageInstaller$Session.commit (D_030)
    - "reflection.class_forname": Class.forName(String) (D_031)
    - "json.deserialize_called": Gson/Moshi/Jackson deserializer (D_031)
    - "sqlite.query_executed": SQLiteDatabase.rawQuery / execSQL / query (D_032)
    - "reflection.method_invoked": Method.invoke (D_033)
    - "reflection.constructor_invoked": Constructor.newInstance (D_033)
    - "activity.set_result": Activity.setResult (D_034)
    - "log.line_emitted": Log.* / FileOutputStream.<init> (D_035)
    - "clipboard.read_observed": ClipboardManager.getPrimaryClip (D_036)
    - "error": something went wrong inside the script
    """
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class FridaCapture:
    """Result of a Frida hooking session."""
    events: list[FridaHookEvent]
    duration_seconds: float
    target_package: str
    target_pid: int
    script_errors: list[str] = field(default_factory=list)


class FridaRunner:
    """Async wrapper for Frida USB-device instrumentation."""

    # Number of times to retry the actual attach() call if frida-server
    # drops the connection.
    ATTACH_RETRY_COUNT = 3
    ATTACH_RETRY_DELAY_SECONDS = 2.0

    # Timeout for the adb pidof fallback in _find_pid.
    ADB_PIDOF_TIMEOUT_SECONDS = 5.0

    def __init__(self) -> None:
        self._device: Any = None
        self._session: Any = None
        self._script: Any = None
        self._target_package: str = ""
        self._target_pid: int = 0
        self._events: list[FridaHookEvent] = []
        self._script_errors: list[str] = []
        self._events_lock = asyncio.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._start_time: float = 0
        self._spawned: bool = False
        self._frida_unavailable_reason: Optional[str] = None
        try:
            import frida  # noqa: F401
        except ImportError as e:
            self._frida_unavailable_reason = (
                f"frida python library not installed: {e}"
            )

    async def attach(
        self,
        package: str,
        spawn: bool = False,
    ) -> ToolResult[dict]:
        """Attach to or spawn the named package on the USB device.

        When spawn=True, force-stops the target via `adb shell am
        force-stop` and starts it under Frida control (paused). The
        caller MUST call resume() after inject_script() returns to let
        the app actually start. Use spawn mode for apps with anti-Frida
        detection at startup; use the default attach mode for
        already-running apps you want to introspect without disrupting.
        """
        if self._frida_unavailable_reason:
            return ToolResult.fail(self._frida_unavailable_reason)

        self._target_package = package
        self._events = []
        self._script_errors = []
        self._start_time = time.monotonic()
        self._spawned = False
        self._loop = asyncio.get_event_loop()

        try:
            import frida

            self._device = await self._loop.run_in_executor(
                None, frida.get_usb_device, 5000,
            )
            logger.info(
                "Frida device: %s (%s)",
                self._device.name, self._device.type,
            )

            # Preflight: client lib major must match server major.
            # Frida 17 dropped the built-in Java bridge that every hook
            # in frida_agent/src/ uses. Mismatch = silent zero-event
            # captures, which makes N_005 falsely report "no pinning
            # bypassed" on apps that are actually trivially bypassable.
            version_warning = await self._loop.run_in_executor(
                None, self._check_version_compatibility,
            )
            if version_warning:
                logger.warning("FRIDA VERSION PREFLIGHT: %s", version_warning)
                self._script_errors.append(
                    f"version_preflight: {version_warning}"
                )

            if spawn:
                return await self._spawn_and_attach(package)

            pid: Optional[int] = None
            for attempt in range(1, 6):
                pid = await self._loop.run_in_executor(
                    None, self._find_pid, package,
                )
                if pid is not None:
                    if attempt > 1:
                        logger.info(
                            "Frida: found %s after %d attempts",
                            package, attempt,
                        )
                    break
                await asyncio.sleep(1.0)

            if pid is None:
                diag = await self._loop.run_in_executor(
                    None, self._diag_processes, package,
                )
                return ToolResult.fail(
                    f"Package '{package}' not running on device after "
                    f"5s of retries. {diag}. "
                    f"Likely causes: screen timeout backgrounded the app, "
                    f"Android OOM-killed it, or it crashed at launch. "
                    f"Fix: set screen timeout to 10+ minutes and keep the "
                    f"app actively in foreground throughout the entire scan.",
                )
            self._target_pid = pid

            last_err: Optional[BaseException] = None
            for attempt in range(1, self.ATTACH_RETRY_COUNT + 1):
                try:
                    self._session = await self._loop.run_in_executor(
                        None, self._device.attach, pid,
                    )
                    last_err = None
                    if attempt > 1:
                        logger.info(
                            "Frida: attached to PID %d on attempt %d",
                            pid, attempt,
                        )
                    break
                except frida.ServerNotRunningError as e:
                    last_err = e
                    logger.warning(
                        "Frida attach attempt %d/%d failed: "
                        "frida-server connection closed (%s) — "
                        "retrying in %.1fs",
                        attempt, self.ATTACH_RETRY_COUNT, e,
                        self.ATTACH_RETRY_DELAY_SECONDS,
                    )
                    if attempt < self.ATTACH_RETRY_COUNT:
                        await asyncio.sleep(self.ATTACH_RETRY_DELAY_SECONDS)
                except (frida.ProcessNotFoundError,
                        frida.NotSupportedError) as e:
                    last_err = e
                    break
                except Exception as e:  # noqa: BLE001
                    last_err = e
                    logger.warning(
                        "Frida attach attempt %d/%d failed: %s — retrying",
                        attempt, self.ATTACH_RETRY_COUNT, e,
                    )
                    if attempt < self.ATTACH_RETRY_COUNT:
                        await asyncio.sleep(self.ATTACH_RETRY_DELAY_SECONDS)

            if last_err is not None:
                if isinstance(last_err, frida.ServerNotRunningError):
                    return ToolResult.fail(
                        f"Frida attach to PID {pid} failed after "
                        f"{self.ATTACH_RETRY_COUNT} retries: "
                        f"frida-server on the device is not reachable. "
                        f"Fix: restart it with `adb shell \"su -c "
                        f"'nohup /data/local/tmp/frida-server "
                        f">/dev/null 2>&1 &'\"`.",
                    )
                if isinstance(last_err, frida.NotSupportedError):
                    return ToolResult.fail(
                        f"Frida attach to PID {pid} failed: "
                        f"{last_err}. This usually means the device's "
                        f"kernel restricts ptrace. Try: "
                        f"`adb shell \"su -c 'echo 0 > "
                        f"/proc/sys/kernel/yama/ptrace_scope; "
                        f"setenforce 0'\"`.",
                    )
                return ToolResult.fail(
                    f"Frida attach to PID {pid} failed: "
                    f"{type(last_err).__name__}: {last_err}",
                )

            logger.info("Frida attached to %s (pid %d)", package, pid)
            return ToolResult.ok({
                "package": package,
                "pid": pid,
                "device": self._device.name,
            })
        except Exception as e:  # noqa: BLE001
            logger.exception("Frida attach failed")
            return ToolResult.from_exception(
                e, duration=time.monotonic() - self._start_time,
            )

    async def _spawn_and_attach(self, package: str) -> ToolResult[dict]:
        """Force-stop the target, then spawn it paused and attach.

        The spawned PID stays paused until resume() is called by the
        caller — typically right after inject_script() loads the hooks.
        """
        import frida

        adb = shutil.which("adb")
        if adb is not None:
            try:
                subprocess.run(
                    [adb, "shell", "am", "force-stop", package],
                    capture_output=True,
                    timeout=5,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Frida spawn: am force-stop %s failed: %s "
                    "(continuing anyway)", package, e,
                )

        try:
            pid = await self._loop.run_in_executor(
                None, self._device.spawn, [package],
            )
            self._target_pid = pid
            self._spawned = True
            self._session = await self._loop.run_in_executor(
                None, self._device.attach, pid,
            )
            logger.info(
                "Frida spawn: %s started paused at PID %d",
                package, pid,
            )
            return ToolResult.ok({
                "package": package,
                "pid": pid,
                "device": self._device.name,
                "mode": "spawn",
            })
        except frida.NotSupportedError as e:
            return ToolResult.fail(
                f"Frida spawn of '{package}' not supported on this "
                f"device: {e}. Many vendor-customised kernels disallow "
                f"spawn-from-Frida — fall back to attach mode and "
                f"launch the app manually before scanning.",
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("Frida spawn failed")
            return ToolResult.from_exception(e)

    async def resume(self) -> ToolResult[str]:
        """Resume a spawned process. No-op after a regular attach()."""
        if not self._spawned:
            return ToolResult.ok("not spawned, nothing to resume")
        if self._device is None or self._target_pid <= 0:
            return ToolResult.fail("no active spawned session to resume")
        try:
            await self._loop.run_in_executor(
                None, self._device.resume, self._target_pid,
            )
            logger.info(
                "Frida: resumed spawned PID %d (%s)",
                self._target_pid, self._target_package,
            )
            return ToolResult.ok("resumed")
        except Exception as e:  # noqa: BLE001
            logger.exception("Frida resume failed")
            return ToolResult.from_exception(e)

    async def inject_script(self, script_source: str) -> ToolResult[str]:
        """Compile and load a Frida JS hook script."""
        if self._session is None:
            return ToolResult.fail("No active Frida session — call attach() first")
        if self._frida_unavailable_reason:
            return ToolResult.fail(self._frida_unavailable_reason)

        try:
            self._script = await self._loop.run_in_executor(
                None, self._session.create_script, script_source,
            )
            self._script.on("message", self._on_message)
            await self._loop.run_in_executor(None, self._script.load)
            logger.info("Frida script loaded for %s", self._target_package)
            return ToolResult.ok("script_loaded")
        except Exception as e:  # noqa: BLE001
            logger.exception("Frida script injection failed")
            return ToolResult.from_exception(e)

    async def wait(self, seconds: int) -> None:
        """Wait while hooks collect events. User interacts with the app."""
        logger.info("Frida: collecting events for %ds", seconds)
        await asyncio.sleep(seconds)

    async def detach(self) -> ToolResult[FridaCapture]:
        """Detach and return all captured events."""
        duration = time.monotonic() - self._start_time

        if self._script is not None:
            try:
                await self._loop.run_in_executor(None, self._script.unload)
            except Exception as e:  # noqa: BLE001
                logger.warning("Script unload failed: %s", e)

        if self._session is not None:
            try:
                await self._loop.run_in_executor(None, self._session.detach)
            except Exception as e:  # noqa: BLE001
                logger.warning("Session detach failed: %s", e)

        async with self._events_lock:
            events_copy = list(self._events)

        capture = FridaCapture(
            events=events_copy,
            duration_seconds=duration,
            target_package=self._target_package,
            target_pid=self._target_pid,
            script_errors=list(self._script_errors),
        )

        logger.info(
            "Frida: captured %d events in %.1fs (%d errors)",
            len(events_copy), duration, len(self._script_errors),
        )

        self._script = None
        self._session = None
        self._device = None
        self._spawned = False

        return ToolResult.ok(capture, duration=duration)

    # ---------- Internals ----------

    def _check_version_compatibility(self) -> Optional[str]:
        """Return a warning string when client and server majors differ.

        Returns None on success (compatible or undeterminable). The
        check is best-effort: if we cannot read either side's version,
        we proceed and trust the user. The intent is to catch the
        common deployment trap where Frida 17 binaries are pushed but
        the Python lib is pinned to 16.x (or vice versa).
        """
        try:
            import frida
            client_ver = getattr(frida, "__version__", "") or ""
            client_major = client_ver.split(".", 1)[0]
            if not client_major.isdigit():
                return None

            # Try the modern API first
            server_ver = ""
            try:
                params = self._device.query_system_parameters()
                if isinstance(params, dict):
                    for key in ("frida-version", "version", "agent-version"):
                        v = params.get(key)
                        if isinstance(v, str) and v:
                            server_ver = v
                            break
            except Exception:  # noqa: BLE001
                pass

            # Older API surface
            if not server_ver:
                v = getattr(self._device, "version", "")
                if isinstance(v, str):
                    server_ver = v

            if not server_ver:
                return None

            server_major = server_ver.split(".", 1)[0]
            if not server_major.isdigit():
                return None

            if server_major != client_major:
                return (
                    f"frida client lib is {client_ver} but device "
                    f"frida-server is {server_ver}. Major versions must "
                    f"match — Frida 17 dropped the built-in Java bridge "
                    f"that all SENTINEL hooks use. With this mismatch, "
                    f"Java.use(...) will throw inside the hook script "
                    f"and N_005 cert-pinning-bypass + A_003 runtime-crypto "
                    f"will capture zero events (silent false negatives). "
                    f"Fix: install a frida-server binary matching the "
                    f"client major ({client_major}.x) or upgrade the "
                    f"client to match the server."
                )
        except Exception:  # noqa: BLE001
            logger.debug("Frida version preflight could not run", exc_info=True)
        return None

    def _find_pid(self, package: str) -> Optional[int]:
        """Find the running PID for an Android package.

        Strategy (in order):
        1. Device.enumerate_applications() — identifier-based lookup.
           Most reliable when it works.
        2. Device.enumerate_processes() — process-name lookup, used
           for daemons and sub-processes that don't appear as apps.
        3. `adb shell pidof <package>` — bypasses Frida entirely.
           Required on devices where Frida's enumeration hits ptrace
           I/O errors due to YAMA restrictions or vendor-hardened
           processes that refuse introspection. Attaching to a single
           known PID still works on these devices — only the
           iterate-everything enumerate calls fail.
        """
        try:
            # ---- Primary: Frida enumerate_applications ----
            try:
                apps = list(self._device.enumerate_applications())
                for app in apps:
                    pid = getattr(app, "pid", 0)
                    if app.identifier == package and pid > 0:
                        return pid
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Frida enumerate_applications failed (%s) — "
                    "falling back to enumerate_processes",
                    e,
                )

            # ---- Secondary: Frida enumerate_processes ----
            try:
                procs = list(self._device.enumerate_processes())
                for proc in procs:
                    if proc.name == package:
                        return proc.pid
                for proc in procs:
                    if proc.name.startswith(package + ":"):
                        logger.warning(
                            "Frida: main UI for %s not running; attaching "
                            "to sub-process %s (PID %d). Some hooks may "
                            "not fire.",
                            package, proc.name, proc.pid,
                        )
                        return proc.pid
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Frida enumerate_processes failed (%s) — "
                    "falling back to adb pidof",
                    e,
                )

            # ---- Tertiary: adb pidof ----
            adb_pid = self._pid_via_adb(package)
            if adb_pid is not None:
                logger.info(
                    "Frida _find_pid: found %s via adb pidof (PID %d). "
                    "Frida's process enumeration is unavailable on this "
                    "device — likely YAMA ptrace restrictions.",
                    package, adb_pid,
                )
                return adb_pid

            # ---- All three failed — log diagnostic info ----
            self._log_similar_processes(package)

        except Exception:  # noqa: BLE001
            logger.exception("_find_pid failed")
        return None

    def _pid_via_adb(self, package: str) -> Optional[int]:
        """Get the PID of a package via `adb shell pidof`.

        Doesn't use Frida at all — just calls adb directly. Used when
        Frida's process enumeration is failing but the device is
        otherwise reachable.
        """
        adb = shutil.which("adb")
        if adb is None:
            logger.warning("adb not in PATH — cannot use pidof fallback")
            return None
        try:
            result = subprocess.run(
                [adb, "shell", "pidof", package],
                capture_output=True,
                text=True,
                timeout=self.ADB_PIDOF_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                logger.debug(
                    "adb pidof %s returned rc=%d, stderr=%r",
                    package, result.returncode, result.stderr.strip(),
                )
                return None
            pids_str = result.stdout.strip()
            if not pids_str:
                return None
            # pidof may return multiple PIDs for multi-process apps,
            # space-separated. The first one is typically the main UI
            # process which is what we want for Java hooks.
            first = pids_str.split()[0]
            if first.isdigit():
                return int(first)
        except subprocess.TimeoutExpired:
            logger.warning("adb pidof %s timed out", package)
        except Exception as e:  # noqa: BLE001
            logger.warning("adb pidof %s failed: %s", package, e)
        return None

    def _log_similar_processes(self, package: str) -> None:
        """Log apps/processes resembling the package name for diagnostics."""
        keywords = [p for p in package.split(".") if len(p) > 3]
        if not keywords:
            return
        similar: list[str] = []
        try:
            for app in self._device.enumerate_applications():
                pid = getattr(app, "pid", 0)
                if pid <= 0:
                    continue
                ident_lower = app.identifier.lower()
                if any(kw.lower() in ident_lower for kw in keywords):
                    similar.append(
                        f"app: {app.identifier} "
                        f"(pid {pid}, label={app.name!r})"
                    )
        except Exception:  # noqa: BLE001
            pass
        try:
            for proc in self._device.enumerate_processes():
                lower = proc.name.lower()
                if any(kw.lower() in lower for kw in keywords):
                    similar.append(f"proc: {proc.name} (pid {proc.pid})")
        except Exception:  # noqa: BLE001
            pass
        if similar:
            logger.warning(
                "Frida _find_pid: '%s' not found via any method. "
                "Similar entries: %s",
                package, "; ".join(similar[:8]),
            )

    def _diag_processes(self, package: str) -> str:
        """Return a short string describing what's running, for error messages.

        Scans applications, processes, and (as a final fallback) the adb
        process list so the error message contains useful info regardless
        of which enumeration mechanism is currently working.
        """
        keywords = [p for p in package.split(".") if len(p) > 3]
        if not keywords:
            return "no usable keywords from package name"

        # First: matching applications (identifier-based — most reliable)
        try:
            apps = list(self._device.enumerate_applications())
            running_apps = []
            for app in apps:
                pid = getattr(app, "pid", 0)
                if pid <= 0:
                    continue
                ident_lower = app.identifier.lower()
                if any(kw.lower() in ident_lower for kw in keywords):
                    running_apps.append(
                        f"{app.identifier}(pid {pid}, label={app.name!r})"
                    )
            if running_apps:
                return "matching applications: " + ", ".join(
                    running_apps[:6],
                )
        except Exception as e:  # noqa: BLE001
            logger.debug("enumerate_applications failed in _diag: %s", e)

        # Second: matching processes (name-based)
        try:
            procs = list(self._device.enumerate_processes())
            similar = []
            for proc in procs:
                lower = proc.name.lower()
                if any(kw.lower() in lower for kw in keywords):
                    similar.append(f"{proc.name}(pid {proc.pid})")
            if similar:
                return "matching processes: " + ", ".join(similar[:6])
        except Exception as e:  # noqa: BLE001
            logger.debug("enumerate_processes failed in _diag: %s", e)

        # Third: adb pidof as final probe
        try:
            adb_pid = self._pid_via_adb(package)
            if adb_pid is not None:
                return (
                    f"adb sees {package} at pid {adb_pid} "
                    f"but Frida cannot enumerate it (likely YAMA ptrace "
                    f"restriction — try `setenforce 0` and `echo 0 > "
                    f"/proc/sys/kernel/yama/ptrace_scope`)"
                )
        except Exception:  # noqa: BLE001
            pass

        return (
            f"no application or process matching: "
            f"{' or '.join(keywords)} found via Frida or adb"
        )

    def _on_message(self, message: dict, data: Any) -> None:
        """Callback invoked by Frida for every message from the script."""
        try:
            if message.get("type") == "error":
                err = message.get("description", "?")
                stack = message.get("stack", "")
                self._script_errors.append(f"{err}\n{stack}")
                logger.warning("Frida script error: %s", err)
                return

            if message.get("type") != "send":
                return

            payload = message.get("payload", {})
            if not isinstance(payload, dict):
                payload = {"raw": str(payload)}

            kind = payload.get("kind", "unknown")
            event = FridaHookEvent(
                kind=kind,
                payload=payload,
                timestamp=time.time(),
            )

            future = asyncio.run_coroutine_threadsafe(
                self._append_event(event), self._loop,
            )
            future.add_done_callback(self._log_append_errors)

        except Exception:  # noqa: BLE001
            logger.exception("_on_message handler crashed")

    async def _append_event(self, event: FridaHookEvent) -> None:
        async with self._events_lock:
            self._events.append(event)

    @staticmethod
    def _log_append_errors(future: Any) -> None:
        try:
            future.result()
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to append Frida event: %s", e)


# ---------- Compiled Frida agent loader ----------
#
# The actual hook code now lives in frida_agent/src/*.ts and is
# compiled to frida_agent/dist/_agent.js via frida-compile. That
# artifact is checked into the repo so users without Node.js can
# still run SENTINEL — Python never invokes Node.js at runtime.
#
# When dist/_agent.js is missing (e.g. during development before the
# first build), we fall back to a tiny crypto-only inline script and
# log a warning so the developer knows pinning hooks are disabled
# until they rebuild.

_FALLBACK_INLINE_HOOK = r"""
/* Minimal fallback when frida_agent/dist/_agent.js is missing.
 * Only Cipher.getInstance(String) is hooked — enough to satisfy
 * A_003's crypto observation but no pinning bypass coverage.
 */
(function() {
    function setup() {
        try {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.getInstance.overload('java.lang.String').implementation =
                function(t) {
                    send({kind: 'crypto.cipher', algorithm: t,
                          overload: 'string'});
                    return this.getInstance(t);
                };
            send({kind: 'crypto.hooks_installed',
                  count: 1, fallback: true});
        } catch(err) {
            send({kind: 'error',
                  message: 'fallback: ' + err.toString()});
        }
    }
    if (typeof Java !== 'undefined' && Java.available) {
        Java.perform(setup);
    } else {
        var attempts = 0;
        var poll = setInterval(function() {
            attempts++;
            if (typeof Java !== 'undefined' && Java.available) {
                clearInterval(poll);
                Java.perform(setup);
            } else if (attempts >= 30) {
                clearInterval(poll);
                send({kind: 'error',
                      message: 'fallback: Java unavailable after 3s'});
            }
        }, 100);
    }
})();
"""


def load_runtime_hooks() -> str:
    """Return the contents of the compiled Frida agent.

    Reads frida_agent/dist/_agent.js if present. Falls back to a
    minimal crypto-only inline script (with a logged warning) when
    the file is missing — keeps SENTINEL functional during
    development before the agent has been built.
    """
    if _AGENT_PATH.exists():
        return _AGENT_PATH.read_text(encoding="utf-8")
    logger.warning(
        "Compiled Frida agent not found at %s — using fallback "
        "inline hook (crypto-only, no pinning). Build the agent with: "
        "cd frida_agent && npm install && npm run build",
        _AGENT_PATH,
    )
    return _FALLBACK_INLINE_HOOK


# Public alias preserved for the orchestrator and any external callers
# that imported the constant directly. Resolved at import time so the
# warning, if any, fires once per process rather than per scan.
ALL_RUNTIME_HOOKS = load_runtime_hooks()
