"""Frida wrapper — runtime instrumentation of Android apps.

Frida lets us hook arbitrary Java/native methods at runtime, observing
(and optionally modifying) values that static analysis cannot see:
- Actual algorithm passed to Cipher.getInstance() at runtime
- Whether cert pinning code paths execute
- Sensitive data flowing through methods that never appear in logs

Architecture:
1. We use the USB-connected Android device (frida.get_usb_device)
2. zygiskfrida (already installed on the phone) auto-injects Frida into
   every spawned app — so we don't need to manually push/start frida-server
3. We attach to the target app's process AFTER it has been started
4. We inject a JS hook script; the script sends events back to us via
   the message protocol
5. Each event is recorded in a list and returned as a FridaCapture

Crash-proof: all operations return ToolResult. Hook crashes don't kill
the scan — they're logged as warnings and the rest of the pipeline
proceeds.

Threading note: Frida's Python API is callback-based. We bridge it to
asyncio by collecting messages in a list with a lock, and exposing the
collected events when the caller calls stop().

Process lookup note: Frida's Device.enumerate_processes() returns each
running process by *name*, which on Android is frequently the app's
display label ("Signal", "campus 4.0", "WhatsApp"), not the package
identifier ("org.thoughtcrime.securesms", "com.global.edu.campus",
"com.whatsapp"). Matching the package name against process.name is
unreliable across vendors and versions. We use
Device.enumerate_applications() — which exposes the identifier (package
name) alongside the pid — as the primary lookup, and fall back to
process-name matching only for non-app processes and edge cases.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)


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
    - "tls.bypass_failed": pinning library present but bypass setup failed,
      indicating the app resists our generic bypass (N_005 "survived" signal)
    - "tls.hooks_installed": diagnostic, lists pinning libraries successfully
      hooked during the session (N_005)
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
        self._frida_unavailable_reason: Optional[str] = None
        try:
            import frida  # noqa: F401
        except ImportError as e:
            self._frida_unavailable_reason = (
                f"frida python library not installed: {e}"
            )

    async def attach(self, package: str) -> ToolResult[dict]:
        """Attach to the named package on the USB device.

        Requires the package to be currently running on the device.
        Returns a dict with package, pid, device name.
        """
        if self._frida_unavailable_reason:
            return ToolResult.fail(self._frida_unavailable_reason)

        self._target_package = package
        self._events = []
        self._script_errors = []
        self._start_time = time.monotonic()
        self._loop = asyncio.get_event_loop()

        try:
            import frida

            # Get USB-connected Android device
            self._device = await self._loop.run_in_executor(
                None, frida.get_usb_device, 5000,
            )
            logger.info(
                "Frida device: %s (%s)",
                self._device.name, self._device.type,
            )

            # Find the PID for our package. With zygiskfrida, gadget injection
            # happens automatically when the app starts, so we just need to
            # attach to the already-running process. We retry a few times
            # because the orchestrator's start_app may return success while
            # the app process is still initialising (race window of 1-2s).
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
                # Get diagnostic info: what processes WERE running?
                # This surfaces in scan_result.warnings so the user can
                # see exactly what was on the device when attach failed.
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

            # Attach to the process
            self._session = await self._loop.run_in_executor(
                None, self._device.attach, pid,
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

    async def inject_script(self, script_source: str) -> ToolResult[str]:
        """Compile and load a Frida JS hook script.

        The script's send() calls become Python message events that we
        record. Call this AFTER attach(), BEFORE the user interacts
        with the app, so the hooks are live before any sensitive
        operation happens.
        """
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

        # Clean up — best effort
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

        # Reset state
        self._script = None
        self._session = None
        self._device = None

        return ToolResult.ok(capture, duration=duration)

    # ---------- Internals ----------

    def _find_pid(self, package: str) -> Optional[int]:
        """Find the running PID for an Android package.

        Strategy:
        1. Primary — Device.enumerate_applications(): returns Application
           objects with .identifier (package name like
           "org.thoughtcrime.securesms"), .name (display label like
           "Signal"), and .pid (running pid, or 0 if not running). This
           is the right API for matching by package name.
        2. Fallback — Device.enumerate_processes(): returns Process
           objects with .name (process name, frequently the display
           label on Android, not the package identifier). Used to catch
           daemons, sub-processes, and vendor-specific cases that don't
           appear as Applications.

        On previous versions this method only used enumerate_processes()
        and matched by process.name, which silently failed whenever
        Android reported the process name as the app's display label
        (e.g. "Signal" vs "org.thoughtcrime.securesms"). That was the
        root cause of every "Package not running on device" warning
        users hit during Sprint 8.2 Part B real-device validation.
        """
        try:
            # ---- Primary: identifier-based lookup ----
            try:
                apps = list(self._device.enumerate_applications())
                for app in apps:
                    pid = getattr(app, "pid", 0)
                    if app.identifier == package and pid > 0:
                        return pid
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Frida enumerate_applications failed: %s — "
                    "falling back to process enumeration",
                    e,
                )

            # ---- Fallback: process-name match ----
            procs = list(self._device.enumerate_processes())

            # Pass 1: exact match on process name (main UI process when
            # Android happens to report it as the package name)
            for proc in procs:
                if proc.name == package:
                    return proc.pid

            # Pass 2: sub-process match (e.g. package:messaging, package:gcm).
            # Frida can hook these for some classes of events, though the
            # main UI is preferred.
            for proc in procs:
                if proc.name.startswith(package + ":"):
                    logger.warning(
                        "Frida: main UI for %s not running; attaching to "
                        "sub-process %s (PID %d). Some hooks may not fire.",
                        package, proc.name, proc.pid,
                    )
                    return proc.pid

            # ---- Diagnostic: log anything that looks related ----
            # Pull keywords from the package name and scan both apps
            # and processes for substring matches. The most likely cause
            # of reaching this branch is that the app's identifier in
            # enumerate_applications doesn't exactly match `package`
            # (vendor remapping, alias, etc.) — having both views helps.
            keywords = [p for p in package.split(".") if len(p) > 3]
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
            for proc in procs:
                lower = proc.name.lower()
                if any(kw.lower() in lower for kw in keywords):
                    similar.append(f"proc: {proc.name} (pid {proc.pid})")
            if similar:
                logger.warning(
                    "Frida _find_pid: '%s' not found via either application "
                    "identifier or process name. Similar entries: %s",
                    package, "; ".join(similar[:8]),
                )

        except Exception:  # noqa: BLE001
            logger.exception("_find_pid failed")
        return None

    def _diag_processes(self, package: str) -> str:
        """Return a short string describing what's running, for error messages.

        Scans both the application list (identifier-based) and the
        process list (name-based) so the diagnostic surfaces whichever
        view actually contains useful information for the user.
        """
        try:
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
                logger.warning(
                    "enumerate_applications failed in _diag: %s", e,
                )

            # Second: matching processes (name-based fallback)
            procs = list(self._device.enumerate_processes())
            similar = []
            for proc in procs:
                lower = proc.name.lower()
                if any(kw.lower() in lower for kw in keywords):
                    similar.append(f"{proc.name}(pid {proc.pid})")
            if similar:
                return "matching processes: " + ", ".join(similar[:6])

            return (
                f"no application or process matching: "
                f"{' or '.join(keywords)}"
            )
        except Exception as e:  # noqa: BLE001
            return f"could not enumerate processes/apps: {e}"

    def _on_message(self, message: dict, data: Any) -> None:
        """Callback invoked by Frida for every message from the script.

        Called from Frida's thread, not the asyncio loop. We schedule the
        coroutine on the loop via run_coroutine_threadsafe.
        """
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
                # Some scripts send raw strings; normalize
                payload = {"raw": str(payload)}

            kind = payload.get("kind", "unknown")
            event = FridaHookEvent(
                kind=kind,
                payload=payload,
                timestamp=time.time(),
            )

            # Schedule the append on the asyncio loop in a thread-safe way
            future = asyncio.run_coroutine_threadsafe(
                self._append_event(event), self._loop,
            )
            # Don't block here — fire and forget. If append fails, log it.
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


# ---------- Pre-built hook scripts ----------

# A_003 — Cipher.getInstance hook
CIPHER_GETINSTANCE_HOOK = r"""
/*
 * SENTINEL Frida hook -- javax.crypto.Cipher.getInstance
 *
 * Logs every Cipher.getInstance() call to detect weak algorithms in
 * actual runtime use (vs just declared in code). Catches DES, RC4,
 * MD5, ECB mode, and other weak constructs.
 */
Java.perform(function() {
    try {
        var Cipher = Java.use('javax.crypto.Cipher');

        // Cipher.getInstance(String transformation)
        Cipher.getInstance.overload('java.lang.String').implementation = function(t) {
            send({
                kind: 'crypto.cipher',
                algorithm: t,
                overload: 'string'
            });
            return this.getInstance(t);
        };

        // Cipher.getInstance(String, String)
        Cipher.getInstance.overload(
            'java.lang.String', 'java.lang.String'
        ).implementation = function(t, p) {
            send({
                kind: 'crypto.cipher',
                algorithm: t,
                provider: p,
                overload: 'string_string'
            });
            return this.getInstance(t, p);
        };

        // Cipher.getInstance(String, Provider)
        Cipher.getInstance.overload(
            'java.lang.String', 'java.security.Provider'
        ).implementation = function(t, p) {
            send({
                kind: 'crypto.cipher',
                algorithm: t,
                provider: p ? p.getName() : 'null',
                overload: 'string_provider'
            });
            return this.getInstance(t, p);
        };

        // MessageDigest.getInstance -- catches MD5, SHA-1 in actual use
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(a) {
            send({
                kind: 'crypto.digest',
                algorithm: a
            });
            return this.getInstance(a);
        };

        // KeyGenerator.getInstance -- catches weak key generation
        try {
            var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
            KeyGenerator.getInstance.overload('java.lang.String').implementation = function(a) {
                send({
                    kind: 'crypto.keygen',
                    algorithm: a
                });
                return this.getInstance(a);
            };
        } catch(e) {
            // Some apps shrink this class out, ignore
        }

        send({kind: 'crypto.hooks_installed', count: 4});
    } catch(err) {
        send({kind: 'error', message: 'crypto hooks: ' + err.toString()});
    }
});
"""


# N_005 — Certificate Pinning Bypass hook
#
# Attempts to bypass every major Android cert-pinning library at runtime.
# For each library:
#   - Java.use(class) fails  -> library not in app, silently skip
#   - Java.use(class) succeeds + replacement runs -> tls.bypass event (= bug)
#   - Java.use(class) succeeds but hook setup throws -> tls.bypass_failed
#     event (= pinning survived our generic bypass)
#
# Libraries covered:
#   - okhttp3.CertificatePinner (canonical OkHttp pinning)
#   - android.net.http.X509TrustManagerExtensions (Android TrustManager)
#   - android.webkit.WebViewClient.onReceivedSslError (WebView SSL bypass)
#   - com.datatheorem.android.trustkit (TrustKit library)
#   - org.conscrypt.Platform (Conscrypt, modern Android)
#   - okhttp3.internal.tls.OkHostnameVerifier (hostname checks)
#
# WebView limitation: this hooks the BASE WebViewClient class. Apps that
# subclass WebViewClient and override onReceivedSslError will not be
# intercepted by this hook alone. Hooking subclasses generically requires
# Java.choose or class-load instrumentation, deferred to a future sprint.
CERT_PINNING_BYPASS_HOOK = r"""
Java.perform(function() {
    var installed = [];

    function tryHook(label, fn) {
        try {
            fn();
            installed.push(label);
        } catch(e) {
            var msg = e.toString();
            // ClassNotFoundException = library simply isn't in the app -> skip
            if (msg.indexOf("ClassNotFoundException") !== -1) {
                return;
            }
            // Anything else after class load = pinning library is present
            // but our bypass attempt failed (overload mismatch, anti-Frida,
            // obfuscation). Emit a 'survived' signal.
            send({
                kind: 'tls.bypass_failed',
                library: label,
                error: msg
            });
        }
    }

    // ---- OkHttp CertificatePinner ----
    tryHook('okhttp.CertificatePinner', function() {
        var Pinner = Java.use('okhttp3.CertificatePinner');
        // check(String, List)
        Pinner.check.overload(
            'java.lang.String', 'java.util.List'
        ).implementation = function(hostname, certs) {
            send({
                kind: 'tls.bypass',
                library: 'okhttp.CertificatePinner',
                method: 'check(String, List)',
                host: hostname
            });
            // no-op: skip pin validation
        };
        // Optional: check$okhttp on Kotlin internal name (newer versions)
        try {
            Pinner['check$okhttp'].overload(
                'java.lang.String', 'kotlin.jvm.functions.Function0'
            ).implementation = function(hostname, fn) {
                send({
                    kind: 'tls.bypass',
                    library: 'okhttp.CertificatePinner',
                    method: 'check$okhttp',
                    host: hostname
                });
            };
        } catch(e) {
            // older OkHttp without this overload — fine
        }
    });

    // ---- X509TrustManagerExtensions (Android system) ----
    tryHook('X509TrustManager', function() {
        var TMExt = Java.use('android.net.http.X509TrustManagerExtensions');
        TMExt.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ).implementation = function(chain, authType, host) {
            send({
                kind: 'tls.bypass',
                library: 'X509TrustManager',
                method: 'X509TrustManagerExtensions.checkServerTrusted',
                host: host
            });
            // Return an empty list — caller iterates the chain, empty is safe
            return Java.use('java.util.Collections').emptyList();
        };
    });

    // ---- WebViewClient ----
    tryHook('WebViewClient.onReceivedSslError', function() {
        var WVC = Java.use('android.webkit.WebViewClient');
        WVC.onReceivedSslError.implementation = function(view, handler, error) {
            var url = '';
            try { url = error ? error.getUrl() : ''; } catch(e) {}
            send({
                kind: 'tls.bypass',
                library: 'WebViewClient.onReceivedSslError',
                method: 'onReceivedSslError',
                host: url
            });
            handler.proceed();  // accept the bad cert
        };
    });

    // ---- TrustKit ----
    tryHook('TrustKit', function() {
        var TK = Java.use(
            'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier'
        );
        TK.verify.overload(
            'java.lang.String', 'javax.net.ssl.SSLSession'
        ).implementation = function(hostname, session) {
            send({
                kind: 'tls.bypass',
                library: 'TrustKit',
                method: 'OkHostnameVerifier.verify',
                host: hostname
            });
            return true;
        };
    });

    // ---- Conscrypt Platform (modern Android) ----
    tryHook('Conscrypt.Platform', function() {
        var Plat = Java.use('org.conscrypt.Platform');
        Plat.checkServerTrusted.overload(
            'javax.net.ssl.X509TrustManager',
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'javax.net.ssl.SSLSession'
        ).implementation = function(tm, chain, authType, session) {
            send({
                kind: 'tls.bypass',
                library: 'Conscrypt.Platform',
                method: 'checkServerTrusted',
                host: ''
            });
            // no-op
        };
    });

    // ---- OkHostnameVerifier ----
    tryHook('HostnameVerifier', function() {
        var OKHV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OKHV.verify.overload(
            'java.lang.String', 'javax.net.ssl.SSLSession'
        ).implementation = function(hostname, session) {
            send({
                kind: 'tls.bypass',
                library: 'HostnameVerifier',
                method: 'OkHostnameVerifier.verify',
                host: hostname
            });
            return true;
        };
    });

    // ---- Final diagnostic ----
    send({
        kind: 'tls.hooks_installed',
        libraries: installed,
        count: installed.length
    });
});
"""


# Aggregate of all hook scripts injected during Phase 4.5.
# Multiple Java.perform blocks coexist fine in one script — each block
# independently sets up its hooks, and a failure in one does not stop
# the others.
ALL_RUNTIME_HOOKS = CIPHER_GETINSTANCE_HOOK + "\n\n" + CERT_PINNING_BYPASS_HOOK
