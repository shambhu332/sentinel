"""Pre-scan environment self-check.

Before kicking off a real DAST run, the operator wants to know: is
the device reachable, is frida-server running at a compatible
version, are the bundled login scripts on disk, are test credentials
configured? Running 88 dynamic agents against a half-wired
environment produces silent zero-event failures.

Usage::

    python -m sentinel.tools.preflight
    python -m sentinel.tools.preflight --serial emulator-5554

Exits 0 when every check passes, 1 otherwise. Each check is
independent — one failure does not short-circuit the rest, so the
report shows everything that needs fixing.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str

    def render(self) -> str:
        marker = "OK  " if self.ok else "FAIL"
        return f"[{marker}] {self.name:<32} {self.detail}"


async def _check_adb(serial: str | None) -> CheckResult:
    from sentinel.tools.adb_runner import AdbRunner

    runner = AdbRunner()
    if serial:
        result = await runner.is_installed("com.android.settings", serial=serial)
        ok = result.success
        detail = (
            f"device {serial} responsive"
            if ok else f"adb error: {result.error}"
        )
        return CheckResult("adb device reachable", ok, detail)
    devices = await runner.list_devices()
    if not devices.success:
        return CheckResult(
            "adb device reachable", False,
            f"adb list failed: {devices.error}",
        )
    online = [d for d in (devices.data or []) if getattr(d, "state", "") == "device"]
    if not online:
        return CheckResult(
            "adb device reachable", False,
            "no devices in state 'device' — run `adb devices`",
        )
    return CheckResult(
        "adb device reachable", True,
        f"{len(online)} device(s) online",
    )


def _check_frida_python() -> CheckResult:
    try:
        import frida  # noqa: F401
        version = getattr(frida, "__version__", "?")
        return CheckResult(
            "frida python lib", True, f"installed (v{version})",
        )
    except ImportError as exc:
        return CheckResult(
            "frida python lib", False,
            f"not installed: {exc}",
        )


async def _check_frida_server(serial: str | None) -> CheckResult:
    try:
        import frida
    except ImportError:
        return CheckResult(
            "frida-server on device", False,
            "frida python lib missing — see prior check",
        )

    loop = asyncio.get_event_loop()
    try:
        device = await loop.run_in_executor(None, frida.get_usb_device, 5000)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "frida-server on device", False,
            f"get_usb_device failed: {exc}",
        )

    try:
        procs = await loop.run_in_executor(None, device.enumerate_processes)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "frida-server on device", False,
            f"device reachable but frida-server not responding: {exc} — "
            "start it with `adb shell /data/local/tmp/frida-server &`",
        )

    client_ver = getattr(frida, "__version__", "0")
    return CheckResult(
        "frida-server on device", True,
        f"responding ({len(procs)} processes visible) — frida client v{client_ver}",
    )


def _check_compiled_agent() -> CheckResult:
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "frida_agent" / "dist" / "_agent.js"
    if path.exists():
        size = path.stat().st_size
        return CheckResult(
            "compiled Frida agent", True,
            f"{path.relative_to(repo_root)} ({size:,} bytes)",
        )
    return CheckResult(
        "compiled Frida agent", False,
        "frida_agent/dist/_agent.js missing — run "
        "`cd frida_agent && npm install && npm run build`",
    )


def _check_login_scripts() -> CheckResult:
    repo_root = Path(__file__).resolve().parents[2]
    directory = repo_root / "frida_agent" / "login_scripts"
    if not directory.is_dir():
        return CheckResult(
            "login scripts", False, f"directory missing: {directory}",
        )
    scripts = sorted(directory.glob("*.js"))
    if not scripts:
        return CheckResult(
            "login scripts", False,
            f"{directory} contains no <package>.js files",
        )
    return CheckResult(
        "login scripts", True,
        f"{len(scripts)} script(s): {', '.join(s.stem for s in scripts)}",
    )


def _check_test_credentials() -> CheckResult:
    from sentinel.tools.credential_manager import CredentialManager

    cm = CredentialManager.from_env()
    if cm.has_credentials:
        labels = ", ".join(cm.labels())
        return CheckResult(
            "test credentials", True, f"{len(cm.labels())} loaded ({labels})",
        )
    return CheckResult(
        "test credentials", False,
        "no TEST_USER_<LABEL>_USERNAME / _PASSWORD vars or .env.test entries — "
        "auth-gated findings will not transition to verified",
    )


async def run_preflight(serial: str | None = None) -> list[CheckResult]:
    """Run all checks. Each one independent; never raises."""
    results: list[CheckResult] = []
    for coro in (
        _check_adb(serial),
        _check_frida_server(serial),
    ):
        try:
            results.append(await coro)
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(
                "uncategorised check", False, f"crash: {exc}",
            ))
    for sync_check in (
        _check_frida_python,
        _check_compiled_agent,
        _check_login_scripts,
        _check_test_credentials,
    ):
        try:
            results.append(sync_check())
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(
                "uncategorised check", False, f"crash: {exc}",
            ))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL pre-scan environment self-check.",
    )
    parser.add_argument("--serial", default=None, help="adb device serial")
    parser.add_argument(
        "--quiet", action="store_true",
        help="only print failures",
    )
    args = parser.parse_args()

    results = asyncio.run(run_preflight(args.serial))
    failures = [r for r in results if not r.ok]
    for r in results:
        if args.quiet and r.ok:
            continue
        print(r.render())
    print(
        f"\n{len(results) - len(failures)}/{len(results)} checks passed",
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
