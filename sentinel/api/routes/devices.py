"""Android device pool and dynamic-lab controls for the web UI."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sentinel.auth.jwt_auth import get_current_active_user
from sentinel.core.config import get_settings
from sentinel.devices import get_device_manager
from sentinel.tools.adb_runner import AdbRunner
from sentinel.tools.preflight import run_preflight
from sentinel.tools.screen_mirror import ScreenMirror

router = APIRouter(prefix="/devices", tags=["devices"])

# Module-scope manager — Redis-backed when SENTINEL_REDIS_URL is set,
# in-process otherwise. See sentinel/devices/redis_pool.py.
_manager = get_device_manager()


class LaunchRequest(BaseModel):
    """Package launch request from the web dynamic-lab screen."""

    package: str = Field(..., min_length=1)
    activity: str | None = Field(
        default=None,
        description="Optional Activity class or full package/activity component",
    )


class ConnectRequest(BaseModel):
    """ADB TCP connect request (used for Genymotion / WiFi ADB)."""

    address: str = Field(..., min_length=7, description="host:port, e.g. 192.168.56.101:5555")


class TapRequest(BaseModel):
    """Normalised tap coordinates from the screen mirror canvas."""

    x: float = Field(..., ge=0.0, le=1.0, description="0-1 normalised x position")
    y: float = Field(..., ge=0.0, le=1.0, description="0-1 normalised y position")


def _serial(serial: str) -> str:
    return serial.strip()


def _command_payload(name: str, result: Any) -> dict[str, Any]:
    if not result.success or result.data is None:
        return {
            "name": name,
            "ok": False,
            "error": result.error or "adb command failed",
            "duration_seconds": result.duration_seconds,
        }
    return {
        "name": name,
        "ok": result.data.exit_code == 0,
        "exit_code": result.data.exit_code,
        "stdout": result.data.stdout,
        "stderr": result.data.stderr,
        "duration_seconds": result.duration_seconds,
    }


async def _run_adb_action(
    name: str,
    args: list[str],
    *,
    serial: str,
    timeout: int = 30,
) -> dict[str, Any]:
    runner = AdbRunner()
    result = await runner._run_adb(args, serial=_serial(serial), timeout=timeout)
    return _command_payload(name, result)


def _action_response(serial: str, actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "ok": all(action.get("ok") for action in actions),
        "serial": _serial(serial),
        "actions": actions,
    }


@router.get("")
async def list_devices(current_user=Depends(get_current_active_user)) -> JSONResponse:
    """Force a fresh `adb devices` enumeration and return what we see."""
    devs = await _manager.refresh()
    return JSONResponse(content=[d.to_dict() for d in devs])


@router.post("/{serial}/preflight")
async def device_preflight(
    serial: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Run the same DAST preflight checks exposed by the CLI."""
    checks = await run_preflight(_serial(serial))
    return {
        "ok": all(check.ok for check in checks),
        "serial": _serial(serial),
        "checks": [
            {
                "name": check.name,
                "ok": check.ok,
                "detail": check.detail,
            }
            for check in checks
        ],
    }


@router.post("/{serial}/disable-verifier")
async def disable_package_verifier(
    serial: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Disable Android package verifier settings for local test installs."""
    actions = [
        await _run_adb_action(
            "disable adb install verifier",
            ["shell", "settings", "put", "global", "verifier_verify_adb_installs", "0"],
            serial=serial,
        ),
        await _run_adb_action(
            "disable package verifier",
            ["shell", "settings", "put", "global", "package_verifier_enable", "0"],
            serial=serial,
        ),
        await _run_adb_action(
            "suppress verifier consent",
            ["shell", "settings", "put", "secure", "package_verifier_user_consent", "-1"],
            serial=serial,
        ),
    ]
    return _action_response(serial, actions)


@router.post("/{serial}/frida/forward")
async def forward_frida(
    serial: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Forward the device Frida server to localhost:27042."""
    actions = [
        await _run_adb_action(
            "adb forward frida",
            ["forward", "tcp:27042", "tcp:27042"],
            serial=serial,
            timeout=8,
        ),
    ]
    return _action_response(serial, actions)


@router.get("/{serial}/frida/status")
async def frida_status(
    serial: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Check whether Frida is reachable for this device serial."""
    result = await run_preflight(_serial(serial))
    frida_checks = [
        check for check in result
        if check.name in {"frida python lib", "frida-server on device"}
    ]
    return {
        "ok": all(check.ok for check in frida_checks),
        "serial": _serial(serial),
        "checks": [
            {
                "name": check.name,
                "ok": check.ok,
                "detail": check.detail,
            }
            for check in frida_checks
        ],
    }


@router.post("/{serial}/frida/setup")
async def setup_frida(
    serial: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Start `/data/local/tmp/frida-server` and create the TCP forward."""
    start = await _run_adb_action(
        "start frida-server",
        [
            "shell",
            "sh",
            "-c",
            (
                "if pidof frida-server >/dev/null 2>&1; then "
                "echo already-running; "
                "else /data/local/tmp/frida-server -D >/dev/null 2>&1 & "
                "echo started; fi"
            ),
        ],
        serial=serial,
        timeout=8,
    )
    forward = await _run_adb_action(
        "adb forward frida",
        ["forward", "tcp:27042", "tcp:27042"],
        serial=serial,
        timeout=8,
    )
    pid = await _run_adb_action(
        "pidof frida-server",
        ["shell", "pidof", "frida-server"],
        serial=serial,
        timeout=8,
    )
    return _action_response(serial, [start, forward, pid])


@router.post("/{serial}/install")
async def install_uploaded_apks(
    serial: str,
    apks: list[UploadFile] = File(..., description="One APK or a split APK set"),
    replace: bool = Form(default=True),
    grant_permissions: bool = Form(default=True),
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Install one APK or a base+split APK set on the selected device."""
    if not apks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="upload at least one APK",
        )
    if len(apks) > 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="too many APK files; upload 32 or fewer split APKs",
        )

    settings = get_settings()
    max_bytes = settings.max_apk_size_mb * 1024 * 1024
    total_bytes = 0
    stored: list[Path] = []
    file_names: list[str] = []

    with tempfile.TemporaryDirectory(prefix="sentinel-device-install-") as tmp:
        tmp_dir = Path(tmp)
        for index, apk in enumerate(apks):
            try:
                if not apk.filename:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="uploaded APK filename missing",
                    )
                suffix = Path(apk.filename).suffix.lower()
                if suffix != ".apk":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"unsupported extension {suffix!r}; need .apk",
                    )
                safe_name = Path(apk.filename).name.replace("/", "_").replace("\\", "_")
                dst = tmp_dir / f"{index:02d}-{safe_name}"
                bytes_written = 0
                with dst.open("wb") as out:
                    while True:
                        chunk = await apk.read(1024 * 1024)
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > max_bytes:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail=(
                                    f"APK upload exceeds {settings.max_apk_size_mb} MB "
                                    "limit"
                                ),
                            )
                        out.write(chunk)
                if bytes_written == 0:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"{apk.filename} is empty",
                    )
                stored.append(dst)
                file_names.append(safe_name)
            finally:
                await apk.close()

        runner = AdbRunner()
        if len(stored) == 1:
            install = await runner.install_apk(
                stored[0],
                serial=_serial(serial),
                replace=replace,
                grant_permissions=grant_permissions,
            )
            mode = "single"
        else:
            install = await runner.install_multiple_apks(
                stored,
                serial=_serial(serial),
                replace=replace,
                grant_permissions=grant_permissions,
            )
            mode = "split"

    return {
        "ok": install.success,
        "serial": _serial(serial),
        "mode": mode,
        "files": file_names,
        "bytes": total_bytes,
        "stdout": install.data or "",
        "error": install.error,
        "duration_seconds": install.duration_seconds,
    }


@router.post("/{serial}/launch")
async def launch_package(
    serial: str,
    request: LaunchRequest,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Launch an installed package or explicit package/activity component."""
    package = request.package.strip()
    activity = (request.activity or "").strip()
    if not package:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="package is required",
        )

    if activity:
        component = activity if "/" in activity else f"{package}/{activity}"
        launch_args = ["shell", "am", "start", "-W", "-n", component]
        action_name = "am start"
    else:
        launch_args = [
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ]
        action_name = "monkey launch"

    launch = await _run_adb_action(
        action_name,
        launch_args,
        serial=serial,
        timeout=20,
    )
    pid = await _run_adb_action(
        "pidof package",
        ["shell", "pidof", package],
        serial=serial,
        timeout=8,
    )
    return _action_response(serial, [launch, pid])


@router.get("/{serial}/packages/{package_name}")
async def package_status(
    serial: str,
    package_name: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Report whether a package is installed and currently running."""
    package = package_name.strip()
    if not package:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="package name is required",
        )
    installed = await AdbRunner().is_installed(package, serial=_serial(serial))
    path = await _run_adb_action(
        "pm path",
        ["shell", "pm", "path", package],
        serial=serial,
        timeout=8,
    )
    pid = await _run_adb_action(
        "pidof package",
        ["shell", "pidof", package],
        serial=serial,
        timeout=8,
    )
    return {
        "ok": installed.success,
        "serial": _serial(serial),
        "package": package,
        "installed": bool(installed.data) if installed.success else False,
        "error": installed.error,
        "actions": [path, pid],
    }


@router.post("/{serial}/logcat/clear")
async def clear_logcat(
    serial: str,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Clear the device logcat ring buffer."""
    action = await _run_adb_action(
        "logcat clear",
        ["logcat", "-c"],
        serial=serial,
        timeout=10,
    )
    return _action_response(serial, [action])


@router.get("/{serial}/logcat")
async def read_logcat(
    serial: str,
    lines: int = 250,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Read a bounded tail of logcat for launch/crash diagnosis."""
    safe_lines = max(20, min(int(lines), 1000))
    action = await _run_adb_action(
        "logcat tail",
        ["logcat", "-d", "-t", str(safe_lines), "-v", "time"],
        serial=serial,
        timeout=20,
    )
    return _action_response(serial, [action])


@router.post("/connect")
async def adb_connect(
    request: ConnectRequest,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Run ``adb connect <address>`` — used to connect Genymotion / WiFi ADB devices."""
    import re
    addr = request.address.strip()
    # Basic safety check — only allow host:port format
    if not re.match(r'^[\w.\-]+:\d{2,5}$', addr):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="address must be host:port (e.g. 192.168.56.101:5555)",
        )
    runner = AdbRunner()
    result = await runner._run_adb(["connect", addr], timeout=10)
    out = result.data.stdout.strip() if result.success and result.data else ""
    ok  = result.success and "connected" in out.lower()
    return {
        "ok":      ok,
        "address": addr,
        "stdout":  out,
        "error":   result.error if not result.success else None,
    }


@router.post("/{serial}/tap")
async def inject_tap(
    serial: str,
    request: TapRequest,
    current_user=Depends(get_current_active_user),
) -> dict[str, Any]:
    """Inject a tap at normalised coordinates from the screen mirror canvas."""
    mirror = ScreenMirror(_serial(serial))
    ok = await mirror.inject_tap(request.x, request.y)
    return {"ok": ok, "serial": _serial(serial), "x": request.x, "y": request.y}


@router.websocket("/{serial}/mirror")
async def screen_mirror(websocket: WebSocket, serial: str) -> None:
    """WebSocket screen mirror — streams PNG frames at 8 fps.

    Frame envelope: ``{"type": "frame", "data": "<base64-png>", "fps": 8}``
    Client can send: ``{"type": "tap", "x": 0.5, "y": 0.5}`` to inject taps,
    or ``{"type": "stop"}`` to end the session cleanly.
    """
    await websocket.accept()
    mirror = ScreenMirror(_serial(serial))

    import asyncio

    async def recv_loop() -> None:
        """Handle incoming control messages while stream runs."""
        try:
            while True:
                msg = await websocket.receive_json()
                if msg.get("type") == "stop":
                    mirror.stop()
                    break
                elif msg.get("type") == "tap":
                    await mirror.inject_tap(
                        float(msg.get("x", 0.5)),
                        float(msg.get("y", 0.5)),
                    )
        except (WebSocketDisconnect, Exception):
            mirror.stop()

    recv_task = asyncio.create_task(recv_loop())
    try:
        await mirror.stream(websocket)
    except WebSocketDisconnect:
        pass
    finally:
        mirror.stop()
        recv_task.cancel()
        try:
            await recv_task
        except (asyncio.CancelledError, Exception):
            pass
