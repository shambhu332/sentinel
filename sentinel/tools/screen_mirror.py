"""Screen mirror — streams device screenshots over a WebSocket.

Captures frames via ``adb exec-out screencap -p`` and sends each one as a
base64-encoded PNG wrapped in a small JSON envelope. The browser side draws
each frame onto a ``<canvas>`` element.

Target frame rate is intentionally modest (8 fps default) — screencap is a
full-resolution PNG capture and higher rates saturate the ADB socket without
meaningfully improving the pentesting experience.

Envelope format (server → client)::

    {"type": "frame", "data": "<base64-png>", "fps": 8}

Control messages (client → server)::

    {"type": "tap",  "x": 0.42, "y": 0.61}   # normalised 0-1 coords
    {"type": "stop"}

On any ADB error the stream sends::

    {"type": "error", "message": "..."}

and closes the connection — the frontend shows a reconnect button.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import shutil
import time
from typing import Any

logger = logging.getLogger(__name__)


class ScreenMirror:
    """Async screen-mirror session for one ADB device."""

    def __init__(
        self,
        serial: str,
        *,
        fps: int = 8,
        adb_path: str | None = None,
    ) -> None:
        self._serial   = serial
        self._fps      = max(1, min(fps, 30))
        self._interval = 1.0 / self._fps
        self._adb      = adb_path or shutil.which("adb") or "adb"
        self._running  = False

    # ----------------------------------------------------------------- stream

    async def stream(self, websocket: Any) -> None:
        """Capture frames and push them until the client disconnects or stop."""
        self._running = True
        logger.info("[mirror] starting stream serial=%s fps=%d", self._serial, self._fps)

        try:
            while self._running:
                t0 = time.monotonic()

                png = await self._screencap()
                if png is None:
                    await websocket.send_json({
                        "type": "error",
                        "message": "screencap failed — check ADB connection",
                    })
                    break

                await websocket.send_json({
                    "type":  "frame",
                    "data":  base64.b64encode(png).decode(),
                    "fps":   self._fps,
                })

                elapsed = time.monotonic() - t0
                sleep   = max(0.0, self._interval - elapsed)
                if sleep > 0:
                    await asyncio.sleep(sleep)

        except Exception as exc:
            logger.debug("[mirror] stream ended: %s", exc)
        finally:
            self._running = False
            logger.info("[mirror] stream stopped serial=%s", self._serial)

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------- tap

    async def inject_tap(self, x_norm: float, y_norm: float) -> bool:
        """Send a tap at normalised coordinates (0–1, 0–1).

        Resolves the screen resolution from ``wm size`` then fires
        ``input tap`` — much lighter than a full screencap and returns
        before the next frame is due.
        """
        w, h = await self._screen_size()
        if not w or not h:
            return False
        px = int(x_norm * w)
        py = int(y_norm * h)
        code, _, _ = await self._adb_run(
            ["shell", "input", "tap", str(px), str(py)],
            timeout=5.0,
        )
        return code == 0

    # ---------------------------------------------------------------- helpers

    async def _screencap(self) -> bytes | None:
        """Return raw PNG bytes from ``adb exec-out screencap -p``."""
        cmd = [self._adb]
        if self._serial:
            cmd += ["-s", self._serial]
        cmd += ["exec-out", "screencap", "-p"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=8.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return None
            if proc.returncode or len(out) < 512:
                return None
            return out
        except Exception as exc:
            logger.debug("[mirror] screencap error: %s", exc)
            return None

    async def _screen_size(self) -> tuple[int, int]:
        """Return (width, height) from ``adb shell wm size``."""
        code, out, _ = await self._adb_run(
            ["shell", "wm", "size"], timeout=5.0,
        )
        if code != 0:
            return 0, 0
        # "Physical size: 1080x1920"
        for part in out.split():
            if "x" in part:
                try:
                    w, h = part.split("x", 1)
                    return int(w), int(h)
                except ValueError:
                    pass
        return 0, 0

    async def _adb_run(
        self, args: list[str], *, timeout: float = 10.0,
    ) -> tuple[int, str, str]:
        cmd = [self._adb]
        if self._serial:
            cmd += ["-s", self._serial]
        cmd += args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (
                proc.returncode or 0,
                out.decode("utf-8", errors="replace"),
                err.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            return -1, "", "timed out"
        except Exception as exc:
            return -1, "", str(exc)
