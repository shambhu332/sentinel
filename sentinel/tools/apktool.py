"""apktool wrapper — extracts AndroidManifest.xml and decoded resources.

JADX gives us readable Java source; apktool gives us the manifest in XML form
and decoded resources (strings.xml, network_security_config.xml, etc).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 180


class ApktoolError(Exception):
    """apktool execution failed."""


class ApktoolResult(NamedTuple):
    output_dir: Path
    manifest_path: Path | None
    res_dir: Path | None
    exit_code: int
    stderr: str


class ApktoolRunner:
    """Async wrapper for apktool d (decode)."""

    def __init__(self, apktool_path: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> None:
        self._apktool_path = apktool_path or shutil.which("apktool")
        if self._apktool_path is None:
            raise ApktoolError("apktool not found in PATH")
        self._timeout = timeout

    async def decode(self, apk_path: Path, output_dir: Path) -> ApktoolResult:
        """Decode APK into output_dir using `apktool d`."""
        apk_path = apk_path.expanduser().resolve()
        output_dir = output_dir.expanduser().resolve()

        if not apk_path.exists():
            raise ApktoolError(f"APK not found: {apk_path}")

        # apktool refuses to overwrite existing directories without -f
        cmd = [
            self._apktool_path, "d",
            "-f",               # force overwrite
            "-s",               # skip sources (we use JADX for those)
            "-o", str(output_dir),
            str(apk_path),
        ]

        logger.info("Running apktool: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout,
                )
            except asyncio.TimeoutError as e:
                proc.kill()
                await proc.wait()
                raise ApktoolError(f"apktool timeout after {self._timeout}s") from e

        except FileNotFoundError as e:
            raise ApktoolError(f"Cannot execute apktool: {e}") from e

        exit_code = proc.returncode or 0
        stderr_text = stderr.decode("utf-8", errors="replace")[:5000]

        manifest = output_dir / "AndroidManifest.xml"
        res = output_dir / "res"

        if exit_code != 0 and not manifest.exists():
            raise ApktoolError(
                f"apktool failed (exit {exit_code}): {stderr_text[:500]}"
            )

        logger.info("apktool decoded %s (exit=%d)", apk_path.name, exit_code)

        return ApktoolResult(
            output_dir=output_dir,
            manifest_path=manifest if manifest.exists() else None,
            res_dir=res if res.exists() else None,
            exit_code=exit_code,
            stderr=stderr_text,
        )
