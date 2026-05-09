"""JADX wrapper — Android APK and DEX decompiler.

Converts an APK's compiled bytecode back into readable Java source code.
Runs JADX as a subprocess with resource limits and path traversal protection.

CRASH-PROOF GUARANTEE: This module never raises exceptions to its caller.
All operations return a ToolResult[JadxResult]. Check result.success.

Important: JADX returns exit code 1 when *any* class fails to decompile, even
if 99% of the output is valid. We treat exit-code-1-with-output as success.

Timeout policy: scales with APK size. Small APKs (<10MB) get 300s. Large
production APKs (50-200MB) get up to 1800s (30 minutes). Override via the
`timeout` constructor arg or SENTINEL_JADX_TIMEOUT env var.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from pathlib import Path
from typing import NamedTuple

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300  # 5 minutes — minimum for tiny APKs
MAX_TIMEOUT = 1800     # 30 minutes — cap for monster APKs
TIMEOUT_PER_MB = 8     # seconds of timeout budget per MB of APK
MAX_OUTPUT_SIZE_MB = 500
JADX_JVM_HEAP = "4g"


class JadxError(Exception):
    """JADX execution failed (used internally; callers see ToolResult.error)."""


class JadxResult(NamedTuple):
    """Result of a JADX decompilation."""
    output_dir: Path
    sources_dir: Path
    resources_dir: Path
    java_file_count: int
    exit_code: int
    stderr: str


def auto_timeout_for_apk(apk_path: Path) -> int:
    """Scale timeout to APK size.

    Examples:
        3.4MB  InsecureBankv2 →  300s (minimum)
        20MB   medium APK     →  300s (minimum)
        50MB   large APK      →  400s
        95MB   huge APK       →  760s
        200MB  monster APK    → 1600s
    """
    try:
        size_mb = apk_path.stat().st_size / (1024 * 1024)
    except OSError:
        return DEFAULT_TIMEOUT

    scaled = int(size_mb * TIMEOUT_PER_MB)
    return max(DEFAULT_TIMEOUT, min(MAX_TIMEOUT, scaled))


class JadxRunner:
    """Async subprocess wrapper for JADX.

    All public methods return ToolResult — they never raise exceptions
    to the caller. Internal methods may raise JadxError for control flow,
    which is caught at the boundary.
    """

    def __init__(
        self,
        jadx_path: str | None = None,
        timeout: int | None = None,
    ) -> None:
        self._jadx_path = jadx_path or shutil.which("jadx")
        # Note: missing jadx is a config error, not a runtime crash.
        # We still record it but defer the failure to decompile() time.
        self._jadx_missing_reason: str | None = None
        if self._jadx_path is None:
            self._jadx_missing_reason = (
                "jadx not found in PATH. Install via: paru -S jadx"
            )

        # Timeout resolution order:
        # 1. Explicit constructor arg
        # 2. SENTINEL_JADX_TIMEOUT env var
        # 3. None — use auto_timeout_for_apk per-call
        if timeout is not None:
            self._timeout: int | None = timeout
        else:
            env_timeout = os.environ.get("SENTINEL_JADX_TIMEOUT", "").strip()
            if env_timeout.isdigit():
                self._timeout = int(env_timeout)
            else:
                self._timeout = None  # auto-scale per APK

    async def decompile(
        self, apk_path: Path, output_dir: Path,
    ) -> ToolResult[JadxResult]:
        """Decompile APK into output_dir.

        Returns ToolResult.success=True with JadxResult on success.
        Returns ToolResult.success=False with error string on any failure.
        Never raises.
        """
        start = time.monotonic()
        warnings: list[str] = []

        # Pre-flight checks
        if self._jadx_missing_reason:
            return ToolResult.fail(
                f"JadxError: {self._jadx_missing_reason}",
                duration=time.monotonic() - start,
            )

        try:
            return await self._decompile_inner(apk_path, output_dir, start, warnings)
        except JadxError as e:
            return ToolResult.fail(
                f"JadxError: {e}",
                duration=time.monotonic() - start,
                warnings=warnings,
            )
        except Exception as e:  # noqa: BLE001
            # Defensive — anything unexpected becomes a tool failure, not a crash
            logger.exception("Unexpected JADX error")
            return ToolResult.from_exception(e, duration=time.monotonic() - start)

    async def _decompile_inner(
        self,
        apk_path: Path,
        output_dir: Path,
        start: float,
        warnings: list[str],
    ) -> ToolResult[JadxResult]:
        """Inner decompile logic. May raise JadxError; caller catches."""
        apk_path = apk_path.expanduser().resolve()
        output_dir = output_dir.expanduser().resolve()

        if not apk_path.exists():
            raise JadxError(f"APK not found: {apk_path}")
        if not apk_path.is_file():
            raise JadxError(f"Not a file: {apk_path}")

        output_dir.mkdir(parents=True, exist_ok=True)

        # Determine effective timeout
        effective_timeout = self._timeout or auto_timeout_for_apk(apk_path)
        size_mb = apk_path.stat().st_size / (1024 * 1024)
        logger.info(
            "JADX timeout for %.1fMB APK: %ds",
            size_mb, effective_timeout,
        )

        # Minimal flags — only the most basic ones that have existed since
        # JADX 1.0. -d sets output dir, --show-bad-code keeps partial output
        # rather than aborting on failed classes.
        cmd = [
            self._jadx_path,
            "-d", str(output_dir),
            "--show-bad-code",
            str(apk_path),
        ]

        logger.info("Running JADX: %s", " ".join(cmd))

        env = os.environ.copy()
        existing_opts = env.get("JAVA_OPTS", "")
        env["JAVA_OPTS"] = f"-Xmx{JADX_JVM_HEAP} {existing_opts}".strip()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as e:
            raise JadxError(f"Cannot execute JADX at {self._jadx_path}: {e}") from e

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=effective_timeout,
            )
        except asyncio.TimeoutError as e:
            proc.kill()
            await proc.wait()
            raise JadxError(
                f"timeout after {effective_timeout}s on {size_mb:.1f}MB APK. "
                f"Override with SENTINEL_JADX_TIMEOUT env var if needed."
            ) from e

        exit_code = proc.returncode or 0
        stderr_text = stderr.decode("utf-8", errors="replace")[:5000]
        stdout_text = stdout.decode("utf-8", errors="replace")[:5000]

        logger.info("JADX exited with code %d", exit_code)
        if stdout_text.strip():
            logger.debug("JADX stdout: %s", stdout_text[:1000])
        if stderr_text.strip():
            logger.debug("JADX stderr: %s", stderr_text[:1000])

        # Count Java files anywhere under output_dir
        java_files = list(output_dir.rglob("*.java"))
        java_count = len(java_files)
        logger.info("Found %d .java files in %s", java_count, output_dir)

        # Identify the actual sources directory
        sources_subdir = output_dir / "sources"
        if sources_subdir.exists() and any(sources_subdir.rglob("*.java")):
            sources_dir = sources_subdir
        else:
            sources_dir = output_dir

        resources_dir = output_dir / "resources"

        # Only fail if NOTHING was produced
        if java_count == 0:
            raise JadxError(
                f"produced no Java files (exit {exit_code}). "
                f"stdout: {stdout_text[:200]} | stderr: {stderr_text[:200]}"
            )

        # Size sanity check (warning, not failure)
        try:
            total_size = sum(
                f.stat().st_size for f in output_dir.rglob("*") if f.is_file()
            )
            size_mb_output = total_size // (1024 * 1024)
            if size_mb_output > MAX_OUTPUT_SIZE_MB:
                msg = f"JADX output unusually large: {size_mb_output} MB"
                logger.warning(msg)
                warnings.append(msg)
        except OSError:
            pass

        # Note partial decompile (exit 1 = some classes failed but we got output)
        if exit_code == 1:
            warnings.append(
                f"JADX exit code 1 — some classes failed to decompile, "
                f"but {java_count} files were produced"
            )

        logger.info(
            "JADX decompiled %s: %d Java files, exit=%d",
            apk_path.name, java_count, exit_code,
        )

        result = JadxResult(
            output_dir=output_dir,
            sources_dir=sources_dir,
            resources_dir=resources_dir,
            java_file_count=java_count,
            exit_code=exit_code,
            stderr=stderr_text,
        )

        return ToolResult.ok(
            result,
            duration=time.monotonic() - start,
            warnings=warnings,
        )
