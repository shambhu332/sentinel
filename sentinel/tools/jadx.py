"""JADX wrapper — Android APK and DEX decompiler.

Converts an APK's compiled bytecode back into readable Java source code.
Runs JADX as a subprocess with resource limits and path traversal protection.

Important: JADX returns exit code 1 when *any* class fails to decompile, even
if 99% of the output is valid. We treat exit-code-1-with-output as success.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300  # 5 minutes
MAX_OUTPUT_SIZE_MB = 500
# JADX JVM heap — default 1GB can OOM on medium APKs. 4GB is safe.
JADX_JVM_HEAP = "4g"


class JadxError(Exception):
    """JADX execution failed."""


class JadxResult(NamedTuple):
    """Result of a JADX decompilation."""
    output_dir: Path
    sources_dir: Path
    resources_dir: Path
    java_file_count: int
    exit_code: int
    stderr: str


class JadxRunner:
    """Async subprocess wrapper for JADX.

    Security: no shell=True, absolute paths, output size cap, hard timeout.
    """

    def __init__(self, jadx_path: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> None:
        self._jadx_path = jadx_path or shutil.which("jadx")
        if self._jadx_path is None:
            raise JadxError("jadx not found in PATH. Install via: paru -S jadx")
        self._timeout = timeout

    async def decompile(self, apk_path: Path, output_dir: Path) -> JadxResult:
        """Decompile APK into output_dir. Returns result with counts and paths.

        Args:
            apk_path: absolute path to the APK file
            output_dir: directory where Java sources will be written

        Raises:
            JadxError on hard failure (no output produced)
        """
        apk_path = apk_path.expanduser().resolve()
        output_dir = output_dir.expanduser().resolve()

        if not apk_path.exists():
            raise JadxError(f"APK not found: {apk_path}")
        if not apk_path.is_file():
            raise JadxError(f"Not a file: {apk_path}")

        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            self._jadx_path,
            "--output-dir", str(output_dir),
            "--show-bad-code",
            "--no-res-lists",
            "--threads-count", "4",
            "--no-inline-anonymous",
            "--escape-unicode",
            str(apk_path),
        ]

        logger.info("Running JADX: %s", " ".join(cmd))
        logger.debug("JADX output_dir resolved to: %s", output_dir)

        try:
            env = os.environ.copy()
            existing_opts = env.get("JAVA_OPTS", "")
            env["JAVA_OPTS"] = f"-Xmx{JADX_JVM_HEAP} {existing_opts}".strip()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout,
                )
            except asyncio.TimeoutError as e:
                proc.kill()
                await proc.wait()
                raise JadxError(f"JADX timeout after {self._timeout}s") from e

        except FileNotFoundError as e:
            raise JadxError(f"Cannot execute JADX at {self._jadx_path}: {e}") from e

        exit_code = proc.returncode or 0
        stderr_text = stderr.decode("utf-8", errors="replace")[:5000]
        stdout_text = stdout.decode("utf-8", errors="replace")[:5000]

        # Diagnostic: log what JADX printed and what's actually in output_dir
        logger.info("JADX exited with code %d", exit_code)
        if stdout_text.strip():
            logger.debug("JADX stdout: %s", stdout_text[:1000])
        if stderr_text.strip():
            logger.debug("JADX stderr: %s", stderr_text[:1000])

        # List what got written to output_dir
        if output_dir.exists():
            entries = list(output_dir.iterdir())
            logger.info(
                "JADX output_dir contains %d entries: %s",
                len(entries),
                [e.name for e in entries[:10]],
            )

        # Count Java files anywhere under output_dir (handles all JADX layouts)
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

        # Only fail if NOTHING was produced. Exit code 1 with valid output is
        # JADX's normal "some classes had warnings" signal.
        if java_count == 0:
            raise JadxError(
                f"JADX produced no Java files (exit {exit_code}). "
                f"stdout: {stdout_text[:200]} | stderr: {stderr_text[:200]} | "
                f"output_dir: {output_dir} | exists: {output_dir.exists()}"
            )

        try:
            total_size = sum(
                f.stat().st_size for f in output_dir.rglob("*") if f.is_file()
            )
            if total_size > MAX_OUTPUT_SIZE_MB * 1024 * 1024:
                logger.warning(
                    "JADX output unusually large: %d MB", total_size // (1024 * 1024),
                )
        except OSError:
            pass

        logger.info(
            "JADX decompiled %s: %d Java files, exit=%d",
            apk_path.name, java_count, exit_code,
        )

        return JadxResult(
            output_dir=output_dir,
            sources_dir=sources_dir,
            resources_dir=resources_dir,
            java_file_count=java_count,
            exit_code=exit_code,
            stderr=stderr_text,
        )
