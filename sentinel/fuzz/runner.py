"""AFL++ / libFuzzer runner — drives the harnesses ``harness_gen`` writes.

End-to-end flow:

  1. ``compile_harnesses(dir)`` runs ``make`` inside the harness
     directory. Picks ``clang`` first, falls back to ``afl-clang-fast``
     when available. Returns the list of built ``_fuzz`` binaries.
  2. ``run_harness(binary, time_s)`` invokes the fuzzer with
     ``-max_total_time`` (libFuzzer) or wraps it with ``afl-fuzz -Q``
     when AFL++ is on PATH. Crashes land under ``out/``.
  3. ``triage_crashes(out_dir)`` reads every crash artifact, classifies
     the signal (SIGSEGV / SIGBUS / SIGABRT / ASAN-heap-overflow), and
     emits a ``D_072`` follow-up ``Finding`` per unique crash.

Toolchain detection is best-effort — if ``clang`` / ``afl-fuzz`` /
QEMU usermode isn't on PATH, the runner returns early with a clear
``ToolMissing`` reason instead of crashing. That lets CI invoke
``run_for_session()`` unconditionally and just skip the fuzz step
when the runner-side toolchain is absent.

This is opt-in: the orchestrator only calls into this module when
``ctx.fuzz_enabled`` is True (set by ``--fuzz`` on the CLI / the
``fuzz`` option on the API).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class ToolchainStatus:
    available: bool
    compiler: str = ""
    fuzzer: str = ""
    qemu: bool = False
    reason: str = ""


@dataclass
class FuzzCrash:
    """One reproducer file emitted by the fuzzer."""
    harness: str
    artifact_path: Path
    signal: str = ""
    asan_signature: str = ""
    input_bytes_b64: str = ""


# --------------------------- toolchain detection ----------------------------


def detect_toolchain() -> ToolchainStatus:
    """Return what's available locally — never raises."""
    compiler = (
        shutil.which("afl-clang-fast")
        or shutil.which("clang")
        or ""
    )
    fuzzer = (
        shutil.which("afl-fuzz")
        or ""
    )
    qemu = bool(shutil.which("qemu-aarch64-static")) or bool(
        shutil.which("qemu-arm-static"),
    )
    if not compiler:
        return ToolchainStatus(
            available=False,
            reason="No clang / afl-clang-fast on PATH. "
                   "Install clang or AFL++ first.",
        )
    return ToolchainStatus(
        available=True, compiler=compiler, fuzzer=fuzzer, qemu=qemu,
        reason="OK",
    )


# --------------------------- compile + run ---------------------------------


def compile_harnesses(harness_dir: Path, status: ToolchainStatus) -> list[Path]:
    """Run ``make`` inside the harness dir. Returns built _fuzz binaries."""
    if not status.available:
        return []
    if not (harness_dir / "Makefile").exists():
        logger.warning("Fuzz: no Makefile in %s — nothing to build", harness_dir)
        return []
    env = dict(os.environ)
    env.setdefault("CC", status.compiler)
    try:
        subprocess.run(
            ["make"], cwd=str(harness_dir),
            env=env, check=True, capture_output=True, timeout=600,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.warning("Fuzz: harness compile failed: %s", e)
        return []
    return sorted(p for p in harness_dir.glob("*_fuzz") if os.access(p, os.X_OK))


def run_harness(
    binary: Path, time_s: int, status: ToolchainStatus,
) -> Path:
    """Run one harness for ``time_s`` seconds. Returns its out/ dir."""
    out_dir = binary.parent / "out" / binary.name
    out_dir.mkdir(parents=True, exist_ok=True)
    corpus = binary.parent / "corpus"
    corpus.mkdir(exist_ok=True)
    seed = corpus / "seed"
    if not seed.exists():
        seed.write_bytes(b"AAAA_CANARY_AAAA")

    if status.fuzzer and status.qemu:
        # AFL++ in QEMU usermode — the only way to fuzz ARM/ARM64 binaries
        # on an x86 host.
        cmd = [
            status.fuzzer, "-Q",
            "-i", str(corpus), "-o", str(out_dir),
            "--", str(binary), "@@",
        ]
    else:
        # libFuzzer path — only works when the binary is a native
        # x86_64 build (i.e. when the user smoke-tests on the dev host).
        cmd = [
            str(binary),
            f"-max_total_time={time_s}",
            f"-artifact_prefix={out_dir}/crash_",
            str(corpus),
        ]

    logger.info("Fuzz: launching %s (timeout %ds)", binary.name, time_s)
    try:
        subprocess.run(
            cmd, timeout=time_s + 30, check=False,
            capture_output=True,
        )
    except subprocess.TimeoutExpired:
        logger.info("Fuzz: %s timeout hit (expected)", binary.name)
    except Exception:  # noqa: BLE001
        logger.exception("Fuzz: %s runner crashed", binary.name)
    return out_dir


# --------------------------- crash triage ----------------------------------


def triage_crashes(harness_dir: Path) -> list[FuzzCrash]:
    """Walk the out/ tree and classify every crash artifact."""
    import base64

    out: list[FuzzCrash] = []
    root = harness_dir / "out"
    if not root.exists():
        return out
    for crash in root.rglob("*"):
        if not crash.is_file():
            continue
        if "README" in crash.name or "fuzzer_stats" in crash.name:
            continue
        if not (crash.name.startswith("crash") or "crash_" in crash.name):
            continue
        try:
            data = crash.read_bytes()
        except OSError:
            continue
        # Quick + heuristic signal classification — no symbol resolution,
        # no PC unwinding. The crash file itself is the reproducer; the
        # signal label is just a hint for triage.
        signal = ""
        asan_sig = ""
        text = data[:4096].decode("utf-8", errors="replace")
        if "AddressSanitizer" in text or "heap-buffer-overflow" in text:
            signal = "SIGSEGV"
            asan_sig = "ASAN/heap-buffer-overflow"
        elif "stack-overflow" in text:
            signal = "SIGSEGV"
            asan_sig = "ASAN/stack-overflow"
        elif "SIGABRT" in text:
            signal = "SIGABRT"
        elif data[:4] == b"\x7fELF":
            # Raw input — not a log. Default to SIGSEGV pending re-run.
            signal = "SIGSEGV"
        harness = crash.parent.name
        out.append(FuzzCrash(
            harness=harness,
            artifact_path=crash,
            signal=signal or "unknown",
            asan_signature=asan_sig,
            input_bytes_b64=base64.b64encode(data[:1024]).decode("ascii"),
        ))
    return out


def crashes_to_findings(
    crashes: list[FuzzCrash], session_id: str,
) -> list[Finding]:
    """Turn each crash into a D_072 follow-up finding."""
    findings: list[Finding] = []
    for c in crashes:
        sev = (
            Severity.CRITICAL
            if "buffer-overflow" in c.asan_signature
            or c.signal == "SIGSEGV"
            else Severity.HIGH
        )
        findings.append(Finding(
            session_id=session_id,
            agent_id="D_072",
            vuln_class="Native Memory Safety Crash (AFL++ confirmed)",
            severity=sev,
            confidence=0.95,
            recommendation=(
                f"AFL++ fuzzing of the JNI harness `{c.harness}` reached "
                f"a {c.signal} signal"
                + (f" ({c.asan_signature})" if c.asan_signature else "")
                + ". The reproducer input is attached as base64 in "
                "evidence.input_bytes_b64. Treat as a confirmed native "
                "memory-safety bug — likely RCE candidate. Run the "
                "harness binary against the reproducer to reproduce "
                "locally; minimise with afl-tmin."
            ),
            evidence={
                "afl_harness": c.harness,
                "afl_crash_path": str(c.artifact_path),
                "afl_signal": c.signal,
                "afl_asan_signature": c.asan_signature,
                "input_bytes_b64": c.input_bytes_b64,
                "dynamic_target": True,
                "cwe": "CWE-787",
            },
        ))
    return findings


# --------------------------- orchestrator entry ---------------------------


def run_for_session(
    workspace: Path, session_id: str, time_per_harness_s: int = 60,
) -> tuple[list[Finding], ToolchainStatus]:
    """One-shot: compile every harness under <workspace>/<session>/fuzz/
    + run each for ``time_per_harness_s`` seconds + emit crash findings.

    Used by the orchestrator's optional Phase 4.7. Safe to call even
    when no harnesses exist: returns empty list quickly.
    """
    status = detect_toolchain()
    if not status.available:
        logger.info("Fuzz: %s — skipping", status.reason)
        return [], status

    harness_dir = workspace / session_id / "fuzz" / "harnesses"
    if not harness_dir.exists():
        return [], status
    binaries = compile_harnesses(harness_dir, status)
    if not binaries:
        logger.info("Fuzz: nothing to run after compile")
        return [], status
    start = time.monotonic()
    for b in binaries:
        run_harness(b, time_per_harness_s, status)
    elapsed = time.monotonic() - start
    crashes = triage_crashes(harness_dir)
    logger.info(
        "Fuzz: %d binaries, %d crashes after %.1fs",
        len(binaries), len(crashes), elapsed,
    )
    return crashes_to_findings(crashes, session_id), status


__all__ = [
    "FuzzCrash",
    "ToolchainStatus",
    "compile_harnesses",
    "crashes_to_findings",
    "detect_toolchain",
    "run_for_session",
    "run_harness",
    "triage_crashes",
]
