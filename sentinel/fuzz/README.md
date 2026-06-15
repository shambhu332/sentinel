# SENTINEL native fuzzing

This directory contains the **libFuzzer / AFL++ JNI harness generator** —
the open-source twin of djini.ai's research-tier "Blackbox AFL++ fuzzing for
JNI and native interfaces" feature.

## What ships here

* `harness_gen.py` — emits one `<symbol>_harness.c` per JNI export META_006's
  `native_inspector` finds. Each harness is a self-contained libFuzzer entry
  point that wraps a minimal `JNIEnv` stub and dlopen()s the bundled `.so`.
* Auto-emitted `Makefile` + `run.sh` next to the harnesses for one-command
  build + fuzz.

## What needs an out-of-session follow-up

The harness *generator* runs on every scan (no extra deps). The **runner**
needs:

1. **AFL++** ≥ 4.0 installed (`apt install afl++` or build from source)
2. **clang** ≥ 14 with `-fsanitize=fuzzer` support
3. **QEMU usermode for aarch64** (`apt install qemu-user-static`) — needed
   because nearly every production Android `.so` is ARM/ARM64
4. **Cross-compiler** `aarch64-linux-gnu-gcc` (`apt install gcc-aarch64-linux-gnu`)

With those installed:

```bash
cd <workspace>/<session>/fuzz/harnesses
make                # builds every *_fuzz binary
./run.sh            # smoke-fuzz each for SENTINEL_FUZZ_SECONDS (default 60s)
ls out/             # crash artifacts (one *_crash_* per crashing input)
```

## How crashes feed back into the report

A future patch will wire `runner.py` to:

1. Tail `out/` for crash artifacts during the run.
2. Triage each crash (SIGSEGV / SIGBUS / SIGABRT / heap-buffer-overflow / etc.).
3. Emit a `D_072` follow-on finding with `evidence.afl_crash_input` set to the
   reproducing bytes and `severity=CRITICAL`.

This closes the loop: META_006 enumerates JNI exports → harness_gen.py emits
fuzzing harnesses → AFL++ finds crashes → D_072 reports them as confirmed
native-RCE candidates with reproducer inputs in the bug-bounty PoC bundle.

## Why this isn't run automatically yet

AFL++ + QEMU usermode is a 200 MB toolchain that most CI runners don't have.
Until the orchestrator gains a `--fuzz` opt-in flag that gates the run on
the toolchain being present, harness generation is **passive** — files
are emitted to disk and the user runs `make && ./run.sh` themselves.
