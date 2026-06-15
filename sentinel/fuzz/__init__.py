"""SENTINEL native-fuzzing infrastructure (JNI / libFuzzer / AFL++).

This package generates libFuzzer/AFL++ harnesses for the JNI exports
META_006 ``native_inspector`` enumerates in a target APK. The end-to-
end pipeline is:

  1. ``harness_gen.generate_for_apk(...)`` reads META_006's output and
     writes one ``<symbol>_harness.c`` per JNI export under
     ``<workspace>/fuzz/harnesses/``.
  2. ``runner.build_and_run(...)`` (out-of-session work — needs QEMU
     and AFL++ toolchains) compiles each harness against a stub
     JNIEnv and runs ``afl-fuzz`` for a bounded wall-clock window.
  3. Crashes get triaged back into ``D_072`` JNI Shadow as confirmed
     native-RCE candidates.

What ships in this commit: the harness *generator*. The compile +
runner step requires AFL++ installed under QEMU usermode and is
documented in ``fuzz/README.md`` for a follow-up patch.
"""
from sentinel.fuzz.harness_gen import (
    JniSignature,
    generate_for_apk,
    generate_harness,
    parse_jni_signature,
)

__all__ = [
    "JniSignature",
    "generate_for_apk",
    "generate_harness",
    "parse_jni_signature",
]
