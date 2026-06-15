"""Generate libFuzzer/AFL++ harnesses for the JNI exports of an APK.

For every ``Java_<pkg>_<class>_<method>`` symbol META_006's
``native_inspector`` enumerates, we emit a small C harness:

  * Wraps a minimal ``JNIEnv`` stub so the export is callable from
    libFuzzer's ``LLVMFuzzerTestOneInput``.
  * Synthesizes ``jstring`` / ``jbyteArray`` / ``jint`` args from the
    fuzz input buffer using a deterministic packing scheme.
  * dlopen()s the bundled .so and resolves the symbol at runtime.

This is the *generator* half. Compiling + actually running AFL++
against the harnesses requires the toolchain (QEMU usermode + AFL++
+ aarch64-linux-gnu-gcc cross-compiler) and is documented as a
follow-up — see ``fuzz/README.md``. We emit a ``Makefile`` and a
``run.sh`` next to the harnesses so the user has a one-command path
once those deps are installed.

This is the open-source twin of djini.ai's research-tier "Blackbox
AFL++ fuzzing for JNI and native interfaces".
"""
from __future__ import annotations

import logging
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Matches the JNI mangled name plus an arg-list / return-type string
# captured from D_072's `params` evidence. We accept either shape; we
# don't actually require accurate JNI signature parsing because the
# harness uses the fuzz buffer to compose all string-shaped args.
_JNI_SYMBOL_RE = re.compile(r"^Java_[A-Za-z0-9_]+$")


@dataclass(frozen=True)
class JniSignature:
    symbol: str             # Java_com_x_Foo_doIt
    return_type: str        # void | jint | jstring | jbyteArray | ...
    arg_types: tuple[str, ...]   # ("jstring", "jint")
    source_lib: str = ""    # libnative.so

    @property
    def harness_filename(self) -> str:
        return f"{self.symbol}_harness.c"


_JNI_TYPE_TO_C = {
    "jstring":   "jstring",
    "String":    "jstring",
    "jbyteArray": "jbyteArray",
    "byte[]":    "jbyteArray",
    "jint":      "jint",
    "int":       "jint",
    "jlong":     "jlong",
    "long":      "jlong",
    "jboolean":  "jboolean",
    "boolean":   "jboolean",
    "jfloat":    "jfloat",
    "float":     "jfloat",
    "jdouble":   "jdouble",
    "double":    "jdouble",
}


def parse_jni_signature(symbol: str, params_str: str = "",
                        return_type: str = "void",
                        source_lib: str = "") -> JniSignature:
    """Parse the D_072-emitted (symbol, params, return_type) into a sig."""
    if not _JNI_SYMBOL_RE.match(symbol):
        raise ValueError(f"not a JNI-mangled symbol: {symbol!r}")
    args: list[str] = []
    if params_str:
        for raw in params_str.split(","):
            raw = raw.strip()
            if not raw:
                continue
            # Take the type name (drop "name" if "Type name" shape).
            type_tok = raw.split()[0]
            args.append(_JNI_TYPE_TO_C.get(type_tok, "jbyteArray"))
    return JniSignature(
        symbol=symbol,
        return_type=_JNI_TYPE_TO_C.get(return_type, "void"),
        arg_types=tuple(args),
        source_lib=source_lib,
    )


# ----------------------------- harness body --------------------------------


_HARNESS_TMPL = r"""// SENTINEL — auto-generated libFuzzer harness
// Symbol:       {symbol}
// Source .so:   {source_lib}
// Signature:    {return_type} ({arg_types_csv})
//
// Build (host x86_64, mock JNIEnv) for a smoke test:
//   clang -fsanitize=fuzzer,address -I./jni_stub harness.c
//        -ldl -o {symbol}_fuzz
//   ./{symbol}_fuzz corpus/
//
// Build for the actual target ABI (aarch64) via AFL++/QEMU:
//   $AFL_PATH/afl-clang-lto -target aarch64-linux-gnu \
//        -fsanitize=fuzzer -I./jni_stub harness.c \
//        -ldl -o {symbol}_fuzz
//   afl-fuzz -Q -i corpus/ -o out/ -- ./{symbol}_fuzz @@

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "jni_stub.h"

typedef {return_type} (*fn_t)({arg_types_csv_or_void});
static fn_t target_fn = 0;

static void load_once(void) {{
    if (target_fn) return;
    void *h = dlopen("{source_lib}", RTLD_NOW);
    if (!h) return;
    target_fn = (fn_t)dlsym(h, "{symbol}");
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    load_once();
    if (!target_fn) return 0;
    if (size < {min_size}) return 0;

    JNIEnv env = sentinel_make_jnienv(data, size);
{arg_setup}
    target_fn({arg_names});
    sentinel_release_jnienv(&env);
    return 0;
}}
"""


_JNI_STUB_H = r"""// SENTINEL — minimal JNIEnv stub for libFuzzer harnesses
// Only the JNIEnv methods our harness actually calls are stubbed.
// Returned strings/arrays come from the fuzz input buffer so the
// fuzzer drives the target with attacker-controlled bytes.
#ifndef SENTINEL_JNI_STUB_H
#define SENTINEL_JNI_STUB_H
#include <stdint.h>
#include <stddef.h>

typedef int jint;
typedef long long jlong;
typedef unsigned char jboolean;
typedef float jfloat;
typedef double jdouble;
typedef struct _jobject *jobject;
typedef struct _jclass  *jclass;
typedef struct _jstring *jstring;
typedef struct _jbyteArray *jbyteArray;

typedef struct _JNIEnv {
    const uint8_t *buf;
    size_t len;
    size_t cursor;
} JNIEnv;

JNIEnv sentinel_make_jnienv(const uint8_t *data, size_t size);
void   sentinel_release_jnienv(JNIEnv *env);

jstring     sentinel_take_jstring(JNIEnv *env, size_t want);
jbyteArray  sentinel_take_jbyteArray(JNIEnv *env, size_t want);
jint        sentinel_take_jint(JNIEnv *env);
jlong       sentinel_take_jlong(JNIEnv *env);
jboolean    sentinel_take_jboolean(JNIEnv *env);
jfloat      sentinel_take_jfloat(JNIEnv *env);
jdouble     sentinel_take_jdouble(JNIEnv *env);

#endif
"""

_JNI_STUB_C = r"""// SENTINEL — JNIEnv stub implementation
#include "jni_stub.h"
#include <stdlib.h>
#include <string.h>

JNIEnv sentinel_make_jnienv(const uint8_t *data, size_t size) {
    JNIEnv e = { data, size, 0 };
    return e;
}

void sentinel_release_jnienv(JNIEnv *env) { (void)env; }

static const uint8_t* take_bytes(JNIEnv *env, size_t n) {
    if (env->cursor + n > env->len) return 0;
    const uint8_t *p = env->buf + env->cursor;
    env->cursor += n;
    return p;
}

jstring sentinel_take_jstring(JNIEnv *env, size_t want) {
    const uint8_t *p = take_bytes(env, want);
    if (!p) return 0;
    char *s = (char*)malloc(want + 1);
    if (!s) return 0;
    memcpy(s, p, want);
    s[want] = 0;
    return (jstring)s;
}

jbyteArray sentinel_take_jbyteArray(JNIEnv *env, size_t want) {
    const uint8_t *p = take_bytes(env, want);
    if (!p) return 0;
    uint8_t *b = (uint8_t*)malloc(want);
    if (!b) return 0;
    memcpy(b, p, want);
    return (jbyteArray)b;
}

jint sentinel_take_jint(JNIEnv *env) {
    const uint8_t *p = take_bytes(env, 4);
    if (!p) return 0;
    jint v; memcpy(&v, p, 4); return v;
}

jlong sentinel_take_jlong(JNIEnv *env) {
    const uint8_t *p = take_bytes(env, 8);
    if (!p) return 0;
    jlong v; memcpy(&v, p, 8); return v;
}

jboolean sentinel_take_jboolean(JNIEnv *env) {
    const uint8_t *p = take_bytes(env, 1);
    return p ? (*p & 1) : 0;
}

jfloat sentinel_take_jfloat(JNIEnv *env) {
    const uint8_t *p = take_bytes(env, 4);
    if (!p) return 0;
    jfloat v; memcpy(&v, p, 4); return v;
}

jdouble sentinel_take_jdouble(JNIEnv *env) {
    const uint8_t *p = take_bytes(env, 8);
    if (!p) return 0;
    jdouble v; memcpy(&v, p, 8); return v;
}
"""


def _arg_setup_for(sig: JniSignature) -> tuple[str, str, int]:
    """Return (setup_block, names_csv, min_input_size)."""
    setup_lines: list[str] = []
    names: list[str] = []
    min_size = 0
    for i, t in enumerate(sig.arg_types):
        name = f"arg{i}"
        names.append(name)
        if t == "jstring":
            setup_lines.append(
                f"    jstring {name} = sentinel_take_jstring(&env, 16);"
            )
            min_size += 16
        elif t == "jbyteArray":
            setup_lines.append(
                f"    jbyteArray {name} = sentinel_take_jbyteArray(&env, 32);"
            )
            min_size += 32
        elif t == "jint":
            setup_lines.append(f"    jint {name} = sentinel_take_jint(&env);")
            min_size += 4
        elif t == "jlong":
            setup_lines.append(f"    jlong {name} = sentinel_take_jlong(&env);")
            min_size += 8
        elif t == "jboolean":
            setup_lines.append(f"    jboolean {name} = sentinel_take_jboolean(&env);")
            min_size += 1
        elif t == "jfloat":
            setup_lines.append(f"    jfloat {name} = sentinel_take_jfloat(&env);")
            min_size += 4
        elif t == "jdouble":
            setup_lines.append(f"    jdouble {name} = sentinel_take_jdouble(&env);")
            min_size += 8
        else:
            # Unknown — fall through to NULL pointer.
            setup_lines.append(f"    void *{name} = 0;")
    return "\n".join(setup_lines), ", ".join(names), max(min_size, 1)


def generate_harness(sig: JniSignature) -> str:
    """Return the C source for one harness file."""
    setup, names, min_size = _arg_setup_for(sig)
    arg_types_csv = ", ".join(sig.arg_types) if sig.arg_types else ""
    return _HARNESS_TMPL.format(
        symbol=sig.symbol,
        source_lib=sig.source_lib or "libnative.so",
        return_type=sig.return_type,
        arg_types_csv=arg_types_csv,
        arg_types_csv_or_void=arg_types_csv or "void",
        arg_setup=setup,
        arg_names=names,
        min_size=min_size,
    )


def _make_runner(out_dir: Path, signatures: list[JniSignature]) -> None:
    """Drop a Makefile + run.sh that compiles + smoke-runs each harness."""
    mk = ["# SENTINEL — auto-generated harness build\nCC ?= clang\n",
          "CFLAGS = -fsanitize=fuzzer,address -O1 -I./jni_stub\n",
          "LDLIBS = -ldl\n\nall: \\\n"]
    for s in signatures:
        mk.append(f"\t{s.symbol}_fuzz \\\n")
    mk.append("\n\n")
    for s in signatures:
        mk.append(
            f"{s.symbol}_fuzz: {s.harness_filename} jni_stub/jni_stub.c\n"
            f"\t$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)\n\n"
        )
    (out_dir / "Makefile").write_text("".join(mk), encoding="utf-8")

    run_sh = textwrap.dedent("""\
        #!/usr/bin/env bash
        # SENTINEL — fuzz every generated harness for 60s each.
        # Requires AFL++ or libFuzzer in $PATH; QEMU usermode for aarch64.
        set -eu
        TIME=${SENTINEL_FUZZ_SECONDS:-60}
        mkdir -p corpus out
        # A 16-byte seed so libFuzzer has something to start from.
        : > corpus/seed && head -c 16 /dev/urandom > corpus/seed
        for fuzz in *_fuzz; do
            [ -x "$fuzz" ] || continue
            echo "==> $fuzz ($TIME s)"
            timeout "$TIME" "./$fuzz" -max_total_time="$TIME" corpus/ \\
                -artifact_prefix="out/${fuzz}_crash_" || true
        done
        echo "Crashes (if any) written to ./out/"
    """)
    (out_dir / "run.sh").write_text(run_sh, encoding="utf-8")
    try:
        (out_dir / "run.sh").chmod(0o755)
    except OSError:
        pass


def _drop_stub(out_dir: Path) -> None:
    stub_dir = out_dir / "jni_stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    (stub_dir / "jni_stub.h").write_text(_JNI_STUB_H, encoding="utf-8")
    (stub_dir / "jni_stub.c").write_text(_JNI_STUB_C, encoding="utf-8")


def generate_for_apk(
    native_info: dict[str, Any], out_dir: Path,
) -> list[JniSignature]:
    """Generate harnesses for every JNI export in META_006's output.

    ``native_info`` is the dict META_006 stores in
    ``ctx.app_profile['native_libs_info']``. We look for an ``exports``
    list of ``{"symbol": ..., "lib": ..., "params": ..., "return_type": ...}``
    entries and write one harness per Java_-prefixed entry.

    Returns the list of signatures actually generated. Caller can pass
    each to D_072 for cross-correlation with crashes.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    _drop_stub(out_dir)

    sigs: list[JniSignature] = []
    exports = (native_info or {}).get("exports") or []
    for raw in exports:
        sym = raw.get("symbol") if isinstance(raw, dict) else None
        if not isinstance(sym, str) or not sym.startswith("Java_"):
            continue
        try:
            sig = parse_jni_signature(
                symbol=sym,
                params_str=str(raw.get("params") or ""),
                return_type=str(raw.get("return_type") or "void"),
                source_lib=str(raw.get("lib") or "libnative.so"),
            )
        except ValueError:
            continue
        (out_dir / sig.harness_filename).write_text(
            generate_harness(sig), encoding="utf-8",
        )
        sigs.append(sig)

    if sigs:
        _make_runner(out_dir, sigs)
        logger.info(
            "AFL++ harness gen: %d JNI harnesses written under %s",
            len(sigs), out_dir,
        )
    return sigs


__all__ = [
    "JniSignature", "generate_for_apk", "generate_harness",
    "parse_jni_signature",
]
