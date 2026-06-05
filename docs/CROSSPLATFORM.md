# Cross-Platform Agents — React Native & Flutter

Two agents extend SENTINEL's coverage to JS- and Dart-shipping APKs.
Both are **deliberately conservative** about what they claim: the
RN agent stops at Hermes, the Flutter agent labels itself
experimental on every run. The honest "we can't see this" matters
more than a fake positive.

## RN_001 — React Native bundle auditor

Activates when the resources tree carries
`assets/index.android.bundle`, `libreactnativejni.so`, or
`libhermes.so`.

### Hermes short-circuit

As of React Native 0.70 (mid-2022), **Hermes is on by default**. The
shipped bundle in those apps is no longer JavaScript text — it's a
Hermes-bytecode blob whose first 4 bytes are the magic
`0xC61FBC03` (little-endian, i.e. `03 BC 1F C6` on disk; the
constant lives in
[Hermes' `BytecodeFileFormat.h`](https://github.com/facebook/hermes/blob/main/include/hermes/BCGen/HBC/BytecodeFileFormat.h)).

When RN_001 sees that magic at the bundle head it stops and emits a
single `HERMES_BYTECODE_LIMITATION` INFO finding. Regex-scanning
Hermes bytecode is not productive — the binary contains string
literals interleaved with opcode bytes and pointer-relative
relocations, and any pattern match against it produces garbage that
wastes a triager's time.

This matters because **most modern RN apps are Hermes apps**. The
limitation isn't a corner case; it's the default. Documenting it
clearly is the whole point.

### What we scan on plain-JS bundles

| Detector | Severity | Confidence | What it looks for |
|---|---|---:|---|
| `INSECURE_STORAGE` | High | 0.85 | `AsyncStorage.setItem(...)` / `EncryptedStorage.setItem(...)` with a credential-shaped key (`token`, `jwt`, `password`, `secret`, `auth`, `session`, …) |
| `CLEARTEXT_TRAFFIC` | Medium | 0.85 | `'http://...'` URLs in the bundle — excluding `localhost`, `127.0.0.1`, `10.0.2.2` (dev hosts) |
| `HARDCODED_SECRET` | High / Medium | 0.55 – 0.95 | AWS, Google API, Firebase, Slack, Stripe, generic bearer tokens |
| `WEBVIEW_XSS` | Medium / Low | 0.55 – 0.75 | `<WebView source={{uri: <variable>}} originWhitelist={['*']}>` — higher confidence when both signals fire |
| `DANGEROUS_SET_INNER_HTML` | Low | 0.55 | `dangerouslySetInnerHTML={{__html: ...}}` |

### Future work — Hermes disassembly

To audit modern RN apps end-to-end we'd need to disassemble the
Hermes bundle back to readable JS, then re-run the scanners.
Candidates:

* [`hermes-dec`](https://github.com/P1sec/hermes-dec) — Python
  rewriter that can produce pseudocode. Most actively maintained.
* [`hbctool`](https://github.com/bongtrop/hbctool) — Python
  disassembler with assemble/reassemble round-trip.

Both ship as Python packages so the integration cost is real but
much smaller than e.g. shipping a JVM. Slated for a follow-up sprint;
called out in this doc so it doesn't get forgotten.

## FL_001 — Flutter `libapp.so` auditor (experimental)

Activates when `libflutter.so` and/or `libapp.so` are present under
`resources/lib/<abi>/`.

### What's hard about Flutter

Flutter compiles **every line of Dart code** into `libapp.so` as
AOT-compiled native machine code. There is no source-style
intermediate representation in the shipped artifact. Real Dart-level
analysis requires:

* the AOT class hierarchy (recoverable via `reFlutter` or `Doldrums`),
* a Dart IR (decompiler output, not present by default),
* sometimes the matching Flutter engine snapshot (versions matter).

That's a research-tooling pipeline. We don't run it. We do a
**strings(1)-style scan** instead.

### Always-on experimental notice

Every applicable scan emits `FLUTTER_ANALYSIS_EXPERIMENTAL` as the
**first finding**, before any string-scan output. The notice carries:

* the framework tokens we saw in `libapp.so` (proves we're really
  looking at a Flutter binary — defends against false positives on a
  random `.so` named `libapp.so`),
* an explicit `coverage_disclosure` field listing what we did NOT
  inspect (Dart symbol resolution, AOT disassembly, taint, call
  graph),
* a `future_work` field naming reFlutter / Doldrums by URL.

A reviewer who sees a "clean" FL_001 result therefore cannot
mistake it for a positive verdict — the notice is unmissable.

### What the string scan looks for

| Detector | Severity | Confidence | Notes |
|---|---|---:|---|
| `CLEARTEXT_TRAFFIC_IN_LIBAPP` | Medium | 0.55 | Cleartext `http://` URL literals embedded in the AOT |
| `HARDCODED_SECRET_IN_LIBAPP` | High / Medium | 0.65 – 0.90 | Same secret-family regexes as RN_001, lower confidence |

Confidence is deliberately *lower* than the same patterns in RN_001
because a stripped AOT binary mixes real string literals with PC-
relative reloc bytes, and matches against the binary tail produce
more false positives than matches against readable JS source.

### Future work — Dart AOT decompilation

* [`reFlutter`](https://github.com/Impact-I/reFlutter) — patches the
  Flutter engine to dump runtime artefacts; the most mature Dart AOT
  inspection tool.
* [`Doldrums`](https://github.com/rscloura/Doldrums) — static
  disassembler for Dart AOT snapshots; doesn't require running the
  app.

Both would let us recover Dart-level structure suitable for the rest
of the SAST stack (TAINT_001 in particular). Tracked as
distinction-grade future work.

## Triage guidance

* **RN apps**: if the Hermes notice appears, the *absence* of other
  RN_001 findings tells you nothing about the app's security
  posture. Combine with NL_001 (which scans the native libs
  regardless), N_001 (cert pinning), N_002 (cleartext traffic at the
  manifest level), and any DAST capture.
* **Flutter apps**: treat FL_001 output as a sighting list, not a
  verdict. Pair with NL_001 (also string-scans `libapp.so`),
  manifest-level checks, and — if the app warrants it — a manual
  reFlutter / Doldrums pass.

The experimental notice and the Hermes notice are themselves
findings: the report should preserve them so a downstream consumer
knows the coverage envelope.
