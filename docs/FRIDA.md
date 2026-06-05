# SENTINEL Frida layer

This doc covers the runtime-instrumentation layer that powers Sprint 8.2's
dynamic agents (`A_003` runtime crypto, `N_005` certificate pinning bypass).

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│ Source of truth                                                        │
│   frida_agent/src/**.ts ── TypeScript hook code, one file per concern  │
│                                                                        │
│                                ─── frida-compile ───►                  │
│                                                                        │
│ Compiled artifact (checked into git)                                   │
│   frida_agent/dist/_agent.js ── bundled JS, includes frida-java-bridge │
│                                                                        │
│                                ─── load_runtime_hooks() ───►           │
│                                                                        │
│ Python runtime                                                         │
│   sentinel/tools/frida_runner.py ── reads dist/_agent.js, injects via  │
│                                     FridaRunner.inject_script()         │
└────────────────────────────────────────────────────────────────────────┘
```

The Python side never spawns Node.js. Users without Node.js installed can
still run SENTINEL because the compiled `dist/_agent.js` is committed.

### Why a separate `frida_agent/` Node project?

Frida 17 (April 2025) removed the built-in Java bridge from the default
agent. To stay compatible with both Frida 16 and Frida 17 without forcing
users to choose, we bundle `frida-java-bridge` into our agent script via
`frida-compile`. On Frida 16 the bundled bridge is harmless (it just
re-exposes the built-in one); on Frida 17 it's required.

### Hook modules

| File | Coverage |
|---|---|
| `src/hooks/crypto.ts` | Cipher, MessageDigest, KeyGenerator, Mac, SecureRandom, SecretKeyFactory, KeyPairGenerator |
| `src/hooks/pinning_okhttp.ts` | CertificatePinner (`check`, `check$okhttp`), OkHttpClient$Builder, OkHostnameVerifier, Interceptor chain |
| `src/hooks/pinning_system.ts` | X509TrustManagerExtensions, Conscrypt.Platform, X509TrustManager (via `Java.choose`), CertPathValidator |
| `src/hooks/pinning_webview.ts` | WebViewClient base + every subclass (enumerated + ClassLoader hook for future-loaded ones) + `onReceivedHttpAuthRequest` |
| `src/hooks/pinning_libraries.ts` | TrustKit, Volley HurlStack, Cronet, Apache HttpClient, NetworkSecurityConfig, Picasso |
| `src/hooks/pinning_native.ts` | libssl / libboringssl / libcrypto: `SSL_CTX_set_verify`, `SSL_set_verify` |
| `src/hooks/diagnostics.ts` | Emits the `tls.hooks_summary` event |

## Adding a new pinning library hook

1. Pick the most specific file (`pinning_libraries.ts` if it's a
   third-party SDK, `pinning_system.ts` for an AOSP class).
2. Add a `tryHook(result, 'YourLibrary.label', () => { ... })` block
   following the existing pattern. The label string becomes the
   `library` field on every `tls.bypass` event.
3. Inside the callback:
   - `Java.use("fully.qualified.ClassName")` — throws
     `ClassNotFoundException` if absent, which `tryHook` silently
     swallows.
   - Override the check method's implementation with a no-op (returning
     `true`/`void` to bypass) or a tap (returning the original return
     value to merely observe).
   - Call `sendBypass({ library, method, host })` so the event lands in
     the capture.
4. If the new library is canonical pinning (a real production framework
   developers rely on), add it to `_LIBRARY_SEVERITY` in
   `sentinel/agents/dynamic/cert_pinning_bypass_agent.py` with weight
   `"high"`. Less common libraries default to `"medium"`.
5. Rebuild and run the n005 tests:
   ```bash
   cd frida_agent && npm run build
   cd .. && poetry run pytest tests/unit/test_sprint8_n005.py
   ```

### Template

```typescript
tryHook(result, "MyVendor.MyClass", () => {
    const MyClass = Java.use("com.myvendor.MyClass");
    MyClass.checkSomething.overload(
        "java.lang.String",
    ).implementation = function (this: any, arg: string) {
        sendBypass({
            library: "MyVendor.MyClass",
            method: "checkSomething",
            host: arg,
        });
        return true;  // bypass; use `return this.checkSomething(arg);`
                      // for observation-only.
    };
});
```

## Rebuilding the agent

```bash
cd frida_agent
npm install            # one-time
npm run build          # produces dist/_agent.js
```

Commit `dist/_agent.js`. Verify:

```bash
ls -lh dist/_agent.js                       # expect ~250-600 KB
grep -c frida-java-bridge dist/_agent.js    # expect > 1
```

Watch mode for hook development:
```bash
npm run watch
```

## Spawn vs attach mode

| Mode | When to use | CLI flag |
|---|---|---|
| **attach** (default) | App is already running on the device. Non-disruptive — the user can keep interacting through the scan. | (none — default) |
| **spawn** | App detects Frida at startup and crashes / aborts. Spawn launches the app paused, loads hooks before any app code runs, then resumes. | `--frida-spawn` |

Implementation:
- `FridaRunner.attach(package, spawn=True)` calls `am force-stop` then
  `device.spawn([package])` and pauses at the entry point.
- Orchestrator detects spawn mode and calls `FridaRunner.resume()`
  immediately after `inject_script()` succeeds, before the wait window.
- Spawn requires kernel support for ptrace-spawn; many vendor-customised
  kernels disallow it and SENTINEL will fall through with a clear error.

## Compatibility matrix

| Frida | Android | Notes |
|---|---|---|
| 16.7.x | 7-14 | Reference target. Built-in Java bridge used. |
| 16.7.x | 14+ (Samsung Knox / RKP) | Spawn often blocked; use attach + `adb pidof` PID fallback (built into `_find_pid`). |
| 17.x | 7-14 | Works because bundled `frida-java-bridge` is loaded by our agent. |
| 17.x | 14+ | Same as above; better ptrace mechanism in 17 makes some Samsung kernels work where 16 failed. |

Known broken:
- **Frida 16 + Samsung One UI 6 (Android 14) + Knox active** — `device.spawn` returns NotSupportedError. Workaround: launch the app manually, then run SENTINEL without `--frida-spawn`.

## Debugging a hook that isn't firing

1. **Confirm the agent loaded at all.** Check the scan log for
   `Frida script loaded for <pkg>`. Absence means `inject_script()`
   threw — usually a malformed JS payload.

2. **Check the `tls.hooks_summary` event.** Every run emits one; it lists
   `attempted`, `succeeded`, and `failed` libraries:
   ```python
   for ev in capture.events:
       if ev.kind == "tls.hooks_summary":
           print(ev.payload)
   ```
   If your library is in `attempted` but not in `succeeded` or `failed`,
   the class wasn't present in the running app (silently skipped via
   `ClassNotFoundException`). If it's in `failed`, the `reason` field
   tells you which overload signature mismatched.

3. **Verify Frida itself isn't broken.** Run frida-trace by hand:
   ```bash
   frida-trace -U -j 'okhttp3.CertificatePinner!check' -F com.target.app
   ```
   If frida-trace shows hits and our hook doesn't, the bug is in our
   overload signature or label routing.

4. **Common pitfalls:**
   - Subclass overrides win over base class — see `pinning_webview.ts`
     for the enumeration pattern. Any new "single class" pinning hook
     against a heavily-subclassed interface should use the same approach.
   - `Java.choose` only walks **currently loaded** instances; classes
     loaded later need the `ClassLoader.loadClass` interception trick.
   - Native hooks fire before Java bridge is ready — that's intentional,
     so install them *outside* `waitForJava`.
   - Reflection-protected classes (TrustKit's anti-Frida builds) throw
     on `Java.use`; the `tryHook` wrapper makes that a `failed` entry
     rather than crashing the whole agent.

5. **Force the fallback path to isolate problems.** Temporarily delete
   `frida_agent/dist/_agent.js` — the loader logs a warning and falls
   back to a tiny crypto-only inline script. If that works and the full
   agent doesn't, the bug is in the compiled TS hook code, not Frida or
   the device.

## Event reference

| `kind` | Meaning | Emitted by |
|---|---|---|
| `crypto.cipher` | `Cipher.getInstance(algo)` called | `crypto.ts` |
| `crypto.digest` | `MessageDigest.getInstance(algo)` called | `crypto.ts` |
| `crypto.keygen` | `KeyGenerator.getInstance(algo)` called | `crypto.ts` |
| `crypto.mac` | `Mac.getInstance(algo)` called | `crypto.ts` |
| `crypto.secure_random` | `SecureRandom()` constructed | `crypto.ts` |
| `crypto.secret_key_factory` | `SecretKeyFactory.getInstance` called | `crypto.ts` |
| `crypto.keypair_generator` | `KeyPairGenerator.getInstance` called | `crypto.ts` |
| `crypto.hooks_installed` | Diagnostic, end of crypto setup | `crypto.ts` |
| `tls.bypass` | A pinning check was no-op'd | every `pinning_*.ts` |
| `tls.bypass_failed` | A pinning hook setup threw post-class-load | every `pinning_*.ts` |
| `tls.hooks_summary` | End-of-run roll-up: attempted / succeeded / failed | `diagnostics.ts` |
| `error` | Something inside the agent threw | various |
