# Claude Code Prompt — SENTINEL Frida Layer Upgrade

## Project context

You're upgrading the Frida runtime-instrumentation layer in SENTINEL, the open-source Android security scanner at `~/Desktop/project/sentinel/`. The current Frida implementation lives in `sentinel/tools/frida_runner.py` and works for the happy path but has six known limitations that we're fixing in this sprint.

**Do not modify any other Python files** unless explicitly listed below. The orchestrator, agents, CLI, and LLM router all stay as-is. The scope is limited to: the Frida runner, the hook scripts, a new `frida_agent/` directory with a Node.js build pipeline, related tests, and documentation.

## Current state — what already works

`frida_runner.py` already has:

- **Three-stage PID lookup** in `_find_pid`: `enumerate_applications()` → `enumerate_processes()` → `adb shell pidof <package>`. The adb fallback is critical for Samsung devices with Knox/RKP that fail Frida's full-process iteration.
- **Attach retry logic** (3 attempts, 2s delay) handling `ServerNotRunningError` transients.
- **IIFE-wrapped hook scripts** with a Java-availability poll (`typeof Java !== 'undefined' && Java.available`, 100ms tick, 3s ceiling) before calling `Java.perform`.
- **Two hook scripts** in module-level string constants: `CIPHER_GETINSTANCE_HOOK` (crypto: Cipher, MessageDigest, KeyGenerator) and `CERT_PINNING_BYPASS_HOOK` (six pinning libraries: OkHttp CertificatePinner, X509TrustManagerExtensions, WebViewClient base class, TrustKit, Conscrypt, OkHostnameVerifier).
- **Combined export** `ALL_RUNTIME_HOOKS = CIPHER_GETINSTANCE_HOOK + "\n\n" + CERT_PINNING_BYPASS_HOOK` used by the orchestrator.

Project is currently **pinned to `frida ~16.7`** in `pyproject.toml` because Frida 17 removed the built-in Java bridge.

## Known limitations to fix in this sprint

1. **Frida 17 not supported.** Pinning to 16.x means we miss Frida 17's better ptrace mechanism (which works on Samsung Knox/RKP devices where 16.x fails).
2. **WebView subclasses bypass our pinning hook.** The hook patches `android.webkit.WebViewClient.onReceivedSslError`, but Android's dynamic dispatch means apps that subclass WebViewClient (most production apps) have their *override* run instead, bypassing our instrumentation entirely.
3. **No `spawn` mode.** Some apps detect Frida at startup and crash. Spawning under Frida's control bypasses this.
4. **Sparse pinning library coverage.** Six libraries hooked; many real apps use Volley, Cronet, Retrofit interceptors, Network Security Config, or Apache HttpClient.
5. **No structured hook diagnostics.** The script emits one `tls.hooks_installed` event at the end, but we can't see which libraries were attempted, which were absent, and which were present-but-bypass-failed.
6. **Native networking unobservable.** Apps that call `libssl` directly (Flutter, React Native, NDK code) bypass all Java hooks. We need at least basic native-side observation.

## Goals for this sprint

By the end, SENTINEL's Frida layer must:

- Work on **both Frida 16 and Frida 17** without code changes from the user (we bundle `frida-java-bridge` for 17, no-op the bundle on 16).
- Hook **every subclass** of `WebViewClient.onReceivedSslError` and `WebViewClient.onReceivedHttpAuthRequest`.
- Support **spawn mode** as an alternative to attach for apps that detect Frida at startup.
- Cover **twelve pinning libraries** (six existing + six new) and emit a structured `tls.hooks_summary` event at the end with `attempted` / `succeeded` / `failed` lists.
- Hook **native libssl** functions for basic TLS observation outside the Java layer.
- Stay **crash-proof end-to-end** — every new hook gracefully degrades if its target class/symbol is absent.
- Pass **all existing 230 unit tests** plus new tests for the additions.

## File-by-file changes

### NEW: `frida_agent/` directory at repo root

A Node.js project that produces a self-contained Frida agent script bundling `frida-java-bridge`. This is the artifact the Python side loads.

````
frida_agent/
├── package.json
├── tsconfig.json
├── src/
│   ├── agent.ts                 # Entry point — orchestrates all hooks
│   ├── hooks/
│   │   ├── crypto.ts            # Cipher/MessageDigest/KeyGenerator hooks
│   │   ├── pinning_okhttp.ts    # OkHttp CertificatePinner + variants
│   │   ├── pinning_system.ts    # X509TrustManagerExtensions, Conscrypt
│   │   ├── pinning_webview.ts   # WebViewClient + all subclasses via Java.choose
│   │   ├── pinning_libraries.ts # TrustKit, OkHostnameVerifier, Volley,
│   │   │                          Cronet, Apache HttpClient, NSC bypass
│   │   ├── pinning_native.ts    # libssl Interceptor hooks
│   │   └── diagnostics.ts       # hooks_summary builder
│   └── lib/
│       ├── send.ts              # Typed wrapper around Frida's `send()`
│       └── java_ready.ts        # The Java-availability poll utility
├── dist/
│   └── _agent.js                # Compiled output — CHECKED INTO GIT
├── README.md                    # Build instructions + when to rebuild
└── .gitignore                   # ignore node_modules, dist/_agent.js.map
````

#### `frida_agent/package.json`

````json
{
  "name": "sentinel-frida-agent",
  "version": "0.2.0",
  "private": true,
  "description": "SENTINEL Frida agent — bundled hook script for runtime instrumentation",
  "main": "dist/_agent.js",
  "scripts": {
    "build": "frida-compile src/agent.ts -o dist/_agent.js -c",
    "watch": "frida-compile src/agent.ts -o dist/_agent.js -w",
    "clean": "rm -f dist/_agent.js"
  },
  "devDependencies": {
    "@types/frida-gum": "^18.0.0",
    "frida-compile": "^16.5.0",
    "typescript": "^5.4.0"
  },
  "dependencies": {
    "frida-java-bridge": "^7.1.0"
  }
}
````

#### `frida_agent/tsconfig.json`

````json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "strict": true,
    "noImplicitAny": true,
    "skipLibCheck": true,
    "lib": ["ES2020"]
  },
  "include": ["src/**/*"]
}
````

#### `frida_agent/src/lib/java_ready.ts`

````typescript
/**
 * Frida 17 removed the built-in Java bridge; this module imports
 * frida-java-bridge explicitly so it works on Frida 17. On Frida 16
 * the import still works (it just re-exposes the built-in module).
 *
 * The waitForJava helper polls Java.available with a 100ms tick and
 * 30-attempt ceiling (3s total), then runs the callback inside
 * Java.perform so all bytecode access is on the correct thread.
 */
import Java from "frida-java-bridge";

export { Java };

export type SetupFn = () => void;

export function waitForJava(label: string, setup: SetupFn): void {
    if (Java.available) {
        Java.perform(setup);
        return;
    }
    let attempts = 0;
    const interval = setInterval(() => {
        attempts++;
        if (Java.available) {
            clearInterval(interval);
            Java.perform(setup);
        } else if (attempts >= 30) {
            clearInterval(interval);
            send({
                kind: "error",
                message: `${label}: Java bridge unavailable after 3s`,
            });
        }
    }, 100);
}
````

#### `frida_agent/src/lib/send.ts`

````typescript
/**
 * Typed wrappers around Frida's global `send()`. Every event passes
 * through one of these helpers so the Python side gets a consistent
 * payload shape. Each helper enforces a discriminated 'kind' field
 * and structured payload, making the orchestrator's event parsing
 * resilient to refactors here.
 */

export function sendCipher(algorithm: string, provider?: string, overload?: string): void {
    send({ kind: "crypto.cipher", algorithm, provider, overload });
}

export function sendDigest(algorithm: string): void {
    send({ kind: "crypto.digest", algorithm });
}

export function sendKeygen(algorithm: string): void {
    send({ kind: "crypto.keygen", algorithm });
}

export interface BypassEvent {
    library: string;
    method: string;
    host?: string;
    extra?: Record<string, unknown>;
}

export function sendBypass(e: BypassEvent): void {
    send({ kind: "tls.bypass", ...e });
}

export function sendBypassFailed(library: string, error: string): void {
    send({ kind: "tls.bypass_failed", library, error });
}

export function sendHooksSummary(summary: {
    attempted: string[];
    succeeded: string[];
    failed: { library: string; reason: string }[];
    subclass_hooks_added: number;
    native_hooks_added: number;
}): void {
    send({ kind: "tls.hooks_summary", ...summary });
}

export function sendError(message: string): void {
    send({ kind: "error", message });
}
````

#### `frida_agent/src/hooks/crypto.ts`

Port the existing `CIPHER_GETINSTANCE_HOOK` to TypeScript. Same hooks: `Cipher.getInstance` (three overloads), `MessageDigest.getInstance`, `KeyGenerator.getInstance`. Also **add** these new crypto hooks while you're here:

- `javax.crypto.Mac.getInstance(String)` — HMAC algorithms, important for weak HMAC detection
- `java.security.SecureRandom` constructors (`SecureRandom()` and `SecureRandom(byte[])`) — flag misuse
- `javax.crypto.SecretKeyFactory.getInstance(String)` — exposes weak KDF algos like PBE-SHA1
- `java.security.KeyPairGenerator.getInstance(String)` — RSA/DSA/EC key generation observation

Each emits a typed `crypto.*` event via the `send.ts` helpers. Wrap setup in `try/catch` and emit `error` events for failures.

#### `frida_agent/src/hooks/pinning_okhttp.ts`

Port the existing OkHttp `CertificatePinner` hooks (both `check(String, List)` and `check$okhttp` Kotlin variant). **Add**:

- `okhttp3.OkHttpClient$Builder.certificatePinner(CertificatePinner)` — observe setup-time pinning configuration
- `okhttp3.internal.tls.OkHostnameVerifier.verify(String, SSLSession)` — already exists but emit a distinct `library: "okhttp.OkHostnameVerifier"` value
- `okhttp3.Interceptor` chain instrumentation — hook `Interceptor.intercept(Chain)` calls to detect custom pinning interceptors apps build

#### `frida_agent/src/hooks/pinning_system.ts`

Port existing X509TrustManagerExtensions, Conscrypt Platform hooks. **Add**:

- `javax.net.ssl.X509TrustManager.checkServerTrusted` — base interface; bypass via `Java.choose` on all loaded implementations
- `java.security.cert.CertPathValidator.validate` — last-resort cert chain validation

#### `frida_agent/src/hooks/pinning_webview.ts`

**This is the major new hook.** Replace the single-class WebViewClient hook with subclass enumeration. Implementation outline:

````typescript
import { Java, waitForJava } from "../lib/java_ready";
import { sendBypass, sendBypassFailed } from "../lib/send";

interface WebViewHookResult {
    libraryLabel: string;
    subclassesHooked: number;
}

export function installWebViewHooks(): WebViewHookResult {
    let subclassesHooked = 0;
    const baseClass = "android.webkit.WebViewClient";

    try {
        const WebViewClientBase = Java.use(baseClass);

        // Step 1: hook the base class first — catches direct uses
        try {
            WebViewClientBase.onReceivedSslError.implementation = function(
                view: unknown, handler: unknown, error: unknown,
            ) {
                let url = "";
                try { url = (error as any)?.getUrl() ?? ""; } catch {}
                sendBypass({
                    library: "WebViewClient.base",
                    method: "onReceivedSslError",
                    host: url,
                });
                (handler as any).proceed();
            };
            subclassesHooked++;
        } catch (e) {
            // base class method missing — extremely unusual
        }

        // Step 2: enumerate all currently loaded classes and hook
        // each subclass's own onReceivedSslError. Dynamic dispatch
        // means the subclass override runs instead of the base, so
        // we have to instrument each subclass directly.
        const loaded = Java.enumerateLoadedClassesSync();
        const WebViewClientClass = WebViewClientBase.class;

        loaded.forEach((className: string) => {
            if (className === baseClass) return;
            try {
                const cls = Java.use(className);
                if (!WebViewClientClass.isAssignableFrom(cls.class)) return;
                if (typeof cls.onReceivedSslError === "undefined") return;

                cls.onReceivedSslError.implementation = function(
                    view: unknown, handler: unknown, error: unknown,
                ) {
                    let url = "";
                    try { url = (error as any)?.getUrl() ?? ""; } catch {}
                    sendBypass({
                        library: `WebViewClient.subclass:${className}`,
                        method: "onReceivedSslError",
                        host: url,
                    });
                    (handler as any).proceed();
                };
                subclassesHooked++;
            } catch {
                // skip classes we can't instrument
            }
        });

        // Step 3: catch classes loaded LATER via classLoader hook
        // (after our setup runs). When a new WebViewClient subclass
        // gets loaded, hook it immediately.
        const ClassLoader = Java.use("java.lang.ClassLoader");
        const originalLoadClass = ClassLoader.loadClass.overload("java.lang.String");
        originalLoadClass.implementation = function(name: string) {
            const loaded = originalLoadClass.call(this, name);
            try {
                if (loaded && WebViewClientClass.isAssignableFrom(loaded)
                    && name !== baseClass) {
                    const cls = Java.use(name);
                    if (typeof cls.onReceivedSslError !== "undefined") {
                        cls.onReceivedSslError.implementation = function(
                            view: unknown, handler: unknown, error: unknown,
                        ) {
                            let url = "";
                            try { url = (error as any)?.getUrl() ?? ""; } catch {}
                            sendBypass({
                                library: `WebViewClient.subclass:${name}`,
                                method: "onReceivedSslError",
                                host: url,
                            });
                            (handler as any).proceed();
                        };
                    }
                }
            } catch {
                // ignore — class not instrumentable
            }
            return loaded;
        };
    } catch (e) {
        sendBypassFailed("WebViewClient", String(e));
    }

    return { libraryLabel: "WebViewClient.all", subclassesHooked };
}
````

#### `frida_agent/src/hooks/pinning_libraries.ts`

Port existing TrustKit and OkHostnameVerifier hooks. **Add**:

- **Volley** — `com.android.volley.toolbox.HurlStack` and `com.android.volley.toolbox.NetworkImageView` SSL setup
- **Cronet** — `org.chromium.net.CronetEngine$Builder.build()` observation
- **Apache HttpClient** — `org.apache.http.conn.ssl.AbstractVerifier.verify(String, SSLSession)`
- **Network Security Config bypass** — `android.security.net.config.NetworkSecurityConfig$Builder` modification
- **Square Picasso** — `com.squareup.picasso.OkHttp3Downloader` uses OkHttp under the hood; rarely has custom pinning but emit observation events

Each hook follows the same `try/catch` ClassNotFoundException-skip pattern, emits `tls.bypass` on hook fire and `tls.bypass_failed` on setup throw after class load.

#### `frida_agent/src/hooks/pinning_native.ts`

Native-side hooks via Frida's `Interceptor.attach`. Hooks the libssl functions used by Cronet, Flutter, React Native, and other NDK-based networking:

````typescript
export function installNativeHooks(): number {
    let count = 0;

    // SSL_CTX_set_verify — sets the cert verification callback on a context
    const sslCtxSetVerify = Module.findExportByName("libssl.so", "SSL_CTX_set_verify");
    if (sslCtxSetVerify) {
        Interceptor.attach(sslCtxSetVerify, {
            onEnter(args) {
                send({
                    kind: "tls.bypass",
                    library: "libssl.SSL_CTX_set_verify",
                    method: "native_intercept",
                    extra: { mode: args[1].toInt32() },
                });
                // Force SSL_VERIFY_NONE (mode = 0)
                args[1] = ptr("0");
            },
        });
        count++;
    }

    // SSL_set_verify — same but per-connection
    const sslSetVerify = Module.findExportByName("libssl.so", "SSL_set_verify");
    if (sslSetVerify) {
        Interceptor.attach(sslSetVerify, {
            onEnter(args) {
                args[1] = ptr("0");
            },
        });
        count++;
    }

    // BoringSSL specifically (some Android versions)
    ["libboringssl.so", "libcrypto.so"].forEach((lib) => {
        const fn = Module.findExportByName(lib, "SSL_CTX_set_verify");
        if (fn) {
            Interceptor.attach(fn, {
                onEnter(args) {
                    args[1] = ptr("0");
                },
            });
            count++;
        }
    });

    return count;
}
````

#### `frida_agent/src/hooks/diagnostics.ts`

A small helper that collects which libraries were attempted / succeeded / failed and emits the final summary event. Used by `agent.ts` to wrap up.

#### `frida_agent/src/agent.ts` (entry point)

````typescript
import { waitForJava } from "./lib/java_ready";
import { sendHooksSummary, sendError } from "./lib/send";
import { installCryptoHooks } from "./hooks/crypto";
import { installOkHttpHooks } from "./hooks/pinning_okhttp";
import { installSystemHooks } from "./hooks/pinning_system";
import { installWebViewHooks } from "./hooks/pinning_webview";
import { installLibraryHooks } from "./hooks/pinning_libraries";
import { installNativeHooks } from "./hooks/pinning_native";

interface HookResult {
    attempted: string[];
    succeeded: string[];
    failed: { library: string; reason: string }[];
}

function runJavaHooks(): { result: HookResult; subclassesHooked: number } {
    const result: HookResult = { attempted: [], succeeded: [], failed: [] };

    installCryptoHooks(result);
    installOkHttpHooks(result);
    installSystemHooks(result);
    installLibraryHooks(result);
    const webview = installWebViewHooks();
    result.attempted.push(webview.libraryLabel);
    result.succeeded.push(webview.libraryLabel);

    return { result, subclassesHooked: webview.subclassesHooked };
}

// Native hooks don't need the Java bridge — fire them immediately
const nativeHookCount = installNativeHooks();

// Java hooks need the bridge
waitForJava("sentinel-agent", () => {
    try {
        const { result, subclassesHooked } = runJavaHooks();
        sendHooksSummary({
            ...result,
            subclass_hooks_added: subclassesHooked,
            native_hooks_added: nativeHookCount,
        });
    } catch (e) {
        sendError(`agent setup: ${String(e)}`);
    }
});
````

#### `frida_agent/README.md`

````markdown
# SENTINEL Frida agent

Bundled hook script used by `sentinel/tools/frida_runner.py`.

## When to rebuild

- After editing any file under `src/`
- After updating `frida-java-bridge` to a new major version
- Before each release tag

## Build

```bash
cd frida_agent
npm install          # one-time
npm run build        # produces dist/_agent.js
```

Commit `dist/_agent.js` — it's the artifact loaded by Python.
The Python side never invokes Node.js. Users without Node.js installed
can still run SENTINEL because the compiled agent is checked in.

## Verify the build

```bash
ls -lh dist/_agent.js
# Expected: ~150–250 KB (bundles frida-java-bridge ~ 100 KB + our hooks)

head -5 dist/_agent.js
# First lines should be the frida-compile preamble
```
````

#### `frida_agent/.gitignore`

````
node_modules/
*.log
dist/_agent.js.map
src/**/*.js
````

### MODIFY: `sentinel/tools/frida_runner.py`

Two changes:

1. **Stop using the inline `CIPHER_GETINSTANCE_HOOK` / `CERT_PINNING_BYPASS_HOOK` / `ALL_RUNTIME_HOOKS` string constants.** Replace them with code that reads the compiled agent from `frida_agent/dist/_agent.js`. Falls back to a minimal inline crypto-only script if the file is missing (so SENTINEL still functions during development before the agent is built).

````python
   # Replace the module-level CIPHER_GETINSTANCE_HOOK / CERT_PINNING_BYPASS_HOOK
   # / ALL_RUNTIME_HOOKS constants with this loader:

   from pathlib import Path

   _AGENT_PATH = Path(__file__).resolve().parents[2] / "frida_agent" / "dist" / "_agent.js"

   _FALLBACK_INLINE_HOOK = r"""
   /* Minimal fallback when frida_agent/dist/_agent.js is missing. */
   (function() {
       if (typeof Java === 'undefined' || !Java.available) {
           send({kind: 'error', message: 'fallback: Java unavailable'});
           return;
       }
       Java.perform(function() {
           try {
               var Cipher = Java.use('javax.crypto.Cipher');
               Cipher.getInstance.overload('java.lang.String').implementation = function(t) {
                   send({kind: 'crypto.cipher', algorithm: t, overload: 'string'});
                   return this.getInstance(t);
               };
               send({kind: 'crypto.hooks_installed', count: 1, fallback: true});
           } catch(err) {
               send({kind: 'error', message: 'fallback: ' + err.toString()});
           }
       });
   })();
   """


   def load_runtime_hooks() -> str:
       """Read the compiled Frida agent from disk.

       Returns the contents of frida_agent/dist/_agent.js if present.
       Falls back to a tiny crypto-only inline script with a logged
       warning if the file is missing — keeps SENTINEL functional
       during development before the agent has been built.
       """
       if _AGENT_PATH.exists():
           return _AGENT_PATH.read_text(encoding="utf-8")
       logger.warning(
           "Compiled Frida agent not found at %s — using fallback "
           "inline hook (crypto-only, no pinning). Build the agent with: "
           "cd frida_agent && npm install && npm run build",
           _AGENT_PATH,
       )
       return _FALLBACK_INLINE_HOOK


   # Backwards-compatible alias used by the orchestrator
   ALL_RUNTIME_HOOKS = load_runtime_hooks()
````

2. **Add a `spawn` parameter to `FridaRunner.attach()`** that defaults to `False`. When `spawn=True`, the method:
   - Force-stops the target via `am force-stop` (uses `subprocess` since `AdbRunner` isn't injected here — keep it simple)
   - Calls `dev.spawn([package])` to start the app paused
   - Attaches to the returned PID (skipping the `_find_pid` flow)
   - After `inject_script()` returns, calls `dev.resume(pid)` to start execution
   - Resume must be exposed via a new `resume()` method on `FridaRunner` since the orchestrator needs to call it after script load

````python
   async def attach(
       self,
       package: str,
       spawn: bool = False,
   ) -> ToolResult[dict]:
       """Attach to or spawn the named package on the USB device.

       When spawn=True, force-stops the target and starts it under Frida
       control (paused). The caller must call resume() after inject_script
       to let the app actually start. Use spawn mode for apps with
       anti-Frida detection at startup; use the default attach mode for
       already-running apps you want to introspect without disrupting.
       """
       # ... existing setup code ...
       if spawn:
           # Force-stop, then spawn under control
           try:
               import subprocess
               subprocess.run(
                   ["adb", "shell", "am", "force-stop", package],
                   timeout=5, capture_output=True,
               )
           except Exception:
               pass

           try:
               pid = await self._loop.run_in_executor(
                   None, self._device.spawn, [package],
               )
               self._target_pid = pid
               self._spawned = True
               self._session = await self._loop.run_in_executor(
                   None, self._device.attach, pid,
               )
               return ToolResult.ok({
                   "package": package, "pid": pid,
                   "device": self._device.name, "mode": "spawn",
               })
           except Exception as e:
               return ToolResult.from_exception(e)

       # ... existing attach flow unchanged ...

   async def resume(self) -> ToolResult[str]:
       """Resume a spawned process. Only meaningful after attach(spawn=True)."""
       if not getattr(self, "_spawned", False):
           return ToolResult.ok("not spawned, nothing to resume")
       try:
           await self._loop.run_in_executor(
               None, self._device.resume, self._target_pid,
           )
           return ToolResult.ok("resumed")
       except Exception as e:
           return ToolResult.from_exception(e)
````

   Also add `self._spawned = False` to `__init__`.

### MODIFY: `sentinel/core/orchestrator.py`

In `_run_frida_subphase`, support an optional spawn mode controlled by a new `frida_spawn` orchestrator parameter. Default `False` to preserve current behaviour. When set:

- Pass `spawn=True` to `frida.attach(package)`
- After `inject_script()` succeeds, call `await frida.resume()` before the `frida.wait()`

The CLI's `--frida-spawn` flag (next file) sets this.

### MODIFY: `sentinel/cli.py`

Add a `--frida-spawn` flag alongside `--frida-duration`:

````python
@click.option("--frida-spawn", is_flag=True,
              help="Start the target app under Frida control instead of "
                   "attaching to a running instance. Use for apps with "
                   "anti-Frida detection at startup. Implies --frida.")
````

Plumb it through `_run_scan` and into `Orchestrator(frida_spawn=...)`.

### MODIFY: `sentinel/agents/dynamic/cert_pinning_bypass_agent.py`

The N_005 agent currently inspects FridaCapture for events with kind starting with `tls.`. Update the agent to also consume the new `tls.hooks_summary` event for richer reporting:

- Parse `attempted`, `succeeded`, `failed` lists from the summary event
- Include the list of probed libraries in the finding's `evidence` field
- When all probed libraries return `ClassNotFoundException` (none present), emit the existing "Certificate Pinning Resistance" INFO finding with the full probed list in evidence so users see exactly what was checked

The agent's logic shouldn't change qualitatively — just enrich the evidence.

### MODIFY: `tests/unit/test_sprint8_n005.py`

Add new test cases:

1. **WebView subclass bypass detection**: synthetic FridaCapture with a `tls.bypass` event whose `library` starts with `WebViewClient.subclass:` — agent should produce a HIGH-severity finding mentioning the specific subclass.
2. **Native bypass detection**: synthetic FridaCapture with `library: "libssl.SSL_CTX_set_verify"` — agent should produce a HIGH finding.
3. **Hooks summary parsing**: synthetic capture with a `tls.hooks_summary` event — agent should enrich the finding's evidence with the probed-libraries list.
4. **Fallback hook mode**: synthetic capture containing only a `crypto.hooks_installed` event with `fallback: true` — agent should not crash but should not produce a finding (no `tls.*` events).

Plus update existing tests that mention specific hook libraries to use the new structured event format.

### NEW: `tests/unit/test_frida_agent_loader.py`

Tests for the `load_runtime_hooks()` function in `frida_runner.py`:

- When the agent file exists, returns its content
- When the agent file is missing, returns the fallback inline script and logs a warning
- Tests don't depend on Node.js — they create temp files

### NEW: `docs/FRIDA.md`

Documentation file covering:

- Architecture: where hook code lives (`frida_agent/`), where it's loaded (`frida_runner.py`), how the build works
- How to add a new pinning library hook (step-by-step with code template)
- How to rebuild the agent (`cd frida_agent && npm install && npm run build`)
- Spawn mode vs attach mode — when to use which
- Compatibility matrix: tested Frida versions (16.7.x, 17.x.x), tested Android versions, tested devices, known broken combinations (Samsung Knox/RKP + Frida 16)
- How to debug a hook that isn't firing: enable verbose Frida logging, check the `tls.hooks_summary` event, common pitfalls

## Execution order

Don't try to build everything at once. Work in this order:

1. Scaffold `frida_agent/` directory with `package.json`, `tsconfig.json`, `.gitignore`, `README.md`
2. Run `cd frida_agent && npm install` to materialise `node_modules`
3. Write `src/lib/java_ready.ts` and `src/lib/send.ts` (foundational)
4. Port the existing crypto hooks to `src/hooks/crypto.ts` and verify build succeeds: `npm run build` must produce `dist/_agent.js`
5. Port the existing OkHttp pinning hook to `src/hooks/pinning_okhttp.ts`; verify build
6. Port the existing system + library hooks to their files; verify build
7. Write the WebView subclass enumeration hook in `src/hooks/pinning_webview.ts` — most complex new file
8. Write the native hook in `src/hooks/pinning_native.ts`
9. Wire everything together in `src/agent.ts`, run final build, confirm `dist/_agent.js` is ~150–250 KB
10. Modify `sentinel/tools/frida_runner.py` — add `load_runtime_hooks()`, the `spawn` parameter, the `resume()` method
11. Modify `sentinel/core/orchestrator.py` — thread the spawn flag through to `_run_frida_subphase`
12. Modify `sentinel/cli.py` — add `--frida-spawn` option
13. Update `sentinel/agents/dynamic/cert_pinning_bypass_agent.py` to consume the new summary event
14. Write new tests in `tests/unit/test_sprint8_n005.py` and `tests/unit/test_frida_agent_loader.py`
15. Run the full test suite — must be at least 230 + new tests passing
16. Write `docs/FRIDA.md`

## Quality bar

- `poetry run ruff check sentinel tests --fix` returns clean
- `poetry run pytest tests/unit/` shows at least 235 tests passing (previous 230 + the new ones)
- `cd frida_agent && npm run build` completes without TypeScript errors
- `dist/_agent.js` exists, is between 100 KB and 400 KB, and contains the string `frida-java-bridge` (proves the bridge is bundled in)
- The fallback path works: temporarily delete `dist/_agent.js`, run `poetry run python -c "from sentinel.tools.frida_runner import ALL_RUNTIME_HOOKS; print(len(ALL_RUNTIME_HOOKS))"` — should print a small number (~1000 chars, the fallback) and log a warning. Restore the file.
- No existing test fails

## Constraints

- **Do not** change the Python public API of `FridaRunner` beyond adding the `spawn` parameter to `attach()` and the new `resume()` method
- **Do not** rename `ALL_RUNTIME_HOOKS` — orchestrator imports it by that name
- **Do not** remove the existing fallback inline hook — it's the only thing keeping SENTINEL runnable without Node.js installed
- **Do not** modify the LLM router, agents other than N_005, scope parser, memory layer, or any other phase
- **Do not** add new Python dependencies — frida 16.7+ and existing libs only
- **Do not** invent new finding categories — N_005's vuln_class strings stay the same

## Deliverables

When done, paste:
1. Output of `cd frida_agent && npm run build` (last 5 lines)
2. Output of `ls -lh frida_agent/dist/_agent.js`
3. Output of `poetry run pytest tests/unit/ 2>&1 | tail -3`
4. A short summary listing: total new files, total modified Python files, total hooks now installed (count the libraries in `pinning_libraries.ts`), and anything you intentionally skipped

Start by scaffolding `frida_agent/` and getting the TypeScript build working with just the crypto hook ported. Confirm the build artifact exists before moving on to the more complex pinning code.