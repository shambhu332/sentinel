/*
 * Dynamic code-loading hooks (D_005).
 *
 * Watches every entry point an app can use to run code that isn't in
 * the APK's classes.dex / native libs:
 *
 *   - dalvik.system.DexClassLoader.<init>
 *   - dalvik.system.PathClassLoader.<init>
 *   - dalvik.system.InMemoryDexClassLoader.<init>
 *   - java.lang.System.load
 *   - java.lang.System.loadLibrary (filtered for absolute paths)
 *   - java.lang.Runtime.exec(String)
 *
 * Each hook emits a single event with the resolved path and a short
 * caller stack. The Python DynamicCodeLoadingAgent classifies the
 * source as external / network / private and assigns severity.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendDexLoad,
    sendNativeLoad,
    sendRuntimeExec,
    sendError,
} from "../lib/send.js";

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 6; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

export function installCodeLoadingHooks(): number {
    let installed = 0;

    // ---- DexClassLoader ----
    try {
        const DexCL = Java.use("dalvik.system.DexClassLoader");
        DexCL.$init.overload(
            "java.lang.String", "java.lang.String",
            "java.lang.String", "java.lang.ClassLoader",
        ).implementation = function (
            dexPath: string, optDir: string,
            libPath: string, parent: any,
        ) {
            try {
                sendDexLoad({
                    loader_class: "dalvik.system.DexClassLoader",
                    path: String(dexPath),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`code.dex hook: ${String(e)}`);
            }
            return this.$init(dexPath, optDir, libPath, parent);
        };
        installed++;
    } catch (_) { /* overload may differ */ }

    // ---- PathClassLoader ----
    try {
        const PathCL = Java.use("dalvik.system.PathClassLoader");
        PathCL.$init.overload(
            "java.lang.String", "java.lang.ClassLoader",
        ).implementation = function (path: string, parent: any) {
            try {
                sendDexLoad({
                    loader_class: "dalvik.system.PathClassLoader",
                    path: String(path),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`code.path hook: ${String(e)}`);
            }
            return this.$init(path, parent);
        };
        installed++;
    } catch (_) { /* overload may differ */ }

    // ---- InMemoryDexClassLoader ----
    try {
        const IMDexCL = Java.use("dalvik.system.InMemoryDexClassLoader");
        const overloads = IMDexCL.$init.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    sendDexLoad({
                        loader_class: "dalvik.system.InMemoryDexClassLoader",
                        path: "<in-memory>",
                        stack: shortStack(),
                    });
                } catch (e) {
                    sendError(`code.imdex hook: ${String(e)}`);
                }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* API 26+ only */ }

    // ---- System.load(absolute path) ----
    try {
        const System = Java.use("java.lang.System");
        System.load.implementation = function (path: string) {
            try {
                sendNativeLoad({
                    loader_class: "java.lang.System.load",
                    path: String(path),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`code.system.load hook: ${String(e)}`);
            }
            return this.load(path);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- Runtime.exec(String) ----
    try {
        const Runtime = Java.use("java.lang.Runtime");
        const overload = Runtime.exec.overload("java.lang.String");
        overload.implementation = function (cmd: string) {
            try {
                sendRuntimeExec({
                    loader_class: "java.lang.Runtime.exec",
                    path: String(cmd),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`code.runtime.exec hook: ${String(e)}`);
            }
            return overload.call(this, cmd);
        };
        installed++;
    } catch (_) { /* anti-tamper hook may have already taken this */ }

    return installed;
}
