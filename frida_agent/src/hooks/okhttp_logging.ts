/*
 * OkHttp HttpLoggingInterceptor level observation (D_039).
 *
 * Hook:
 *   - okhttp3.logging.HttpLoggingInterceptor.intercept — reads the
 *     interceptor's current Level via getLevel() on every call and
 *     emits one event per (interceptor, level) pair.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendOkhttpLoggingLevel,
    sendError,
} from "../lib/send.js";

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 4; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

function callerClass(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            if (cls.indexOf("okhttp3.") === 0) continue;
            if (cls.indexOf("java.lang.Thread") === 0) continue;
            return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

const seen = new Set<string>();

function emit(interceptor: any): void {
    try {
        let level = "";
        try { level = String(interceptor.getLevel()); }
        catch (_) { return; }
        if (!level || level === "NONE" || level === "BASIC") return;

        const cls = String(interceptor.getClass().getName());
        const key = `${cls}#${level}`;
        if (seen.has(key)) return;
        seen.add(key);

        sendOkhttpLoggingLevel({
            level,
            interceptor_class: cls,
            caller_class: callerClass(),
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`okhttp.logging.emit: ${String(e)}`);
    }
}

export function installOkhttpLoggingHooks(): number {
    let installed = 0;
    try {
        const HLI = Java.use(
            "okhttp3.logging.HttpLoggingInterceptor",
        );
        if (!HLI.intercept) return 0;
        const overloads = HLI.intercept.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (chain: any) {
                try { emit(this); } catch (_) { /* swallow */ }
                return ov.call(this, chain);
            };
            installed++;
        }
    } catch (_) { /* skip — OkHttp logging not bundled */ }
    return installed;
}
