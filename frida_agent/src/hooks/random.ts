/*
 * Insecure RNG consumption observation (D_028).
 *
 * Hooks:
 *   - java.util.Random.nextInt / nextLong / nextBytes / nextDouble
 *   - java.lang.Math.random
 *   - java.security.SecureRandom.setSeed (the byte[] overload — a
 *     caller-supplied seed defeats the OS entropy injection).
 *
 * Each call emits one random.observation event tagged with the api
 * label, the byte count where applicable, the calling class, and a
 * security_context_hint derived from the calling class + method name.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendRandomObservation, sendError } from "../lib/send.js";

const SECURITY_KEYWORDS = [
    "token", "otp", "nonce", "session", "csrf",
    "key", "iv", "salt", "password", "secret",
    "challenge", "credential",
];

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 5; i++) {
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
            if (cls.indexOf("java.util.Random") === 0) continue;
            if (cls.indexOf("java.lang.Math") === 0) continue;
            if (cls.indexOf("java.security.SecureRandom") === 0) continue;
            if (cls.indexOf("java.lang.Thread") === 0) continue;
            return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

function securityHint(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length && i < 12; i++) {
            const cls = String(frames[i].getClassName()).toLowerCase();
            const meth = String(frames[i].getMethodName()).toLowerCase();
            const probe = `${cls}.${meth}`;
            for (let k = 0; k < SECURITY_KEYWORDS.length; k++) {
                if (probe.indexOf(SECURITY_KEYWORDS[k]) !== -1) {
                    return SECURITY_KEYWORDS[k];
                }
            }
        }
    } catch (_) { /* swallow */ }
    return "";
}

function emit(api: string, byteCount?: number): void {
    try {
        sendRandomObservation({
            api,
            byte_count: byteCount,
            caller_class: callerClass(),
            security_context_hint: securityHint(),
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`random.emit: ${String(e)}`);
    }
}

export function installRandomHooks(): number {
    let installed = 0;

    try {
        const Random = Java.use("java.util.Random");

        const wrapAll = (methodName: string, label: string,
                         byteCounter?: (args: any[]) => number) => {
            const m = (Random as any)[methodName];
            if (!m || !m.overloads) return;
            for (let i = 0; i < m.overloads.length; i++) {
                const ov = m.overloads[i];
                ov.implementation = function (...args: any[]) {
                    try {
                        emit(label, byteCounter ? byteCounter(args) : undefined);
                    } catch (_) { /* swallow */ }
                    return ov.apply(this, args);
                };
                installed++;
            }
        };

        wrapAll("nextInt",   "Random.nextInt",    () => 4);
        wrapAll("nextLong",  "Random.nextLong",   () => 8);
        wrapAll("nextDouble", "Random.nextDouble", () => 8);
        wrapAll("nextBytes", "Random.nextBytes",  (a: any[]) => {
            try { return a[0] ? Number(a[0].length) : 0; }
            catch (_) { return 0; }
        });
    } catch (_) { /* skip */ }

    try {
        const Math = Java.use("java.lang.Math");
        Math.random.implementation = function () {
            try { emit("Math.random", 8); }
            catch (_) { /* swallow */ }
            return this.random();
        };
        installed++;
    } catch (_) { /* skip */ }

    try {
        const SR = Java.use("java.security.SecureRandom");
        const ov = SR.setSeed.overload("[B");
        ov.implementation = function (seed: any) {
            try {
                const n = seed ? Number(seed.length) : 0;
                emit("SecureRandom.setSeed", n);
            } catch (_) { /* swallow */ }
            return ov.call(this, seed);
        };
        installed++;
    } catch (_) { /* skip */ }

    return installed;
}
