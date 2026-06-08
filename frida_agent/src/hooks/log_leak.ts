/*
 * Log / local-file leak observation (D_035).
 *
 * Hooks:
 *   - android.util.Log.{v,d,i,w,e}(String, String) and the
 *     (String, String, Throwable) overloads.
 *   - java.io.FileOutputStream.<init>(File) / (String) — capture
 *     the target path so the Python side can flag writes outside
 *     the app's private dir.
 *
 * Sensitive shape detection is regex-based and runs before the
 * message body is redacted in the emitted event.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendLogLineEmitted, sendError } from "../lib/send.js";

const PATTERNS: Array<{ label: string; re: RegExp }> = [
    {
        label: "jwt",
        re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
    },
    { label: "bearer", re: /\bBearer\s+[A-Za-z0-9._\-]{16,}\b/i },
    { label: "password_field", re: /\bpassword\s*[=:]\s*\S+/i },
    { label: "credit_card", re: /\b(?:\d[ -]?){13,19}\b/ },
    { label: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
    { label: "phone", re: /\+?\d[\d\s\-().]{8,}\d/ },
    { label: "base64_secret", re: /\b[A-Za-z0-9+/]{40,}={0,2}\b/ },
];

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

function redact(text: string): string {
    if (!text) return "";
    if (text.length <= 80) return text;
    return text.substring(0, 32) + "…(redacted " + text.length + " chars)…"
        + text.substring(text.length - 16);
}

function classify(text: string): string[] {
    if (!text) return [];
    const out: string[] = [];
    for (let i = 0; i < PATTERNS.length; i++) {
        if (PATTERNS[i].re.test(text)) out.push(PATTERNS[i].label);
    }
    return out;
}

function emitLog(level: string, tag: any, message: any): void {
    try {
        const tagStr = tag === null || tag === undefined ? "" : String(tag);
        const msg = message === null || message === undefined
            ? "" : String(message);
        const shapes = classify(msg);
        // Only emit if there is something to flag — keeps the
        // event stream cheap on chatty apps.
        if (shapes.length === 0 && msg.length < 256) return;
        sendLogLineEmitted({
            api: "Log",
            level,
            tag: tagStr,
            message_redacted: redact(msg),
            sensitive_shapes: shapes,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`log.emit: ${String(e)}`);
    }
}

function wrapLogLevel(LogCls: any, methodName: string, level: string,
                     installedRef: { count: number }): void {
    if (!LogCls[methodName] || !LogCls[methodName].overloads) return;
    const overloads = LogCls[methodName].overloads;
    for (let i = 0; i < overloads.length; i++) {
        const ov = overloads[i];
        ov.implementation = function (...args: any[]) {
            try { emitLog(level, args[0], args[1]); }
            catch (_) { /* swallow */ }
            return ov.apply(this, args);
        };
        installedRef.count++;
    }
}

export function installLogLeakHooks(): number {
    const ref = { count: 0 };

    try {
        const Log = Java.use("android.util.Log");
        wrapLogLevel(Log, "v", "VERBOSE", ref);
        wrapLogLevel(Log, "d", "DEBUG", ref);
        wrapLogLevel(Log, "i", "INFO", ref);
        wrapLogLevel(Log, "w", "WARN", ref);
        wrapLogLevel(Log, "e", "ERROR", ref);
    } catch (_) { /* skip */ }

    // FileOutputStream — emit target_path on init.
    try {
        const FOS = Java.use("java.io.FileOutputStream");
        const overloads = FOS.$init ? FOS.$init.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    let target = "";
                    const first = args[0];
                    if (first && typeof first === "string") {
                        target = first;
                    } else if (first && typeof first.getAbsolutePath === "function") {
                        target = String(first.getAbsolutePath());
                    }
                    if (target) {
                        sendLogLineEmitted({
                            api: "FileOutputStream",
                            target_path: target,
                            sensitive_shapes: [],
                            stack: shortStack(),
                        });
                    }
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            ref.count++;
        }
    } catch (_) { /* skip */ }

    return ref.count;
}
