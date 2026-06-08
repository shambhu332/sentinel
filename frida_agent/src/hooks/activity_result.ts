/*
 * Activity setResult observation (D_034).
 *
 * Hooks:
 *   - android.app.Activity.setResult(int)
 *   - android.app.Activity.setResult(int, Intent)
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendActivitySetResult, sendError } from "../lib/send.js";

const SENSITIVE_KEYWORDS = [
    "token", "secret", "password", "cookie", "auth",
    "bearer", "otp", "account", "email", "phone", "ssn",
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

function ownPackage(activity: any): string {
    try {
        const ctx = activity.getApplicationContext();
        return ctx ? String(ctx.getPackageName()) : "";
    } catch (_) { return ""; }
}

function callingPackage(activity: any): string {
    try {
        const pkg = activity.getCallingPackage();
        return pkg ? String(pkg) : "";
    } catch (_) { return ""; }
}

function extrasInfo(intent: any): { keys: string[]; sensitive: string[] } {
    if (!intent) return { keys: [], sensitive: [] };
    try {
        const extras = intent.getExtras();
        if (!extras) return { keys: [], sensitive: [] };
        const keyset = extras.keySet();
        const iter = keyset.iterator();
        const keys: string[] = [];
        const sensitive: string[] = [];
        while (iter.hasNext()) {
            const k = String(iter.next());
            keys.push(k);
            const lower = k.toLowerCase();
            for (let i = 0; i < SENSITIVE_KEYWORDS.length; i++) {
                if (lower.indexOf(SENSITIVE_KEYWORDS[i]) !== -1) {
                    sensitive.push(k);
                    break;
                }
            }
        }
        return { keys, sensitive };
    } catch (_) { return { keys: [], sensitive: [] }; }
}

function emit(activity: any, code: number, intent: any): void {
    try {
        const info = extrasInfo(intent);
        sendActivitySetResult({
            activity_class: String(activity.getClass().getName()),
            result_code: code,
            extras_keys: info.keys,
            extras_sensitive: info.sensitive,
            calling_package: callingPackage(activity),
            own_package: ownPackage(activity),
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`activity.set_result: ${String(e)}`);
    }
}

export function installActivityResultHooks(): number {
    let installed = 0;
    try {
        const Activity = Java.use("android.app.Activity");

        const ovInt = Activity.setResult.overload("int");
        ovInt.implementation = function (code: number) {
            try { emit(this, code, null); } catch (_) { /* swallow */ }
            return ovInt.call(this, code);
        };
        installed++;

        const ovIntIntent = Activity.setResult.overload(
            "int", "android.content.Intent",
        );
        ovIntIntent.implementation = function (code: number, intent: any) {
            try { emit(this, code, intent); } catch (_) { /* swallow */ }
            return ovIntIntent.call(this, code, intent);
        };
        installed++;
    } catch (_) { /* skip */ }
    return installed;
}
