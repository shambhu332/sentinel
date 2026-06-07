/*
 * Keystore key-generation observation (D_026).
 *
 * Hook:
 *   - android.security.keystore.KeyGenParameterSpec$Builder.build()
 *
 * For every constructed spec we read the security-relevant getters on
 * the returned KeyGenParameterSpec — alias, purposes, user-auth flags,
 * StrongBox binding, validity-duration window — and emit one event.
 * The getters that landed in later API levels (isStrongBoxBacked,
 * isUserConfirmationRequired — API 28+) are looked up reflectively so
 * the hook still runs on older devices.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendKeystoreKeySpecBuilt, sendError } from "../lib/send.js";

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

function callBool(spec: any, method: string): boolean | null {
    try {
        if (typeof spec[method] !== "function") return null;
        return Boolean(spec[method]());
    } catch (_) { return null; }
}

function callInt(spec: any, method: string): number | null {
    try {
        if (typeof spec[method] !== "function") return null;
        const v = Number(spec[method]());
        if (!Number.isFinite(v)) return null;
        return v;
    } catch (_) { return null; }
}

function callString(spec: any, method: string): string {
    try {
        if (typeof spec[method] !== "function") return "";
        return String(spec[method]() || "");
    } catch (_) { return ""; }
}

function inspectSpec(spec: any): void {
    if (!spec) return;
    try {
        const alias = callString(spec, "getKeystoreAlias");
        const purposes = callInt(spec, "getPurposes");
        const userAuth = callBool(spec, "isUserAuthenticationRequired");
        const invalidated = callBool(
            spec, "isInvalidatedByBiometricEnrollment",
        );
        const strongBox = callBool(spec, "isStrongBoxBacked");
        const validity = callInt(
            spec, "getUserAuthenticationValidityDurationSeconds",
        );
        const confirmation = callBool(
            spec, "isUserConfirmationRequired",
        );

        sendKeystoreKeySpecBuilt({
            alias,
            purposes: purposes === null ? undefined : purposes,
            user_auth_required: userAuth === null ? false : userAuth,
            invalidated_by_biometric_enrollment: invalidated,
            strong_box_backed: strongBox,
            validity_duration_seconds: validity,
            user_confirmation_required: confirmation,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`keystore.inspect: ${String(e)}`);
    }
}

export function installKeystoreHooks(): number {
    let installed = 0;
    try {
        const Builder = Java.use(
            "android.security.keystore.KeyGenParameterSpec$Builder",
        );
        const overloads = Builder.build ? Builder.build.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                const spec = ov.apply(this, args);
                try { inspectSpec(spec); }
                catch (_) { /* swallow */ }
                return spec;
            };
            installed++;
        }
    } catch (_) { /* skip — class missing on very old devices */ }
    return installed;
}
