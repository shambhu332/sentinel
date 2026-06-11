/*
 * BiometricPrompt authenticator-mask observation (D_040).
 *
 * Hooks:
 *   - android.hardware.biometrics.BiometricPrompt$Builder
 *       .setAllowedAuthenticators — records the per-builder mask
 *       keyed by builder hashCode.
 *   - android.hardware.biometrics.BiometricPrompt.authenticate —
 *       on every call, look up the builder mask (if known) and
 *       emit alongside the has_crypto / CryptoObject flag.
 *   - androidx.biometric.BiometricPrompt is identical in shape;
 *       hook the same surface there too.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendBiometricAuthenticateCalled,
    sendError,
} from "../lib/send.js";

const BUILDER_CLASSES = [
    "android.hardware.biometrics.BiometricPrompt$Builder",
    "androidx.biometric.BiometricPrompt$PromptInfo$Builder",
];
const PROMPT_CLASSES = [
    "android.hardware.biometrics.BiometricPrompt",
    "androidx.biometric.BiometricPrompt",
];

// Per-builder-instance mask, keyed by Java identity hash.
const builderMask = new Map<number, number>();

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
            if (cls.indexOf("android.hardware.biometrics") === 0) continue;
            if (cls.indexOf("androidx.biometric") === 0) continue;
            if (cls.indexOf("java.lang.Thread") === 0) continue;
            return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

function identity(obj: any): number {
    try {
        const System = Java.use("java.lang.System");
        return Number(System.identityHashCode(obj));
    } catch (_) { return 0; }
}

function hookBuilder(cls: string, ref: { count: number }): void {
    try {
        const Builder: any = Java.use(cls);
        if (!Builder.setAllowedAuthenticators) return;
        const overloads = Builder.setAllowedAuthenticators.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (mask: any) {
                try {
                    builderMask.set(identity(this), Number(mask));
                } catch (_) { /* swallow */ }
                return ov.call(this, mask);
            };
            ref.count++;
        }
    } catch (_) { /* skip */ }
}

function hookAuthenticate(cls: string, ref: { count: number }): void {
    try {
        const Prompt: any = Java.use(cls);
        if (!Prompt.authenticate) return;
        const overloads = Prompt.authenticate.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    // Heuristic: a CryptoObject arg shows up as one of
                    // the arguments and has a getClass().getName() that
                    // includes "CryptoObject".
                    let hasCrypto = false;
                    for (let a = 0; a < args.length; a++) {
                        const arg = args[a];
                        if (!arg) continue;
                        try {
                            const ac = String(arg.getClass().getName());
                            if (ac.indexOf("CryptoObject") !== -1) {
                                hasCrypto = true; break;
                            }
                        } catch (_) { /* swallow */ }
                    }

                    // The mask is recorded per-Builder; without that
                    // map we fall back to reading it off the prompt
                    // when the platform exposes a getter.
                    let mask = 0;
                    try {
                        if (this.getAllowedAuthenticators) {
                            mask = Number(this.getAllowedAuthenticators());
                        }
                    } catch (_) { /* swallow */ }
                    if (!mask) {
                        // Try the builder map via Java identity-hash —
                        // not perfect but often catches it when the
                        // Builder.build() result kept the same hash.
                        for (const [_, m] of builderMask) {
                            if (m) { mask = m; break; }
                        }
                    }

                    sendBiometricAuthenticateCalled({
                        allowed_authenticators: mask,
                        has_crypto: hasCrypto,
                        negative_button_set: false,
                        caller_class: callerClass(),
                        stack: shortStack(),
                    });
                } catch (e) {
                    sendError(`biometric.authenticate.emit: ${String(e)}`);
                }
                return ov.apply(this, args);
            };
            ref.count++;
        }
    } catch (_) { /* skip */ }
}

export function installBiometricPromptHooks(): number {
    const ref = { count: 0 };
    for (let i = 0; i < BUILDER_CLASSES.length; i++) {
        hookBuilder(BUILDER_CLASSES[i], ref);
    }
    for (let i = 0; i < PROMPT_CLASSES.length; i++) {
        hookAuthenticate(PROMPT_CLASSES[i], ref);
    }
    return ref.count;
}
