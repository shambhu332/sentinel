/*
 * BiometricPrompt hooks (D_003).
 *
 * We instrument BiometricPrompt.Builder so we observe the *final*
 * configuration of every prompt the app builds at runtime:
 *
 *   setAllowedAuthenticators(int)            — bitmask
 *   setDeviceCredentialAllowed(boolean)      — legacy pre-API-30 path
 *   setNegativeButtonText(CharSequence, ...) — best-effort label
 *   build()                                  — flush a single event,
 *                                              also re-fired on
 *                                              authenticate(CryptoObject)
 *
 * One event per build() call. The Python BiometricWeakAgent classifies
 * the bitmask and decides severity.
 */
import { Java } from "../lib/java_ready.js";
import { sendBiometricPrompt, sendError } from "../lib/send.js";

const NO_AUTHENTICATORS = -1;

interface PromptState {
    authenticators: number;
    device_credential_allowed: boolean;
    negative_button: string;
}

function freshState(): PromptState {
    return {
        authenticators: NO_AUTHENTICATORS,
        device_credential_allowed: false,
        negative_button: "",
    };
}

function currentActivity(): string {
    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const at = ActivityThread.currentActivityThread();
        const records = at.mActivities.value;
        const keys = records.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {
            const rec = records.get(keys[i]);
            if (!rec.paused.value) {
                return String(rec.activity.value.getClass().getName());
            }
        }
    } catch (_e) { /* swallow */ }
    return "<unknown>";
}

export function installBiometricHooks(): number {
    let installed = 0;
    // Map Builder hash → in-progress state. Allocated lazily because
    // BiometricPrompt.Builder is API 28+.
    const states = new Map<number, PromptState>();

    try {
        const Builder = Java.use("android.hardware.biometrics.BiometricPrompt$Builder");

        Builder.setAllowedAuthenticators.implementation = function (auth: number) {
            const k = (this as any).$h ?? 0;
            const s = states.get(k) ?? freshState();
            s.authenticators = auth;
            states.set(k, s);
            return this.setAllowedAuthenticators(auth);
        };
        installed++;

        try {
            Builder.setDeviceCredentialAllowed.implementation = function (b: boolean) {
                const k = (this as any).$h ?? 0;
                const s = states.get(k) ?? freshState();
                s.device_credential_allowed = !!b;
                states.set(k, s);
                return this.setDeviceCredentialAllowed(b);
            };
            installed++;
        } catch (_) { /* method removed in API 30+ */ }

        try {
            Builder.setNegativeButton.overload(
                "java.lang.CharSequence",
                "java.util.concurrent.Executor",
                "android.content.DialogInterface$OnClickListener",
            ).implementation = function (txt: any, exec: any, l: any) {
                const k = (this as any).$h ?? 0;
                const s = states.get(k) ?? freshState();
                s.negative_button = String(txt || "");
                states.set(k, s);
                return this.setNegativeButton(txt, exec, l);
            };
            installed++;
        } catch (_) { /* overload may differ */ }

        Builder.build.implementation = function () {
            const built = this.build();
            try {
                const k = (this as any).$h ?? 0;
                const s = states.get(k) ?? freshState();
                sendBiometricPrompt({
                    activity: currentActivity(),
                    authenticators: s.authenticators === NO_AUTHENTICATORS
                        ? undefined : s.authenticators,
                    device_credential_allowed: s.device_credential_allowed,
                    crypto_object: false, // resolved at authenticate()
                    negative_button: s.negative_button,
                });
                states.delete(k);
            } catch (e) {
                sendError(`biometric.build hook: ${String(e)}`);
            }
            return built;
        };
        installed++;

        // authenticate(CryptoObject, …) re-fires the event with
        // crypto_object=true so the agent can tell key-bound prompts
        // apart from yes/no prompts.
        try {
            const BiometricPrompt = Java.use(
                "android.hardware.biometrics.BiometricPrompt",
            );
            const overloads = BiometricPrompt.authenticate.overloads;
            for (let i = 0; i < overloads.length; i++) {
                const params = overloads[i].argumentTypes;
                const bound = params.some(
                    (p: any) => String(p.className).indexOf("CryptoObject") !== -1,
                );
                if (!bound) continue;
                overloads[i].implementation = function (...args: any[]) {
                    try {
                        sendBiometricPrompt({
                            activity: currentActivity(),
                            crypto_object: true,
                        });
                    } catch (e) {
                        sendError(`biometric.authenticate hook: ${String(e)}`);
                    }
                    return overloads[i].apply(this, args);
                };
                installed++;
            }
        } catch (_) { /* class absent — fine */ }
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") === -1) {
            sendError(`biometric install: ${msg}`);
        }
    }
    return installed;
}
