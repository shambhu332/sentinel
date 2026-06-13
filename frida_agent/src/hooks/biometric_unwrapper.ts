/*
 * D_078 — Biometric CryptoObject unwrapper probe.
 *
 * Hooks BiometricPrompt.CryptoObject.getCipher() and performs one
 * bounded Cipher.doFinal probe against the returned initialized Cipher.
 * The hook never extracts key material and never launches UI. It only
 * reports whether the already-unwrapped Cipher remains usable after the
 * app retrieves it from the CryptoObject.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface BiometricUnwrapPayload {
    type?: string;
    class_name?: string;
    test_ciphertext_b64?: string;
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
    };
}

interface BiometricUnwrapSample {
    crypto_object_class: string;
    algorithm?: string;
    provider?: string;
    probe_succeeded: boolean;
    output_len?: number;
    error?: string;
}

interface BiometricUnwrapSummary {
    attempted: number;
    succeeded: number;
    failed: number;
    samples: BiometricUnwrapSample[];
    duration_ms: number;
    tripped: boolean;
    trip_reason?: string;
}

const HARD_CAP = 5;

export async function biometricUnwrapper(
    payload: BiometricUnwrapPayload,
): Promise<BiometricUnwrapSummary> {
    const start = Date.now();
    const budget = payload.safety_budget ?? {};
    const maxTotal = Math.min(budget.max_actions_total ?? 5, HARD_CAP);
    const wallClockMs = (budget.wall_clock_budget_s ?? 30) * 1000;
    const maxCrashes = budget.max_consecutive_crashes ?? 2;
    const samples: BiometricUnwrapSample[] = [];
    let attempted = 0;
    let succeeded = 0;
    let failed = 0;
    let consecutiveFailures = 0;
    let tripReason: string | undefined;

    return new Promise((resolve) => {
        Java.perform(() => {
            let Base64: any;
            try {
                Base64 = Java.use("android.util.Base64");
            } catch (e: any) {
                sendError(`D_078: android.util.Base64 missing: ${e.message}`);
                resolve(summary());
                return;
            }

            const installed = [
                hookCryptoObject(
                    "android.hardware.biometrics.BiometricPrompt$CryptoObject",
                    Base64,
                ),
                hookCryptoObject(
                    "androidx.biometric.BiometricPrompt$CryptoObject",
                    Base64,
                ),
            ].filter(Boolean).length;

            send({
                kind: "biometric_unwrapper.probe_installed",
                payload: {
                    agent_id: "D_078",
                    class_name: payload.class_name ?? "",
                    hooked_classes: installed,
                    max_actions_total: maxTotal,
                },
            });
            setTimeout(() => resolve(summary()), wallClockMs);
        });
    });

    function hookCryptoObject(className: string, Base64Cls: any): boolean {
        try {
            const CryptoObject = Java.use(className);
            const getCipher = CryptoObject.getCipher.overload();
            getCipher.implementation = function () {
                const cipher = getCipher.call(this);
                probeCipher(className, cipher, Base64Cls);
                return cipher;
            };
            return true;
        } catch (_) {
            return false;
        }
    }

    function probeCipher(
        cryptoObjectClass: string,
        cipher: any,
        Base64Cls: any,
    ): void {
        if (cipher === null || cipher === undefined) return;
        if (attempted >= maxTotal || Date.now() - start > wallClockMs) {
            tripReason = attempted >= maxTotal
                ? "max_actions_total exceeded"
                : "wall_clock_budget exceeded";
            return;
        }
        if (consecutiveFailures >= maxCrashes) {
            tripReason = `max_consecutive_crashes ${maxCrashes} tripped`;
            return;
        }

        attempted++;
        const sample: BiometricUnwrapSample = {
            crypto_object_class: cryptoObjectClass,
            algorithm: safeString(() => cipher.getAlgorithm()),
            provider: safeString(() => cipher.getProvider().getName()),
            probe_succeeded: false,
        };
        try {
            const input = probeBytes(Base64Cls);
            const output = cipher.doFinal(input);
            sample.probe_succeeded = true;
            sample.output_len = output ? output.length : 0;
            succeeded++;
            consecutiveFailures = 0;
        } catch (e: any) {
            failed++;
            consecutiveFailures++;
            sample.error = (e.message ?? String(e)).slice(0, 200);
        }
        if (samples.length < 10) samples.push(sample);
        send({
            kind: "biometric_unwrapper.probe_result",
            payload: {
                agent_id: "D_078",
                type: "biometric_unwrap_probe",
                class_name: payload.class_name ?? "",
                ...sample,
            },
        });
    }

    function probeBytes(Base64Cls: any): any {
        const encoded = payload.test_ciphertext_b64 ?? "";
        if (encoded.length > 0) {
            return Base64Cls.decode(encoded, 0);
        }
        return Java.array("byte", []);
    }

    function summary(): BiometricUnwrapSummary {
        return {
            attempted,
            succeeded,
            failed,
            samples,
            duration_ms: Date.now() - start,
            tripped: tripReason !== undefined,
            trip_reason: tripReason,
        };
    }
}

function safeString(fn: () => any): string | undefined {
    try {
        const value = fn();
        if (value === null || value === undefined) return undefined;
        return String(value);
    } catch (_) {
        return undefined;
    }
}

rpc.exports = {
    ...(rpc.exports as any),
    biometricunwrapper: biometricUnwrapper,
};
