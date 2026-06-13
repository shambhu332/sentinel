/*
 * D_056 — Biometric callback timing side-channel measurement.
 *
 * Hooks both onAuthenticationSucceeded and onAuthenticationFailed,
 * timestamps each entry, and reports the wall-clock delta. A
 * consistent positive delta on Succeeded vs Failed indicates that
 * the comparison is taking an input-dependent amount of time —
 * the classic non-constant-time string compare signal.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface TimingSample { event: "succeeded" | "failed"; ts: number; }
interface TimingSummary {
    samples: number;
    avg_succeeded_ms: number;
    avg_failed_ms: number;
    delta_ms: number;
    leak_indicator: boolean;
}

async function biometrictiming(
    payload: { samples?: number; differential_threshold_ms?: number; safety_budget?: any },
): Promise<TimingSummary> {
    const need = Math.min(payload.samples ?? 50, 100);
    const threshold = payload.differential_threshold_ms ?? 2;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 60;
    const samples: TimingSample[] = [];

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const CB = Java.use(
                    "androidx.biometric.BiometricPrompt$AuthenticationCallback",
                );
                CB.onAuthenticationSucceeded.implementation = function (r: any) {
                    samples.push({ event: "succeeded", ts: Date.now() });
                    return this.onAuthenticationSucceeded(r);
                };
                CB.onAuthenticationFailed.implementation = function () {
                    samples.push({ event: "failed", ts: Date.now() });
                    return this.onAuthenticationFailed();
                };
            } catch (e: any) {
                sendError(`D_056: ${e.message}`);
            }
            const start = Date.now();
            const tick = setInterval(() => {
                if (
                    samples.length >= need ||
                    Date.now() - start >= window_s * 1000
                ) {
                    clearInterval(tick);
                    const succ = samples
                        .filter((s) => s.event === "succeeded")
                        .map((s) => s.ts);
                    const fail = samples
                        .filter((s) => s.event === "failed")
                        .map((s) => s.ts);
                    const avg = (a: number[]) =>
                        a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0;
                    const sa = avg(succ);
                    const fa = avg(fail);
                    const delta = sa - fa;
                    resolve({
                        samples: samples.length,
                        avg_succeeded_ms: sa,
                        avg_failed_ms: fa,
                        delta_ms: delta,
                        leak_indicator: Math.abs(delta) >= threshold,
                    });
                }
            }, 250);
        });
    });
}

rpc.exports = { biometrictiming };
