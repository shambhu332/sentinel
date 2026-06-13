/*
 * D_046 — Race-condition trigger.
 *
 * The Python-side `RaceConditionTargetAgent` identifies candidate
 * methods statically and emits `frida_payload` blocks describing
 * which Java method to fire concurrently. This script consumes that
 * payload (passed in via `rpc.exports.triggerRace`) and fires the
 * configured number of parallel invocations against the named method.
 *
 * Each invocation runs on its own JVM-attached thread via
 * `Java.scheduleOnMainThread`-aware async dispatch so the JVM sees
 * genuinely concurrent calls rather than serialised microtasks.
 *
 * Safety rails:
 *   - Hard cap of 32 parallel invocations regardless of payload
 *   - 30-second wall-clock budget; remaining iterations are dropped
 *   - Per-invocation exception is caught + reported (one event each),
 *     never thrown back to the JS runtime — a crashed iteration must
 *     not kill the script
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

// Mirror the SafetyConfig from the Python side for predictable behaviour.
const HARD_CAP_PARALLEL = 32;
const WALL_CLOCK_BUDGET_MS = 30_000;

interface RacePayload {
    class_simple_name: string;
    method_name: string;
    param_types: string[];
    args_template?: any[];
    n_parallel?: number;
    interval_ms?: number;
}

interface RaceResult {
    fired: number;
    succeeded: number;
    failed: number;
    distinct_results: string[];
    duration_ms: number;
}

async function triggerRace(payload: RacePayload): Promise<RaceResult> {
    const start = Date.now();
    const fired = Math.min(payload.n_parallel ?? 10, HARD_CAP_PARALLEL);
    const interval = Math.max(0, payload.interval_ms ?? 0);
    const results: { ok: boolean; out: string }[] = [];

    return new Promise((resolve) => {
        Java.perform(() => {
            let cls: any;
            try {
                cls = Java.use(payload.class_simple_name);
            } catch (e: any) {
                sendError(
                    `D_046 trigger: class ${payload.class_simple_name} not found: ${e.message}`,
                );
                resolve(emptyResult(start));
                return;
            }

            let method: any;
            try {
                method = (cls as any)[payload.method_name];
                if (payload.param_types.length) {
                    method = method.overload(...payload.param_types);
                }
            } catch (e: any) {
                sendError(
                    `D_046 trigger: method ${payload.method_name}(${payload.param_types.join(",")}) not resolvable: ${e.message}`,
                );
                resolve(emptyResult(start));
                return;
            }

            let inFlight = 0;
            let started = 0;
            const args = payload.args_template ?? [];

            const fireOne = () => {
                if (Date.now() - start > WALL_CLOCK_BUDGET_MS) return;
                if (started >= fired) return;
                started++;
                inFlight++;
                setTimeout(() => {
                    try {
                        const out = method.apply(cls.$new ? cls.$new() : cls, args);
                        results.push({ ok: true, out: String(out) });
                    } catch (e: any) {
                        results.push({ ok: false, out: e.message ?? String(e) });
                    } finally {
                        inFlight--;
                        if (inFlight === 0 && started >= fired) {
                            resolve(summarise(results, start));
                        } else {
                            fireOne();
                        }
                    }
                }, interval);
            };

            // Kick off all parallel iterations
            for (let i = 0; i < fired; i++) fireOne();
        });
    });
}

function emptyResult(start: number): RaceResult {
    return {
        fired: 0,
        succeeded: 0,
        failed: 0,
        distinct_results: [],
        duration_ms: Date.now() - start,
    };
}

function summarise(
    results: { ok: boolean; out: string }[],
    start: number,
): RaceResult {
    const succeeded = results.filter((r) => r.ok).length;
    const failed = results.length - succeeded;
    const distinct = Array.from(new Set(results.map((r) => r.out))).slice(0, 20);
    return {
        fired: results.length,
        succeeded,
        failed,
        distinct_results: distinct,
        duration_ms: Date.now() - start,
    };
}

// Frida RPC surface — Python side calls `script.exports.triggerRace(payload)`.
rpc.exports = {
    triggerrace: triggerRace,
};
