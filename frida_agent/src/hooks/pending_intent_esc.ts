/*
 * D_073 — PendingIntent escalation probe.
 *
 * Hooks PendingIntent.send(...) overloads and, for each observed send,
 * tries to dispatch a fillIn Intent carrying a harmless sentinel extra.
 * If Android accepts the fillIn Intent, the token is mutable enough for
 * an attacker-controlled recipient to influence extras at dispatch time.
 *
 * Safety:
 *   - probe value is a fixed benign string: SENTINEL_PROBE
 *   - no component/action/data rewrites
 *   - bounded action count / wall-clock / consecutive failures
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface PendingIntentProbePayload {
    type?: string;
    class_name?: string;
    probe_extra_key?: string;
    probe_extra_value?: string;
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
    };
}

interface PendingIntentProbeResult {
    attempted: number;
    injection_succeeded: number;
    injection_failed: number;
    samples: any[];
    duration_ms: number;
    tripped: boolean;
    trip_reason?: string;
}

const HARD_CAP = 20;

export async function pendingIntentEscalationProbe(
    payload: PendingIntentProbePayload,
): Promise<PendingIntentProbeResult> {
    const start = Date.now();
    const budget = payload.safety_budget ?? {};
    const maxTotal = Math.min(budget.max_actions_total ?? 20, HARD_CAP);
    const wallClockMs = (budget.wall_clock_budget_s ?? 30) * 1000;
    const maxCrashes = budget.max_consecutive_crashes ?? 3;
    const key = payload.probe_extra_key ?? "sentinel_probe";
    const value = payload.probe_extra_value ?? "SENTINEL_PROBE";

    let attempted = 0;
    let ok = 0;
    let failed = 0;
    let consecutiveFailures = 0;
    let tripReason: string | undefined;
    let installingProbe = false;
    const samples: any[] = [];

    return new Promise((resolve) => {
        Java.perform(() => {
            let PendingIntent: any;
            let Intent: any;
            let appContext: any;
            try {
                PendingIntent = Java.use("android.app.PendingIntent");
                Intent = Java.use("android.content.Intent");
                const ActivityThread = Java.use("android.app.ActivityThread");
                appContext = ActivityThread.currentApplication()
                    .getApplicationContext();
            } catch (e: any) {
                sendError(`D_073: required class missing: ${e.message}`);
                resolve(summary());
                return;
            }

            const originalNoArg = PendingIntent.send.overload();
            originalNoArg.implementation = function () {
                probe(this, Intent, appContext, "send()");
                return originalNoArg.call(this);
            };

            const overloads = PendingIntent.send.overloads;
            overloads.forEach((overload: any) => {
                if (overload.argumentTypes.length === 0) return;
                overload.implementation = function (...args: any[]) {
                    probe(
                        this,
                        Intent,
                        appContext,
                        `send/${overload.argumentTypes.length}`,
                    );
                    return overload.apply(this, args);
                };
            });

            send({
                kind: "pending_intent.probe_installed",
                payload: {
                    agent_id: "D_073",
                    class_name: payload.class_name ?? "",
                    max_actions_total: maxTotal,
                },
            });
            setTimeout(() => resolve(summary()), wallClockMs);
        });
    });

    function probe(pi: any, IntentCls: any, context: any, overload: string): void {
        if (installingProbe) return;
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
        try {
            installingProbe = true;
            const fillIn = IntentCls.$new();
            fillIn.putExtra(key, value);
            pi.send(context, 0, fillIn);
            installingProbe = false;
            ok++;
            consecutiveFailures = 0;
            record({
                overload,
                injection_succeeded: true,
                extra_key: key,
                extra_value: value,
            });
            send({
                kind: "pending_intent.probe_result",
                payload: {
                    agent_id: "D_073",
                    type: "pending_intent_probe",
                    class_name: payload.class_name ?? "",
                    injection_succeeded: true,
                    overload,
                    extra_key: key,
                },
            });
        } catch (e: any) {
            installingProbe = false;
            failed++;
            consecutiveFailures++;
            const error = e.message?.slice(0, 200) ?? String(e);
            record({
                overload,
                injection_succeeded: false,
                error,
            });
            send({
                kind: "pending_intent.probe_result",
                payload: {
                    agent_id: "D_073",
                    type: "pending_intent_probe",
                    class_name: payload.class_name ?? "",
                    injection_succeeded: false,
                    overload,
                    error,
                },
            });
        }
    }

    function record(sample: any): void {
        if (samples.length < 10) samples.push(sample);
    }

    function summary(): PendingIntentProbeResult {
        return {
            attempted,
            injection_succeeded: ok,
            injection_failed: failed,
            samples,
            duration_ms: Date.now() - start,
            tripped: tripReason !== undefined,
            trip_reason: tripReason,
        };
    }
}

rpc.exports = {
    ...(rpc.exports as any),
    pendingintentesc: pendingIntentEscalationProbe,
};
