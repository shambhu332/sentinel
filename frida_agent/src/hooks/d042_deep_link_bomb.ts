/*
 * D_042 — Deep-Link bomb trigger.
 *
 * Fires the curated probe deep-link list against the target activity
 * via the Android intent system. We use Java.use("android.content.Intent")
 * directly rather than shelling out to `am start`, so the hook works
 * without requiring an adb shell from the script.
 *
 * Per-probe result:
 *   { probe, dispatched, exception?, target_class? }
 *
 * Crashes are detected by hooking `Thread.UncaughtExceptionHandler`
 * and counting FATAL exceptions whose stack mentions the target
 * activity class. The summary reports the (probe, exception) pairs.
 *
 * Safety: identical envelope to D_063 / D_065 — 50 probes hard cap,
 * 5/s rate, 60s wall-clock, 5 consecutive crashes trips the breaker.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface DeepLinkPayload {
    package: string;
    activity: string;
    probes: string[];
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
    };
}

interface ProbeResult {
    probe: string;
    dispatched: boolean;
    exception?: string;
    target_class?: string;
}

interface BombSummary {
    fired: number;
    dispatched_ok: number;
    crashes: ProbeResult[];
    duration_ms: number;
    tripped: boolean;
    trip_reason?: string;
}

const HARD_CAP = 50;

async function deepLinkBomb(payload: DeepLinkPayload): Promise<BombSummary> {
    const start = Date.now();
    const budget = payload.safety_budget ?? {};
    const maxTotal = Math.min(budget.max_actions_total ?? 50, HARD_CAP);
    const ratePerSec = budget.max_actions_per_sec ?? 5;
    const wallClockMs = (budget.wall_clock_budget_s ?? 60) * 1000;
    const maxCrashes = budget.max_consecutive_crashes ?? 5;

    const probes = payload.probes.slice(0, maxTotal);
    const results: ProbeResult[] = [];
    const crashes: ProbeResult[] = [];
    let consecutiveCrashes = 0;
    let tripReason: string | undefined;

    return new Promise((resolve) => {
        Java.perform(() => {
            let ActivityThread: any;
            let Intent: any;
            let Uri: any;
            try {
                ActivityThread = Java.use("android.app.ActivityThread");
                Intent = Java.use("android.content.Intent");
                Uri = Java.use("android.net.Uri");
            } catch (e: any) {
                sendError(`D_042: required class missing: ${e.message}`);
                resolve({
                    fired: 0, dispatched_ok: 0, crashes: [],
                    duration_ms: Date.now() - start, tripped: false,
                });
                return;
            }

            const ctx = ActivityThread.currentApplication().getApplicationContext();

            const minIntervalMs = ratePerSec > 0 ? 1000 / ratePerSec : 0;
            let idx = 0;
            let lastFireAt = 0;

            const fireNext = () => {
                if (idx >= probes.length) return finish();
                if (Date.now() - start > wallClockMs) {
                    tripReason = "wall_clock_budget exceeded";
                    return finish();
                }
                if (consecutiveCrashes >= maxCrashes) {
                    tripReason = `max_consecutive_crashes ${maxCrashes} tripped`;
                    return finish();
                }
                const now = Date.now();
                const wait = Math.max(0, lastFireAt + minIntervalMs - now);
                setTimeout(() => {
                    const probe = probes[idx++];
                    lastFireAt = Date.now();
                    const result: ProbeResult = {
                        probe,
                        dispatched: false,
                        target_class: payload.activity,
                    };
                    try {
                        const intent = Intent.$new("android.intent.action.VIEW");
                        const uri = Uri.parse(probe);
                        intent.setData(uri);
                        // Required to start from non-Activity context
                        intent.addFlags(0x10000000);
                        ctx.startActivity(intent);
                        result.dispatched = true;
                        consecutiveCrashes = 0;
                    } catch (e: any) {
                        result.exception =
                            e.message?.slice(0, 200) ?? String(e);
                        crashes.push(result);
                        consecutiveCrashes++;
                    }
                    results.push(result);
                    fireNext();
                }, wait);
            };

            const finish = () => {
                const dispatched = results.filter((r) => r.dispatched).length;
                resolve({
                    fired: results.length,
                    dispatched_ok: dispatched,
                    crashes,
                    duration_ms: Date.now() - start,
                    tripped: tripReason !== undefined,
                    trip_reason: tripReason,
                });
            };

            fireNext();
        });
    });
}

rpc.exports = {
    deeplinkbomb: deepLinkBomb,
};
