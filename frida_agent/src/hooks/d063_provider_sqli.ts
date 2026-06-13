/*
 * D_063 — ContentProvider SQLi probe.
 *
 * Consumes the `frida_payload` block emitted by D_063 ProviderSqliAgent
 * and fires every probe payload through `ContentResolver.query()`
 * against every candidate URI. For each (uri, payload) pair we record:
 *
 *   - whether the query succeeded
 *   - the returned cursor row count
 *   - any thrown exception message
 *
 * The Python observer correlates the result back to the static
 * finding: if two payloads return different row counts, the provider
 * is confirmed SQLi-vulnerable.
 *
 * Safety:
 *   - Hard cap of 50 actions total
 *   - 5 actions/sec rate ceiling
 *   - 30-second wall-clock budget
 *   - 3 consecutive exceptions -> breaker trips, remaining probes
 *     are dropped
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SqliProbePayload {
    authority: string;
    candidate_uris: string[];
    probe_payloads: string[];
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
    };
}

interface ProbeResult {
    uri: string;
    payload: string;
    ok: boolean;
    row_count: number;
    error?: string;
}

interface ProbeSummary {
    fired: number;
    succeeded: number;
    failed: number;
    distinct_row_counts: number[];
    results: ProbeResult[];
    duration_ms: number;
    tripped: boolean;
    trip_reason?: string;
}

const HARD_CAP = 50;

async function proberProviderSqli(
    payload: SqliProbePayload,
): Promise<ProbeSummary> {
    const start = Date.now();
    const budget = payload.safety_budget ?? {};
    const maxTotal = Math.min(budget.max_actions_total ?? 50, HARD_CAP);
    const ratePerSec = budget.max_actions_per_sec ?? 5;
    const wallClockMs = (budget.wall_clock_budget_s ?? 30) * 1000;
    const maxCrashes = budget.max_consecutive_crashes ?? 3;

    const results: ProbeResult[] = [];
    let consecutiveCrashes = 0;
    let tripReason: string | undefined;

    return new Promise((resolve) => {
        Java.perform(() => {
            let ActivityThread: any;
            let Uri: any;
            try {
                ActivityThread = Java.use("android.app.ActivityThread");
                Uri = Java.use("android.net.Uri");
            } catch (e: any) {
                sendError(`D_063: required class missing: ${e.message}`);
                resolve(emptySummary(start));
                return;
            }

            const context = ActivityThread.currentApplication().getApplicationContext();
            const resolver = context.getContentResolver();

            const probes: { uri: string; payload: string }[] = [];
            for (const uri of payload.candidate_uris) {
                for (const p of payload.probe_payloads) {
                    probes.push({ uri, payload: p });
                    if (probes.length >= maxTotal) break;
                }
                if (probes.length >= maxTotal) break;
            }

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
                    let result: ProbeResult;
                    try {
                        const uriObj = Uri.parse(probe.uri);
                        const cursor = resolver.query(
                            uriObj,
                            null,
                            probe.payload,    // selection
                            null,
                            null,
                        );
                        const rowCount = cursor !== null ? cursor.getCount() : 0;
                        if (cursor !== null) cursor.close();
                        result = {
                            uri: probe.uri,
                            payload: probe.payload,
                            ok: true,
                            row_count: rowCount,
                        };
                        consecutiveCrashes = 0;
                    } catch (e: any) {
                        result = {
                            uri: probe.uri,
                            payload: probe.payload,
                            ok: false,
                            row_count: -1,
                            error: e.message?.slice(0, 200) ?? String(e),
                        };
                        consecutiveCrashes++;
                    }
                    results.push(result);
                    fireNext();
                }, wait);
            };

            const finish = () => resolve(summarise(results, start, tripReason));

            fireNext();
        });
    });
}

function emptySummary(start: number): ProbeSummary {
    return {
        fired: 0,
        succeeded: 0,
        failed: 0,
        distinct_row_counts: [],
        results: [],
        duration_ms: Date.now() - start,
        tripped: false,
    };
}

function summarise(
    results: ProbeResult[], start: number, tripReason?: string,
): ProbeSummary {
    const succeeded = results.filter((r) => r.ok).length;
    const failed = results.length - succeeded;
    const distinct = Array.from(
        new Set(results.filter((r) => r.ok).map((r) => r.row_count)),
    );
    return {
        fired: results.length,
        succeeded,
        failed,
        distinct_row_counts: distinct,
        results,
        duration_ms: Date.now() - start,
        tripped: tripReason !== undefined,
        trip_reason: tripReason,
    };
}

rpc.exports = {
    proberprovidersqli: proberProviderSqli,
};
