/*
 * D_065 — FileProvider active traversal fuzzer.
 *
 * Fires curated path-traversal probes through
 * `FileProvider.getUriForFile(context, authority, file)` followed by
 * `ContentResolver.openInputStream(uri)` from a controlled context.
 * Each probe records:
 *
 *   - did getUriForFile reject the path? (it should for `../`-shaped input)
 *   - if it minted a URI, what was the canonical path of the File arg?
 *   - did openInputStream actually read bytes? (if so — confirmed traversal)
 *
 * The Python observer correlates with D_024's passive
 * `file_provider.uri_minted` event stream so the static + dynamic
 * verdicts agree.
 *
 * Safety budget mirrors D_063: 40 actions cap, 5/s rate, 30s
 * wall-clock, 3 consecutive crashes trips the breaker.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface FpProbePayload {
    authority: string;
    declared_roots: any[];
    probe_paths: string[];
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
    };
}

interface FpProbeResult {
    probe_path: string;
    uri_minted: boolean;
    minted_uri?: string;
    canonical_path?: string;
    read_bytes: number;
    error?: string;
}

interface FpProbeSummary {
    fired: number;
    minted_count: number;
    read_count: number;
    results: FpProbeResult[];
    duration_ms: number;
    tripped: boolean;
    trip_reason?: string;
}

const HARD_CAP = 40;

async function proberFileProvider(
    payload: FpProbePayload,
): Promise<FpProbeSummary> {
    const start = Date.now();
    const budget = payload.safety_budget ?? {};
    const maxTotal = Math.min(budget.max_actions_total ?? 40, HARD_CAP);
    const ratePerSec = budget.max_actions_per_sec ?? 5;
    const wallClockMs = (budget.wall_clock_budget_s ?? 30) * 1000;
    const maxCrashes = budget.max_consecutive_crashes ?? 3;

    const probes = payload.probe_paths.slice(0, maxTotal);
    const results: FpProbeResult[] = [];
    let consecutiveCrashes = 0;
    let tripReason: string | undefined;

    return new Promise((resolve) => {
        Java.perform(() => {
            let ActivityThread: any;
            let JavaFile: any;
            let FileProvider: any;
            try {
                ActivityThread = Java.use("android.app.ActivityThread");
                JavaFile = Java.use("java.io.File");
                FileProvider = Java.use("androidx.core.content.FileProvider");
            } catch (e: any) {
                sendError(`D_065: required class missing: ${e.message}`);
                resolve({
                    fired: 0, minted_count: 0, read_count: 0,
                    results: [], duration_ms: Date.now() - start,
                    tripped: false,
                });
                return;
            }

            const context = ActivityThread.currentApplication().getApplicationContext();
            const resolver = context.getContentResolver();
            const filesDir = context.getFilesDir();

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
                    const result: FpProbeResult = {
                        probe_path: probe,
                        uri_minted: false,
                        read_bytes: 0,
                    };
                    try {
                        const fileObj = JavaFile.$new(filesDir, probe);
                        const uri = FileProvider.getUriForFile(
                            context, payload.authority, fileObj,
                        );
                        result.uri_minted = true;
                        result.minted_uri = uri.toString();
                        try {
                            result.canonical_path = fileObj.getCanonicalPath();
                        } catch (_e: any) {
                            // ignore — canonical lookup may itself throw on bad input
                        }
                        // Try to read — bounded to 1 byte; we only need
                        // a yes/no signal, not the actual data.
                        try {
                            const stream = resolver.openInputStream(uri);
                            if (stream !== null) {
                                const read = stream.read();
                                result.read_bytes = read >= 0 ? 1 : 0;
                                stream.close();
                            }
                        } catch (_e: any) {
                            // read failure is fine — uri_minted is the
                            // primary signal
                        }
                        consecutiveCrashes = 0;
                    } catch (e: any) {
                        result.error = e.message?.slice(0, 200) ?? String(e);
                        consecutiveCrashes++;
                    }
                    results.push(result);
                    fireNext();
                }, wait);
            };

            const finish = () => {
                const minted = results.filter((r) => r.uri_minted).length;
                const read = results.filter((r) => r.read_bytes > 0).length;
                resolve({
                    fired: results.length,
                    minted_count: minted,
                    read_count: read,
                    results,
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
    proberfileprovider: proberFileProvider,
};
