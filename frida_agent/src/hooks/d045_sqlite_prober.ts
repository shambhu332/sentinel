/*
 * D_045 — App-internal SQLite SQLi prober.
 *
 * Hooks SQLiteDatabase.rawQuery and replaces the selection argument
 * (the third parameter of the second overload) with each probe in
 * turn. Counts distinct returned row counts — a non-singleton set
 * proves exploitable injection.
 *
 * SafetyBudget: 25 actions / 3 per sec / 30s / 3 consecutive crashes.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SqliteProbePayload {
    probe_selections: string[];
    safety_budget?: any;
}

interface SqliteProbeResult {
    fired: number;
    distinct_row_counts: number[];
    results: { selection: string; rows: number; error?: string }[];
    duration_ms: number;
}

async function sqliteprober(payload: SqliteProbePayload): Promise<SqliteProbeResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 25, 50);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const results: any[] = [];
    let fired = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const SQLite = Java.use("android.database.sqlite.SQLiteDatabase");
                // Intercept rawQuery once + re-fire with each probe selection.
                const orig = SQLite.rawQuery.overload(
                    "java.lang.String", "[Ljava.lang.String;",
                );
                let observedSql: string | null = null;
                orig.implementation = function (sql: any, args: any) {
                    if (!observedSql) {
                        observedSql = String(sql);
                        payload.probe_selections.slice(0, max).forEach((probe) => {
                            try {
                                const c = this.rawQuery(
                                    observedSql!.replace(/\?/g, `'${probe}'`),
                                    null,
                                );
                                const count = c ? c.getCount() : 0;
                                if (c) c.close();
                                results.push({ selection: probe, rows: count });
                                fired++;
                            } catch (e: any) {
                                results.push({
                                    selection: probe, rows: -1,
                                    error: e.message?.slice(0, 200),
                                });
                            }
                        });
                    }
                    return this.rawQuery(sql, args);
                };
            } catch (e: any) {
                sendError(`D_045: ${e.message}`);
            }
            setTimeout(() => {
                const distinct = Array.from(
                    new Set(results.filter((r) => r.rows >= 0).map((r) => r.rows)),
                );
                resolve({
                    fired,
                    distinct_row_counts: distinct,
                    results: results.slice(0, 30),
                    duration_ms: Date.now() - start,
                });
            }, window_s * 1000);
        });
    });
}

rpc.exports = { sqliteprober };
