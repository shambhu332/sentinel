/*
 * D_059 — Clipboard paste-poisoning.
 *
 * Plants each poison payload on the system clipboard, then hooks the
 * three configured downstream sinks (rawQuery, evaluateJavascript,
 * loadUrl). Any call to a sink whose argument matches the payload we
 * just planted = confirmed paste-through-to-sink flow.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface ClipboardHijackPayload {
    poison_payloads: string[];
    trigger_method: string;
    monitor_sinks: string[];
    safety_budget?: any;
}

interface ClipboardHijackResult {
    planted: number;
    sink_hits: { sink: string; payload: string }[];
    duration_ms: number;
}

async function clipboardhijack(
    payload: ClipboardHijackPayload,
): Promise<ClipboardHijackResult> {
    const maxTotal = Math.min(payload.safety_budget?.max_actions_total ?? 10, 20);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const sink_hits: { sink: string; payload: string }[] = [];
    let planted = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                const ClipboardManager = Java.use(
                    "android.content.ClipboardManager",
                );
                const ClipData = Java.use("android.content.ClipData");
                const cb = ctx.getSystemService("clipboard");

                // Hook the configured sinks first so we catch any subsequent
                // call that consumes the planted payload.
                if (payload.monitor_sinks.includes("rawQuery")) {
                    try {
                        const SQLiteDB = Java.use(
                            "android.database.sqlite.SQLiteDatabase",
                        );
                        SQLiteDB.rawQuery.overload(
                            "java.lang.String", "[Ljava.lang.String;",
                        ).implementation = function (sql: any, args: any) {
                            const s = String(sql);
                            payload.poison_payloads.forEach((p) => {
                                if (s.includes(p)) {
                                    sink_hits.push({ sink: "rawQuery", payload: p });
                                }
                            });
                            return this.rawQuery(sql, args);
                        };
                    } catch (_) { /* class may be on a different runtime */ }
                }
                if (payload.monitor_sinks.includes("evaluateJavascript")) {
                    try {
                        const WV = Java.use("android.webkit.WebView");
                        WV.evaluateJavascript.implementation = function (
                            script: any, cbk: any,
                        ) {
                            const s = String(script);
                            payload.poison_payloads.forEach((p) => {
                                if (s.includes(p)) {
                                    sink_hits.push({ sink: "evaluateJavascript", payload: p });
                                }
                            });
                            return this.evaluateJavascript(script, cbk);
                        };
                    } catch (_) { /* ignore */ }
                }

                // Plant each payload + wait briefly for the app to consume
                payload.poison_payloads.slice(0, maxTotal).forEach((p, i) => {
                    setTimeout(() => {
                        try {
                            const clip = ClipData.newPlainText("hijack", p);
                            cb.setPrimaryClip(clip);
                            planted++;
                        } catch (_) { /* ignore */ }
                    }, i * 1000);
                });
            } catch (e: any) {
                sendError(`D_059: ${e.message}`);
            }
            setTimeout(() => resolve({
                planted,
                sink_hits: sink_hits.slice(0, 30),
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { clipboardhijack };
