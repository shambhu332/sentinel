/*
 * D_086 — Intent injection → WebView XSS probe.
 *
 * Hooks WebChromeClient.onConsoleMessage first so any probe's
 * console.log fires reach the agent. Then constructs Intents
 * targeting the named activity with each probe payload set on
 * each configured extra key, and dispatches them via
 * Context.startActivity. The activity's own onCreate -> loadUrl
 * path renders the probe, which (if the activity is vulnerable)
 * executes the console.log.
 *
 * Safety: probes are console.log only. Never alert(), never
 * external XHR, never clipboard writes.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface IntentXssPayload {
    target_activity: string;
    activity_exported: boolean;
    intent_extra_keys: string[];
    probes: string[];
    expect_console_token: string;
    safety_budget?: any;
}

interface IntentXssResult {
    intents_dispatched: number;
    console_hits: { message: string; matched: boolean }[];
    xss_confirmed: boolean;
    duration_ms: number;
}

async function intentxss(payload: IntentXssPayload): Promise<IntentXssResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 6, 12);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 1;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 20;
    const start = Date.now();
    const consoleHits: { message: string; matched: boolean }[] = [];
    let dispatched = 0;

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const WCC = Java.use("android.webkit.WebChromeClient");
                WCC.onConsoleMessage.overload(
                    "android.webkit.ConsoleMessage",
                ).implementation = function (msg: any) {
                    try {
                        const text = String(msg.message());
                        consoleHits.push({
                            message: text.slice(0, 200),
                            matched: text.includes(payload.expect_console_token),
                        });
                    } catch (_) { /* ignore */ }
                    return this.onConsoleMessage(msg);
                };
            } catch (e: any) {
                sendError(`D_086: WCC hook: ${e.message}`);
            }

            let ctx: any, Intent: any, ComponentName: any;
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                Intent = Java.use("android.content.Intent");
                ComponentName = Java.use("android.content.ComponentName");
                ctx = ActivityThread.currentApplication().getApplicationContext();
            } catch (e: any) {
                sendError(`D_086: context resolve: ${e.message}`);
                return resolve({
                    intents_dispatched: 0,
                    console_hits: [], xss_confirmed: false,
                    duration_ms: Date.now() - start,
                });
            }

            const pkg = ctx.getPackageName();
            const minInterval = rate > 0 ? 1000 / rate : 0;

            // Cartesian product of (probe x extra key), capped.
            const work: { probe: string; key: string }[] = [];
            for (const probe of payload.probes) {
                for (const key of payload.intent_extra_keys) {
                    work.push({ probe, key });
                    if (work.length >= max) break;
                }
                if (work.length >= max) break;
            }

            let idx = 0, lastFire = 0;
            const fire = () => {
                if (
                    idx >= work.length ||
                    Date.now() - start >= window_s * 1000
                ) {
                    setTimeout(() => resolve({
                        intents_dispatched: dispatched,
                        console_hits: consoleHits.slice(0, 30),
                        xss_confirmed: consoleHits.some((h) => h.matched),
                        duration_ms: Date.now() - start,
                    }), 1000);  // brief drain for late console messages
                    return;
                }
                const now = Date.now();
                const wait = Math.max(0, lastFire + minInterval - now);
                setTimeout(() => {
                    const w = work[idx++];
                    lastFire = Date.now();
                    try {
                        // Search for the full activity class by simple-name
                        // suffix. The Python payload only has the simple
                        // name; we rely on the package being the app's own.
                        const fqcn = `${pkg}.${w.key.includes(".") ? w.key : payload.target_activity}`;
                        const intent = Intent.$new();
                        intent.setComponent(
                            ComponentName.$new(pkg, fqcn),
                        );
                        intent.putExtra(w.key, w.probe);
                        intent.addFlags(0x10000000);  // NEW_TASK
                        ctx.startActivity(intent);
                        dispatched++;
                    } catch (_) {
                        // Activity may not be resolvable from a non-Activity
                        // context, or the package prefix may not match —
                        // both are acceptable failures for a probe.
                    }
                    fire();
                }, wait);
            };

            fire();
        });
    });
}

rpc.exports = { intentxss };
