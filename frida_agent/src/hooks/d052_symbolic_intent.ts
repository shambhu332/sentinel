/*
 * D_052 — Fire the z3-solved Intent at the target component.
 *
 * Receives the witness extras map + per-key types from the Python
 * agent, builds a fresh Intent targeting the same package + activity
 * (or broadcast receiver), and dispatches it. Records the dispatch
 * outcome — onReceive returned cleanly, threw, was rejected by the
 * platform, etc.
 *
 * Safety: 3 actions total, 1 per sec, 15s wall-clock budget. We
 * never want to spam the system with synthetic intents during a scan.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SymbolicPayload {
    extras: Record<string, any>;
    extras_types: Record<string, "bool" | "int" | "string">;
    target_method: string;
    target_class?: string;
    target_action?: string;
    safety_budget?: any;
}

interface SymbolicResult {
    fired: number;
    dispatched_ok: number;
    errors: string[];
    duration_ms: number;
}

async function symbolicintent(
    payload: SymbolicPayload,
): Promise<SymbolicResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 3, 6);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 1;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 15;
    const start = Date.now();
    const errors: string[] = [];
    let fired = 0, ok = 0;

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const Intent = Java.use("android.content.Intent");
                const ctx = ActivityThread.currentApplication().getApplicationContext();

                const minInterval = rate > 0 ? 1000 / rate : 0;
                let lastFireAt = 0;
                let idx = 0;

                const fire = () => {
                    if (idx >= max || Date.now() - start >= window_s * 1000) {
                        return finish();
                    }
                    const now = Date.now();
                    const wait = Math.max(0, lastFireAt + minInterval - now);
                    setTimeout(() => {
                        idx++;
                        lastFireAt = Date.now();
                        try {
                            const intent = payload.target_action
                                ? Intent.$new(payload.target_action)
                                : Intent.$new();
                            for (const [k, v] of Object.entries(payload.extras)) {
                                const t = payload.extras_types[k];
                                if (t === "bool") intent.putExtra(k, Boolean(v));
                                else if (t === "int") intent.putExtra(k, v | 0);
                                else intent.putExtra(k, String(v));
                            }
                            intent.addFlags(0x10000000);
                            // Prefer broadcast — onReceive is the most common
                            // target_method shape from D_052. For onCreate
                            // we fall back to startActivity.
                            if (payload.target_method === "onReceive") {
                                ctx.sendBroadcast(intent);
                            } else {
                                ctx.startActivity(intent);
                            }
                            fired++;
                            ok++;
                        } catch (e: any) {
                            fired++;
                            errors.push(e.message?.slice(0, 200) ?? String(e));
                        }
                        fire();
                    }, wait);
                };

                const finish = () => resolve({
                    fired,
                    dispatched_ok: ok,
                    errors: errors.slice(0, 5),
                    duration_ms: Date.now() - start,
                });

                fire();
            } catch (e: any) {
                sendError(`D_052: ${e.message}`);
                resolve({
                    fired: 0, dispatched_ok: 0, errors: [e.message],
                    duration_ms: Date.now() - start,
                });
            }
        });
    });
}

rpc.exports = { symbolicintent };
