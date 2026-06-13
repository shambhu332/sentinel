/*
 * D_066 — Accessibility-service click hijack.
 *
 * Hooks AccessibilityNodeInfo.performAction. For every captured node
 * whose visible bounds are zero (or whose visibility is GONE / alpha
 * is 0), records the call as a synthetic-click candidate. The agent
 * uses this to confirm runtime click dispatch on invisible UI.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface A11yResult {
    hidden_node_actions: { class: string; action: number; bounds: string }[];
    total_actions: number;
    duration_ms: number;
}

async function a11yabuser(
    payload: { safety_budget?: any },
): Promise<A11yResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const hidden: any[] = [];
    let total = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Node = Java.use(
                    "android.view.accessibility.AccessibilityNodeInfo",
                );
                Node.performAction.overload("int")
                    .implementation = function (action: any) {
                    total++;
                    try {
                        const r = Java.use("android.graphics.Rect").$new();
                        this.getBoundsInScreen(r);
                        const w = r.right.value - r.left.value;
                        const h = r.bottom.value - r.top.value;
                        const visible = this.isVisibleToUser();
                        if (!visible || w * h === 0) {
                            hidden.push({
                                class: String(this.getClassName()),
                                action,
                                bounds: `${w}x${h}`,
                            });
                        }
                    } catch (_) { /* ignore */ }
                    return this.performAction(action);
                };
            } catch (e: any) {
                sendError(`D_066: ${e.message}`);
            }
            setTimeout(() => resolve({
                hidden_node_actions: hidden.slice(0, 30),
                total_actions: total,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { a11yabuser };
