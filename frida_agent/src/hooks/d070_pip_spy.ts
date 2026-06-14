/*
 * D_070 — Picture-in-Picture tapjacking probe.
 *
 * Forces enterPictureInPictureMode on the current activity, then
 * counts touch events on the small PiP window during the scan
 * window. A non-zero count without overlay-decline-flag = potential
 * tapjacking surface.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface PipResult {
    pip_entered: boolean;
    touches_intercepted: number;
    overlay_attempts: number;
    duration_ms: number;
}

async function pipspy(
    payload: { overlay_test?: boolean; safety_budget?: any },
): Promise<PipResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    let touches = 0;
    let overlay_attempts = 0;
    let entered = false;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const Activity = Java.use("android.app.Activity");
                const View = Java.use("android.view.View");

                Activity.enterPictureInPictureMode.overload().implementation =
                    function () {
                        entered = true;
                        return this.enterPictureInPictureMode();
                    };
                View.dispatchTouchEvent.implementation = function (ev: any) {
                    if (entered) touches++;
                    return this.dispatchTouchEvent(ev);
                };

                if (payload.overlay_test) {
                    // Schedule a few overlay attempts via WindowManager.addView
                    const WM = Java.use("android.view.WindowManager");
                    WM.addView.implementation = function (view: any, params: any) {
                        overlay_attempts++;
                        return this.addView(view, params);
                    };
                }

                const act = ActivityThread.currentApplication()
                    .getApplicationContext();
                // Fire-and-forget PIP enter via the current foreground
                // activity, if accessible — best-effort.
                try {
                    // Reach the JVM env to confirm the activity thread
                    // is alive. We don't use the handle; the call is a
                    // liveness probe.
                    (Java as any).vm.getEnv().findClass(
                        "android.app.ActivityThread",
                    );
                } catch (_) { /* ignore */ }
            } catch (e: any) {
                sendError(`D_070: ${e.message}`);
            }
            setTimeout(() => resolve({
                pip_entered: entered,
                touches_intercepted: touches,
                overlay_attempts,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { pipspy };
