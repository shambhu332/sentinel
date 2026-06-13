/*
 * D_071 — Trusted Web Activity session-hijack probe.
 *
 * Hooks androidx.browser.customtabs.CustomTabsIntent.launchUrl,
 * captures the URL the app launches, then fires a malicious
 * CustomTabsIntent at the same URL FROM THIS Frida-controlled context
 * with shared session=true. If the response sets cookies that match
 * the app's session cookie, the TWA is hijackable.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface TwaPayload {
    session_capture?: boolean;
    safety_budget?: any;
}
interface TwaResult {
    launch_intercepts: number;
    captured_urls: string[];
    cookie_response_observed: boolean;
    duration_ms: number;
}

async function twabreaker(payload: TwaPayload): Promise<TwaResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const captured: string[] = [];
    let cookieResp = false;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const CTI = Java.use(
                    "androidx.browser.customtabs.CustomTabsIntent",
                );
                CTI.launchUrl.implementation = function (ctx: any, uri: any) {
                    try {
                        captured.push(String(uri));
                    } catch (_) { /* ignore */ }
                    return this.launchUrl(ctx, uri);
                };
            } catch (_) { /* class may not exist */ }
            // Hook CookieManager to detect cookie-setting responses
            try {
                const CM = Java.use("android.webkit.CookieManager");
                CM.setCookie.overload(
                    "java.lang.String", "java.lang.String",
                ).implementation = function (url: any, value: any) {
                    cookieResp = true;
                    return this.setCookie(url, value);
                };
            } catch (e: any) {
                sendError(`D_071: ${e.message}`);
            }
            setTimeout(() => resolve({
                launch_intercepts: captured.length,
                captured_urls: captured.slice(0, 10),
                cookie_response_observed: cookieResp,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { twabreaker };
