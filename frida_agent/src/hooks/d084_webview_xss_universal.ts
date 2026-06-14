/*
 * D_084 — Universal-XSS probe via loadDataWithBaseURL.
 *
 * Hooks WebChromeClient.onConsoleMessage globally first so any
 * console.log() the probe emits is captured. Then walks every
 * loaded WebView (via Java.choose) and fires loadDataWithBaseURL
 * with each probe payload against the configured base URL. Any
 * onConsoleMessage carrying the expected token confirms execution.
 *
 * Safety: every probe is a console.log; never alert(), never any
 * XHR to an external host. The UXSS probe uses XMLHttpRequest
 * against file:/// — same-origin under the universal-access bypass,
 * never reaches the network.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface XssUniversalPayload {
    target_class: string;
    expect_console_token: string;
    expect_uxss_token: string;
    probes: string[];
    base_url: string;
    safety_budget?: any;
}

interface ConsoleHit {
    message: string;
    level: string;
    matched_probe: boolean;
    matched_uxss: boolean;
}

interface XssUniversalResult {
    probes_fired: number;
    webviews_found: number;
    console_hits: ConsoleHit[];
    xss_confirmed: boolean;
    uxss_confirmed: boolean;
    duration_ms: number;
}

async function webviewxssuniversal(
    payload: XssUniversalPayload,
): Promise<XssUniversalResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 4, 8);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 1;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 20;
    const start = Date.now();
    const consoleHits: ConsoleHit[] = [];
    let webviewsFound = 0;
    let probesFired = 0;

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                // 1) Hook the global ConsoleMessage handler BEFORE we
                //    fire any probe so we capture each emission.
                const WCC = Java.use("android.webkit.WebChromeClient");
                WCC.onConsoleMessage.overload(
                    "android.webkit.ConsoleMessage",
                ).implementation = function (msg: any) {
                    try {
                        const text = String(msg.message());
                        const lvl = String(msg.messageLevel());
                        consoleHits.push({
                            message: text.slice(0, 200),
                            level: lvl,
                            matched_probe: text.includes(
                                payload.expect_console_token,
                            ),
                            matched_uxss: text.includes(
                                payload.expect_uxss_token,
                            ),
                        });
                    } catch (_) { /* ignore */ }
                    return this.onConsoleMessage(msg);
                };
            } catch (e: any) {
                sendError(`D_084: WCC hook: ${e.message}`);
            }

            // 2) Walk every live WebView instance and fire each probe.
            try {
                Java.choose("android.webkit.WebView", {
                    onMatch(wv: any) {
                        webviewsFound++;
                        const probes = payload.probes.slice(0, max);
                        const minInterval = rate > 0 ? 1000 / rate : 0;
                        probes.forEach((p, i) => {
                            setTimeout(() => {
                                try {
                                    wv.loadDataWithBaseURL(
                                        payload.base_url,
                                        p, "text/html", "UTF-8", null,
                                    );
                                    probesFired++;
                                } catch (_) { /* ignore individual fail */ }
                            }, i * Math.max(minInterval, 200));
                        });
                    },
                    onComplete() { /* noop */ },
                });
            } catch (e: any) {
                sendError(`D_084: Java.choose: ${e.message}`);
            }

            setTimeout(() => resolve({
                probes_fired: probesFired,
                webviews_found: webviewsFound,
                console_hits: consoleHits.slice(0, 30),
                xss_confirmed: consoleHits.some((h) => h.matched_probe),
                uxss_confirmed: consoleHits.some((h) => h.matched_uxss),
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { webviewxssuniversal };
