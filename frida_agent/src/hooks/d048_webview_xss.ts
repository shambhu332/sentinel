/*
 * D_048 — WebView XSS injection.
 *
 * Hooks WebViewClient.onPageFinished. After the page loads, fires
 * each XSS probe via evaluateJavascript and captures any echo of a
 * sentinel token we plant into document.title — that's how we
 * distinguish "the rendering engine consumed the script" from "the
 * script bounced".
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface XssPayload { xss_probes: string[]; safety_budget?: any; }
interface XssResult {
    fired: number;
    sentinel_captures: { probe: string; title: string }[];
    duration_ms: number;
}

async function webviewxss(payload: XssPayload): Promise<XssResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 20, 40);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 2;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const captures: any[] = [];
    let fired = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const WVC = Java.use("android.webkit.WebViewClient");
                WVC.onPageFinished.implementation = function (wv: any, url: any) {
                    let idx = 0;
                    const probes = payload.xss_probes.slice(0, max);
                    const minInterval = rate > 0 ? 1000 / rate : 0;
                    const sentinel = "X_SENTINEL_" + Math.random().toString(36).slice(2);
                    const fire = () => {
                        if (idx >= probes.length) return;
                        const p = probes[idx++];
                        const wrapped = `try{document.title='${sentinel}';${p}}catch(e){}`;
                        try {
                            wv.evaluateJavascript(wrapped, null);
                            fired++;
                            setTimeout(() => {
                                try {
                                    wv.evaluateJavascript(
                                        "document.title",
                                        Java.registerClass({
                                            name: "vc.Cb" + idx,
                                            implements: [Java.use("android.webkit.ValueCallback")],
                                            methods: {
                                                onReceiveValue(v: any) {
                                                    const t = String(v);
                                                    if (t.includes(sentinel)) {
                                                        captures.push({ probe: p, title: t });
                                                    }
                                                },
                                            },
                                        }).$new(),
                                    );
                                } catch (_) { /* ignore */ }
                            }, 200);
                        } catch (_) { /* probe rejected */ }
                        setTimeout(fire, minInterval);
                    };
                    fire();
                    return this.onPageFinished(wv, url);
                };
            } catch (e: any) {
                sendError(`D_048: ${e.message}`);
            }
            setTimeout(() => resolve({
                fired,
                sentinel_captures: captures,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { webviewxss };
