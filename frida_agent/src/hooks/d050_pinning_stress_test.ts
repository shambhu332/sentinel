/*
 * D_050 — TLS pinning defense-in-depth stress.
 *
 * For each detected pinning layer in the payload, disables it (one
 * at a time), fires the canary URL, records the HTTP status, then
 * restores the original implementation. Concludes by reporting which
 * layers had to be disabled before traffic actually flowed.
 *
 * Order matters: we disable from the OUTSIDE in (system TrustManager
 * first), so a single weak layer is the headline result.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface PinningPayload {
    layers: string[];
    canary_url: string;
    expected_status: number;
    safety_budget?: any;
}
interface PinningResult {
    iterations: { layer_disabled: string; canary_status: number; flowed: boolean }[];
    weakest_layer?: string;
    duration_ms: number;
}

async function pinningstress(payload: PinningPayload): Promise<PinningResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 60;
    const iterations: any[] = [];
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            const restore: (() => void)[] = [];

            const disable = (layer: string) => {
                try {
                    if (layer === "x509_trust_manager") {
                        const TM = Java.use("javax.net.ssl.X509TrustManager");
                        const orig = TM.checkServerTrusted.overload(
                            "[Ljava.security.cert.X509Certificate;",
                            "java.lang.String",
                        );
                        const o = orig.implementation;
                        orig.implementation = function () { /* trust all */ };
                        restore.push(() => orig.implementation = o);
                    } else if (layer === "okhttp_certificate_pinner") {
                        const CP = Java.use("okhttp3.CertificatePinner");
                        const orig = CP.check.overload(
                            "java.lang.String",
                            "java.util.List",
                        );
                        const o = orig.implementation;
                        orig.implementation = function () { /* noop */ };
                        restore.push(() => orig.implementation = o);
                    } else if (layer === "webview_ssl_error") {
                        const WVC = Java.use("android.webkit.WebViewClient");
                        const orig = WVC.onReceivedSslError;
                        const o = orig.implementation;
                        orig.implementation = function (
                            wv: any, handler: any, err: any,
                        ) { handler.proceed(); };
                        restore.push(() => orig.implementation = o);
                    }
                } catch (_) { /* layer not loaded */ }
            };

            const restoreAll = () => {
                while (restore.length) {
                    try { restore.pop()!(); } catch (_) { /* ignore */ }
                }
            };

            const URL = Java.use("java.net.URL");

            const fireCanary = (): number => {
                try {
                    const conn = URL.$new(payload.canary_url).openConnection();
                    conn.setConnectTimeout(3000);
                    conn.connect();
                    return conn.getResponseCode();
                } catch (e: any) {
                    return -1;
                }
            };

            for (const layer of payload.layers) {
                if (Date.now() - start >= window_s * 1000) break;
                disable(layer);
                const status = fireCanary();
                const flowed = status === payload.expected_status;
                iterations.push({ layer_disabled: layer, canary_status: status, flowed });
                restoreAll();
                if (flowed) break;  // first weakness wins
            }

            const weakest = iterations.find((i) => i.flowed)?.layer_disabled;
            resolve({
                iterations,
                weakest_layer: weakest,
                duration_ms: Date.now() - start,
            });
        });
    });
}

rpc.exports = { pinningstress };
