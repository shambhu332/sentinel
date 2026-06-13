/*
 * D_043 — Hidden internal-endpoint prober.
 *
 * Captures the OkHttpClient instance the app uses (singleton or DI),
 * harvests the current Authorization header, then fires each
 * suspicious URL through that same authenticated client and records
 * status code + first 400 chars of the response body.
 *
 * SafetyBudget: 30 actions / 3 per sec / 30s / 3 consecutive crashes.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface HiddenApiPayload {
    urls: string[];
    safety_budget?: any;
}

interface HiddenApiResult {
    probes: { url: string; status: number; body_preview: string; error?: string }[];
    auth_header_captured: boolean;
    duration_ms: number;
}

async function hiddenapiprobe(payload: HiddenApiPayload): Promise<HiddenApiResult> {
    const maxTotal = Math.min(payload.safety_budget?.max_actions_total ?? 30, 60);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 3;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const maxCrashes = payload.safety_budget?.max_consecutive_crashes ?? 3;
    const probes: any[] = [];
    let capturedAuth: string | null = null;
    let crashes = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            let OkHttp: any, Request: any, RequestBuilder: any;
            try {
                OkHttp = Java.use("okhttp3.OkHttpClient");
                Request = Java.use("okhttp3.Request");
                RequestBuilder = Java.use("okhttp3.Request$Builder");
                // Hook newCall to capture an existing client + any Authorization
                OkHttp.newCall.implementation = function (req: any) {
                    if (!capturedAuth) {
                        try {
                            capturedAuth = String(req.header("Authorization") || "");
                        } catch (_) { /* ignore */ }
                    }
                    return this.newCall(req);
                };
            } catch (e: any) {
                sendError(`D_043: ${e.message}`);
                resolve({
                    probes: [],
                    auth_header_captured: false,
                    duration_ms: Date.now() - start,
                });
                return;
            }

            const minInterval = rate > 0 ? 1000 / rate : 0;
            const urls = payload.urls.slice(0, maxTotal);
            let idx = 0, lastFire = 0;
            const client = OkHttp.$new();

            const fire = () => {
                if (idx >= urls.length || crashes >= maxCrashes ||
                    Date.now() - start >= window_s * 1000) return finish();
                const now = Date.now();
                const wait = Math.max(0, lastFire + minInterval - now);
                setTimeout(() => {
                    const url = urls[idx++];
                    lastFire = Date.now();
                    try {
                        const b = RequestBuilder.$new().url(url);
                        if (capturedAuth) b.header("Authorization", capturedAuth);
                        const resp = client.newCall(b.build()).execute();
                        const body = resp.body();
                        const preview = body ? String(body.string()).slice(0, 400) : "";
                        probes.push({
                            url,
                            status: resp.code(),
                            body_preview: preview,
                        });
                        crashes = 0;
                    } catch (e: any) {
                        probes.push({ url, status: -1, body_preview: "", error: e.message });
                        crashes++;
                    }
                    fire();
                }, wait);
            };

            const finish = () => resolve({
                probes,
                auth_header_captured: !!capturedAuth,
                duration_ms: Date.now() - start,
            });

            fire();
        });
    });
}

rpc.exports = { hiddenapiprobe };
