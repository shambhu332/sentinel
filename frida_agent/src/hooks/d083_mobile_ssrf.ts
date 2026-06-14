/*
 * D_083 — Mobile SSRF prober.
 *
 * For each captured outbound URL request, rewrites the destination
 * to each of the curated SAFE probe targets (cloud-metadata,
 * loopback, RFC1918, file://, content://). Records whether the
 * response body has non-zero length — that's the signal the app
 * actually reached the internal target.
 *
 * Safety boundary: every rewrite is checked against
 * `allowed_destination_prefixes`. If a payload accidentally
 * includes a destination outside that allow-list (programmer
 * error), the hook drops it. We NEVER touch external hosts.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SsrfPayload {
    target_class: string;
    monitor_sinks: string[];
    probe_destinations: string[];
    allowed_destination_prefixes: string[];
    block_external: boolean;
    response_capture_bytes: number;
    safety_budget?: any;
}

interface SsrfResult {
    rewrites_attempted: { original: string; probe: string }[];
    successful_internal_hits: {
        probe: string;
        status: number;
        body_preview: string;
    }[];
    blocked_unsafe_rewrites: number;
    duration_ms: number;
}

async function mobilessrf(payload: SsrfPayload): Promise<SsrfResult> {
    if (!payload.block_external) {
        sendError("D_083 refusing to run: block_external must be true");
        return {
            rewrites_attempted: [],
            successful_internal_hits: [],
            blocked_unsafe_rewrites: 0,
            duration_ms: 0,
        };
    }

    const max = Math.min(payload.safety_budget?.max_actions_total ?? 12, 24);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 1;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const maxCrashes = payload.safety_budget?.max_consecutive_crashes ?? 3;
    const capBytes = Math.min(payload.response_capture_bytes ?? 256, 4096);
    const start = Date.now();
    const rewrites: any[] = [];
    const hits: any[] = [];
    let blocked = 0;
    let consecutiveCrashes = 0;

    // The defensive checker — every URL we're about to fire goes
    // through this. Returns true ONLY when the URL matches the
    // configured safe allow-list.
    const isSafeProbe = (url: string): boolean => {
        return payload.allowed_destination_prefixes.some(
            (prefix) => url.startsWith(prefix),
        );
    };

    // Filter the probe set against the allow-list AT START so any
    // bug in the Python payload is caught before we fire anything.
    const safeProbes = payload.probe_destinations.filter((d) => {
        if (isSafeProbe(d)) return true;
        blocked++;
        return false;
    }).slice(0, max);

    if (safeProbes.length === 0) {
        sendError("D_083: every configured probe failed the allow-list");
        return {
            rewrites_attempted: [],
            successful_internal_hits: [],
            blocked_unsafe_rewrites: blocked,
            duration_ms: Date.now() - start,
        };
    }

    return new Promise((resolve) => {
        Java.perform(() => {
            // 1) Capture the live OkHttp client so we can re-fire
            //    requests through the same auth context.
            let captured: any = null;
            try {
                const Client = Java.use("okhttp3.OkHttpClient");
                Client.newCall.implementation = function (req: any) {
                    if (!captured) captured = this;
                    return this.newCall(req);
                };
            } catch (_) { /* OkHttp may not be loaded */ }

            const Request = (() => {
                try {
                    return Java.use("okhttp3.Request");
                } catch (_) { return null; }
            })();
            const RequestBuilder = (() => {
                try {
                    return Java.use("okhttp3.Request$Builder");
                } catch (_) { return null; }
            })();

            const minInterval = rate > 0 ? 1000 / rate : 0;
            let idx = 0, lastFire = 0;

            const fire = () => {
                if (
                    idx >= safeProbes.length ||
                    Date.now() - start >= window_s * 1000 ||
                    consecutiveCrashes >= maxCrashes
                ) {
                    return finish();
                }
                const now = Date.now();
                const wait = Math.max(0, lastFire + minInterval - now);
                setTimeout(() => {
                    const probe = safeProbes[idx++];
                    lastFire = Date.now();

                    // Belt-and-braces: re-check the allow-list right
                    // before firing.
                    if (!isSafeProbe(probe)) {
                        blocked++;
                        return fire();
                    }

                    rewrites.push({ original: "(rewritten)", probe });

                    // OkHttp fast path — needs a captured client.
                    if (captured && Request && RequestBuilder) {
                        try {
                            const req = RequestBuilder.$new()
                                .url(probe).build();
                            const resp = captured.newCall(req).execute();
                            const status = resp.code();
                            const body = resp.body();
                            const preview = body
                                ? String(body.string()).slice(0, capBytes)
                                : "";
                            if (status > 0 && preview.length > 0) {
                                hits.push({
                                    probe, status,
                                    body_preview: preview,
                                });
                            }
                            consecutiveCrashes = 0;
                        } catch (e: any) {
                            consecutiveCrashes++;
                        }
                    } else {
                        // HttpURLConnection fallback for non-OkHttp apps.
                        try {
                            const URL = Java.use("java.net.URL");
                            const conn = URL.$new(probe).openConnection();
                            conn.setConnectTimeout(3000);
                            conn.setReadTimeout(3000);
                            conn.connect();
                            const status = conn.getResponseCode();
                            // Drain a small chunk.
                            const InputStream = conn.getInputStream();
                            const baos = Java.use(
                                "java.io.ByteArrayOutputStream",
                            ).$new();
                            const buf = Java.array(
                                "byte", new Array(capBytes).fill(0),
                            );
                            const read = InputStream.read(buf);
                            if (read > 0) {
                                const String_ = Java.use("java.lang.String");
                                const preview = String_.$new(buf, 0, read).toString();
                                hits.push({
                                    probe, status,
                                    body_preview: preview,
                                });
                            }
                            InputStream.close();
                            consecutiveCrashes = 0;
                        } catch (_) {
                            consecutiveCrashes++;
                        }
                    }
                    fire();
                }, wait);
            };

            const finish = () => resolve({
                rewrites_attempted: rewrites,
                successful_internal_hits: hits,
                blocked_unsafe_rewrites: blocked,
                duration_ms: Date.now() - start,
            });

            fire();
        });
    });
}

rpc.exports = { mobilessrf };
