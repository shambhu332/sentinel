/*
 * D_058 — WebSocket frame injector.
 *
 * Hooks okhttp3.WebSocket.send(String) and okhttp3.WebSocket.send(ByteString)
 * to capture every outbound frame. For each probe payload, calls
 * webSocket.send(probe) directly through the captured instance and
 * records server response shape via the hooked listener.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface WsPayload {
    probe_messages: string[];
    frame_types?: ("TEXT" | "BINARY")[];
    safety_budget?: any;
}
interface WsResult {
    sent: number;
    responses_observed: number;
    duration_ms: number;
}

async function websocketinjector(payload: WsPayload): Promise<WsResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 25, 50);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    let sent = 0, responses = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const WS = Java.use("okhttp3.WebSocket");
                const Listener = Java.use("okhttp3.WebSocketListener");
                let captured: any = null;

                WS.send.overload("java.lang.String").implementation = function (s: any) {
                    if (!captured) captured = this;
                    return this.send(s);
                };
                Listener.onMessage.overload(
                    "okhttp3.WebSocket", "java.lang.String",
                ).implementation = function (ws: any, msg: any) {
                    responses++;
                    return this.onMessage(ws, msg);
                };

                // Once we've captured a live WebSocket, fire probes through it.
                let attempts = 0;
                const tick = setInterval(() => {
                    if (captured && attempts < Math.min(max, payload.probe_messages.length)) {
                        try {
                            captured.send(payload.probe_messages[attempts]);
                            sent++;
                        } catch (_) { /* ignore */ }
                        attempts++;
                    }
                    if (attempts >= max || Date.now() - start >= window_s * 1000) {
                        clearInterval(tick);
                        resolve({
                            sent, responses_observed: responses,
                            duration_ms: Date.now() - start,
                        });
                    }
                }, 1000);
            } catch (e: any) {
                sendError(`D_058: ${e.message}`);
                resolve({ sent: 0, responses_observed: 0, duration_ms: 0 });
            }
        });
    });
}

rpc.exports = { websocketinjector };
