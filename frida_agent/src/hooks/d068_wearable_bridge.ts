/*
 * D_068 — WearOS DataLayer bridge sniffer.
 *
 * Hooks MessageClient.onMessageReceived + DataClient.onDataChanged
 * and dumps the payload bytes (base64 + length). Passive monitor —
 * triggers only when the paired watch actually sends frames.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface WearableDump {
    api: "message" | "data";
    path: string;
    b64_payload: string;
    bytes: number;
}

interface WearableResult { dumps: WearableDump[]; duration_ms: number; }

async function wearablebridge(
    payload: { safety_budget?: any },
): Promise<WearableResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 60;
    const dumps: WearableDump[] = [];
    const start = Date.now();
    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Base64 = Java.use("android.util.Base64");
                const MCB = Java.use(
                    "com.google.android.gms.wearable.MessageClient$OnMessageReceivedListener",
                );
                MCB.onMessageReceived.implementation = function (event: any) {
                    try {
                        const data = event.getData();
                        dumps.push({
                            api: "message",
                            path: String(event.getPath()),
                            b64_payload: Base64.encodeToString(data, 0),
                            bytes: data ? data.length : 0,
                        });
                    } catch (_) { /* ignore */ }
                    return this.onMessageReceived(event);
                };
            } catch (_) { /* class may not be present */ }
            try {
                const DCB = Java.use(
                    "com.google.android.gms.wearable.DataClient$OnDataChangedListener",
                );
                DCB.onDataChanged.implementation = function (buf: any) {
                    try {
                        const it = buf.iterator();
                        while (it.hasNext()) {
                            const ev = it.next();
                            const item = ev.getDataItem();
                            const data = item.getData();
                            dumps.push({
                                api: "data",
                                path: String(item.getUri().getPath()),
                                b64_payload: data
                                    ? Java.use("android.util.Base64")
                                          .encodeToString(data, 0)
                                    : "",
                                bytes: data ? data.length : 0,
                            });
                        }
                    } catch (_) { /* ignore */ }
                    return this.onDataChanged(buf);
                };
            } catch (e: any) {
                sendError(`D_068: ${e.message}`);
            }
            setTimeout(() => resolve({
                dumps: dumps.slice(0, 30),
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { wearablebridge };
