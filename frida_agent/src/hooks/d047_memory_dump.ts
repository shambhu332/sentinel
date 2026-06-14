/*
 * D_047 — Heap memory dump + secret scan.
 *
 * For each target activity, hooks Activity.onResume; after the
 * configured event, walks Process.enumerateRanges('rw-') and scans
 * each readable+writable region for the configured key shape
 * patterns (JWT, AWS, PAN, Stripe, PEM). Reports each match with a
 * truncated preview.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface MemDumpPayload {
    targets: string[];
    scan_after_event?: string;
    key_patterns: string[];
    safety_budget?: any;
}
interface MemDumpResult {
    activities_hooked: number;
    matches: { pattern: string; preview: string; addr: string }[];
    bytes_scanned: number;
    duration_ms: number;
}

async function memorydump(payload: MemDumpPayload): Promise<MemDumpResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 120;
    const matches: any[] = [];
    let hooked = 0;
    let bytesScanned = 0;
    const start = Date.now();
    const regexes = payload.key_patterns.map((p) => new RegExp(p));

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Activity = Java.use("android.app.Activity");
                const onResume = Activity.onResume;
                const orig = onResume.implementation;
                onResume.implementation = function () {
                    const cls = String(this.getClass().getName());
                    if (payload.targets.some((t) => cls.endsWith(t))) {
                        hooked++;
                        scanHeap();
                    }
                    return orig.call(this);
                };
            } catch (e: any) {
                sendError(`D_047: ${e.message}`);
            }
            setTimeout(() => resolve({
                activities_hooked: hooked,
                matches: matches.slice(0, 30),
                bytes_scanned: bytesScanned,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });

        function scanHeap() {
            try {
                const ranges = Process.enumerateRanges("rw-");
                for (const r of ranges) {
                    // Skip huge regions to keep the scan bounded
                    if (r.size > 8 * 1024 * 1024) continue;
                    try {
                        const buf = r.base.readByteArray(Math.min(r.size, 1024 * 1024));
                        if (!buf) continue;
                        bytesScanned += buf.byteLength;
                        // QuickJS (Frida's JS runtime) does not ship a
                        // TextDecoder. We only need printable ASCII so
                        // hand-roll the conversion.
                        const u8 = new Uint8Array(buf);
                        let s = "";
                        for (let k = 0; k < u8.length; k++) {
                            const c = u8[k];
                            // Keep printable ASCII; everything else
                            // becomes a space (regex still matches
                            // contiguous tokens).
                            s += (c >= 0x20 && c < 0x7f)
                                ? String.fromCharCode(c) : " ";
                        }
                        for (let i = 0; i < regexes.length; i++) {
                            const m = s.match(regexes[i]);
                            if (m) {
                                matches.push({
                                    pattern: payload.key_patterns[i],
                                    preview: m[0].slice(0, 80),
                                    addr: r.base.toString(),
                                });
                            }
                        }
                    } catch (_) { /* unreadable */ }
                    if (matches.length >= 50) break;
                }
            } catch (_) { /* enumerate failed */ }
        }
    });
}

rpc.exports = { memorydump };
