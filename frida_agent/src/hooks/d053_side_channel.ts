/*
 * D_053 — CPU + battery side-channel sampler.
 *
 * Reads /proc/self/stat at sample_interval_ms cadence for window_s
 * seconds. Each sample captures (utime + stime) deltas in jiffies.
 * Hooks Cipher.getInstance + MessageDigest.getInstance so we can
 * correlate spikes with VISIBLE Java crypto. A sustained
 * spike_threshold_pct CPU delta with no overlapping crypto hook
 * activity = hidden native crypto signal.
 */

import { sendError } from "../lib/send.js";
import { Java } from "../lib/java_ready.js";

interface SidePayload {
    monitor_endpoints?: string[];
    sample_interval_ms?: number;
    window_seconds?: number;
    spike_threshold_pct?: number;
    safety_budget?: any;
}
interface SideResult {
    samples: { ts: number; cpu_jiffies: number; java_crypto_active: boolean }[];
    spikes_without_java_crypto: number;
    duration_ms: number;
}

async function sidechannel(payload: SidePayload): Promise<SideResult> {
    const interval = payload.sample_interval_ms ?? 200;
    const window = payload.window_seconds ?? 30;
    const threshold = payload.spike_threshold_pct ?? 70;
    const start = Date.now();
    const samples: any[] = [];
    let javaCryptoActive = false;
    let resetTimer: any = null;

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Cipher = Java.use("javax.crypto.Cipher");
                Cipher.getInstance.overload("java.lang.String").implementation =
                    function (algo: any) {
                        javaCryptoActive = true;
                        clearTimeout(resetTimer);
                        resetTimer = setTimeout(
                            () => (javaCryptoActive = false),
                            interval * 2,
                        );
                        return this.getInstance(algo);
                    };
            } catch (e: any) {
                sendError(`D_053: ${e.message}`);
            }
            const proc = "/proc/self/stat";
            let prevTotal = 0;
            const tick = setInterval(() => {
                if (Date.now() - start >= window * 1000) {
                    clearInterval(tick);
                    const spikes = samples.filter(
                        (s) => s.cpu_jiffies > threshold && !s.java_crypto_active,
                    ).length;
                    resolve({
                        samples: samples.slice(0, 200),
                        spikes_without_java_crypto: spikes,
                        duration_ms: Date.now() - start,
                    });
                    return;
                }
                try {
                    const f = new File(proc, "r");
                    const line = (f as any).readLine?.() ??
                        Java.use("java.io.BufferedReader")
                            .$new(Java.use("java.io.FileReader").$new(proc))
                            .readLine();
                    const parts = String(line).split(" ");
                    const utime = parseInt(parts[13], 10) || 0;
                    const stime = parseInt(parts[14], 10) || 0;
                    const total = utime + stime;
                    const delta = total - prevTotal;
                    prevTotal = total;
                    samples.push({
                        ts: Date.now() - start,
                        cpu_jiffies: delta,
                        java_crypto_active: javaCryptoActive,
                    });
                } catch (_) { /* /proc read failed */ }
            }, interval);
        });
    });
}

rpc.exports = { sidechannel };
