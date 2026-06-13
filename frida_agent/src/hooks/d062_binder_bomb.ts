/*
 * D_062 — Binder transaction fuzzer. HARD-CAPPED at 10 / 1 per sec.
 *
 * Targets the captured Binder via Binder.onTransact(code, data,
 * reply, flags). For each fuzz_sizes_bytes entry, writes that much
 * arbitrary data into a Parcel and dispatches; records throws.
 * For each out_of_range_codes entry, dispatches with that code.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface BinderPayload {
    fuzz_sizes_bytes: number[];
    out_of_range_codes: number[];
    safety_budget?: any;
}
interface BinderResult {
    iterations: { kind: "size" | "code"; arg: number; error?: string }[];
    duration_ms: number;
}

async function binderbomb(payload: BinderPayload): Promise<BinderResult> {
    const maxTotal = Math.min(payload.safety_budget?.max_actions_total ?? 10, 10);
    const ratePerSec = payload.safety_budget?.max_actions_per_sec ?? 1;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const iterations: any[] = [];
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const Parcel = Java.use("android.os.Parcel");
                const Binder = Java.use("android.os.Binder");
                let captured: any = null;
                Binder.onTransact.implementation = function (
                    code: any, data: any, reply: any, flags: any,
                ) {
                    if (!captured) captured = this;
                    return this.onTransact(code, data, reply, flags);
                };

                const minInterval = ratePerSec > 0 ? 1000 / ratePerSec : 1000;
                const work: { kind: "size" | "code"; arg: number }[] = [
                    ...payload.fuzz_sizes_bytes.map(
                        (sz) => ({ kind: "size" as const, arg: sz }),
                    ),
                    ...payload.out_of_range_codes.map(
                        (c) => ({ kind: "code" as const, arg: c }),
                    ),
                ].slice(0, maxTotal);

                let idx = 0;
                const fire = () => {
                    if (
                        !captured || idx >= work.length ||
                        Date.now() - start >= window_s * 1000
                    ) return finish();
                    setTimeout(() => {
                        const w = work[idx++];
                        try {
                            const data = Parcel.obtain();
                            const reply = Parcel.obtain();
                            if (w.kind === "size") {
                                const buf = Java.array(
                                    "byte", new Array(w.arg).fill(0x41),
                                );
                                data.writeByteArray(buf);
                                captured.onTransact(1, data, reply, 0);
                            } else {
                                captured.onTransact(w.arg, data, reply, 0);
                            }
                            data.recycle(); reply.recycle();
                            iterations.push({ kind: w.kind, arg: w.arg });
                        } catch (e: any) {
                            iterations.push({
                                kind: w.kind, arg: w.arg,
                                error: e.message?.slice(0, 200),
                            });
                        }
                        fire();
                    }, minInterval);
                };
                const finish = () => resolve({
                    iterations, duration_ms: Date.now() - start,
                });
                fire();
            } catch (e: any) {
                sendError(`D_062: ${e.message}`);
                resolve({ iterations: [], duration_ms: 0 });
            }
        });
    });
}

rpc.exports = { binderbomb };
