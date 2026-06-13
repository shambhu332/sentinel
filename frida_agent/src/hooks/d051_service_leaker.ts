/*
 * D_051 — Exported-service probe.
 *
 * Builds an Intent targeting the named exported service, attaches each
 * probe extras bag in turn, then bindService()s with a tiny synthetic
 * ServiceConnection. On a successful bind, reflects on the returned
 * IBinder to enumerate transactable methods.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface ServiceProbePayload {
    service_name: string;
    actions: string[];
    probe_extras: Record<string, any>[];
    enumerate_aidl?: boolean;
    safety_budget?: any;
}
interface ServiceProbeResult {
    binds_attempted: number;
    binds_succeeded: number;
    aidl_methods: string[];
    duration_ms: number;
}

async function serviceprobe(payload: ServiceProbePayload): Promise<ServiceProbeResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 15, 30);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    let attempted = 0, succeeded = 0;
    const aidl: string[] = [];
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const Intent = Java.use("android.content.Intent");
                const ComponentName = Java.use("android.content.ComponentName");
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                const pkg = ctx.getPackageName();

                const ConnImpl = Java.registerClass({
                    name: "vc.SvcConn",
                    implements: [Java.use("android.content.ServiceConnection")],
                    methods: {
                        onServiceConnected(name: any, binder: any) {
                            succeeded++;
                            if (payload.enumerate_aidl) {
                                try {
                                    const desc = binder.getInterfaceDescriptor();
                                    if (desc) aidl.push(String(desc));
                                } catch (_) { /* ignore */ }
                            }
                        },
                        onServiceDisconnected(_name: any) {},
                    },
                });
                const conn = ConnImpl.$new();

                const probes = payload.probe_extras.slice(0, max);
                probes.forEach((extras, i) => {
                    if (Date.now() - start >= window_s * 1000) return;
                    const action = payload.actions[i % payload.actions.length];
                    const intent = Intent.$new(action);
                    intent.setComponent(
                        ComponentName.$new(pkg, payload.service_name),
                    );
                    for (const [k, v] of Object.entries(extras)) {
                        if (typeof v === "string") intent.putExtra(k, v);
                        else if (typeof v === "boolean") intent.putExtra(k, v);
                        else if (typeof v === "number") intent.putExtra(k, v | 0);
                    }
                    try {
                        ctx.bindService(intent, conn, 1);
                        attempted++;
                    } catch (_) { /* refused */ }
                });
            } catch (e: any) {
                sendError(`D_051: ${e.message}`);
            }
            setTimeout(() => resolve({
                binds_attempted: attempted,
                binds_succeeded: succeeded,
                aidl_methods: Array.from(new Set(aidl)).slice(0, 30),
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { serviceprobe };
