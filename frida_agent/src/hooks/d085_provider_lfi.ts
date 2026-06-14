/*
 * D_085 — ContentProvider LFI probe.
 *
 * For each probe URI from the Python payload:
 *   1. Defensive check — drop if the URI matches any forbidden_path
 *      substring (/etc, /system, /proc, shadow, passwd...).
 *   2. Restrict the URI's file part to safe_app_owned_files only.
 *   3. Resolve via ContentResolver.openFileDescriptor("r"). Success
 *      means the provider exposed the file to a non-app caller.
 *   4. Capture the first N bytes (default 256) as preview.
 *
 * Per the brief's safety: we ONLY attempt app-owned files. block_off_app_targets
 * is a payload-level flag; the TS hook refuses to run without it.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface LfiPayload {
    type: "lfi_probe";
    authority: string;
    safe_app_owned_files: string[];
    probe_uris: string[];
    forbidden_path_substrings: string[];
    block_off_app_targets: boolean;
    response_capture_bytes?: number;
    safety_budget?: any;
}

interface LfiResult {
    probes_attempted: number;
    fd_opened: { uri: string; bytes_read: number; preview: string }[];
    blocked_forbidden: number;
    blocked_not_app_owned: number;
    duration_ms: number;
}

async function providerlfi(payload: LfiPayload): Promise<LfiResult> {
    if (!payload.block_off_app_targets) {
        sendError("D_085 refusing to run: block_off_app_targets must be true");
        return {
            probes_attempted: 0, fd_opened: [],
            blocked_forbidden: 0, blocked_not_app_owned: 0,
            duration_ms: 0,
        };
    }
    const max = Math.min(payload.safety_budget?.max_actions_total ?? 30, 60);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 2;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const maxCrashes = payload.safety_budget?.max_consecutive_crashes ?? 3;
    const capBytes = Math.min(payload.response_capture_bytes ?? 256, 1024);

    const start = Date.now();
    const opened: any[] = [];
    let blockedForbidden = 0;
    let blockedNotAppOwned = 0;
    let attempted = 0;
    let consecutiveCrashes = 0;

    const isSafe = (uri: string): "ok" | "forbidden" | "not_app" => {
        const lower = uri.toLowerCase();
        if (payload.forbidden_path_substrings.some(
            (f) => lower.includes(f.toLowerCase()),
        )) {
            return "forbidden";
        }
        if (!payload.safe_app_owned_files.some(
            (f) => lower.endsWith(f.toLowerCase()),
        )) {
            return "not_app";
        }
        return "ok";
    };

    // Pre-filter the probe set against the safety rules.
    const safeUris = payload.probe_uris.filter((u) => {
        const verdict = isSafe(u);
        if (verdict === "forbidden") { blockedForbidden++; return false; }
        if (verdict === "not_app")  { blockedNotAppOwned++; return false; }
        return true;
    }).slice(0, max);

    if (safeUris.length === 0) {
        sendError("D_085: every probe URI failed the safety filter");
        return {
            probes_attempted: 0, fd_opened: [],
            blocked_forbidden: blockedForbidden,
            blocked_not_app_owned: blockedNotAppOwned,
            duration_ms: Date.now() - start,
        };
    }

    return new Promise((resolve) => {
        Java.perform(() => {
            // Declare finalise first so the early-return branches
            // below can call it without TDZ trouble.
            const finalise = (): LfiResult => ({
                probes_attempted: attempted,
                fd_opened: opened.slice(0, 30),
                blocked_forbidden: blockedForbidden,
                blocked_not_app_owned: blockedNotAppOwned,
                duration_ms: Date.now() - start,
            });

            let ctx: any, resolver: any, Uri: any;
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                Uri = Java.use("android.net.Uri");
                ctx = ActivityThread.currentApplication().getApplicationContext();
                resolver = ctx.getContentResolver();
            } catch (e: any) {
                sendError(`D_085: context resolve: ${e.message}`);
                return resolve(finalise());
            }

            const minInterval = rate > 0 ? 1000 / rate : 0;
            let idx = 0, lastFire = 0;

            const fire = () => {
                if (
                    idx >= safeUris.length ||
                    Date.now() - start >= window_s * 1000 ||
                    consecutiveCrashes >= maxCrashes
                ) {
                    return resolve(finalise());
                }
                const now = Date.now();
                const wait = Math.max(0, lastFire + minInterval - now);
                setTimeout(() => {
                    const uri = safeUris[idx++];
                    lastFire = Date.now();
                    attempted++;
                    // Defensive re-check at fire-time.
                    if (isSafe(uri) !== "ok") {
                        blockedForbidden++;
                        return fire();
                    }
                    try {
                        const uriObj = Uri.parse(uri);
                        const pfd = resolver.openFileDescriptor(uriObj, "r");
                        if (pfd !== null) {
                            try {
                                const fis = Java.use(
                                    "java.io.FileInputStream",
                                ).$new(pfd.getFileDescriptor());
                                const buf = Java.array(
                                    "byte", new Array(capBytes).fill(0),
                                );
                                const read = fis.read(buf);
                                let preview = "";
                                if (read > 0) {
                                    const S = Java.use("java.lang.String");
                                    preview = String(S.$new(buf, 0, read));
                                }
                                opened.push({
                                    uri,
                                    bytes_read: read,
                                    preview: preview.slice(0, capBytes),
                                });
                                fis.close();
                            } finally {
                                pfd.close();
                            }
                        }
                        consecutiveCrashes = 0;
                    } catch (_) {
                        consecutiveCrashes++;
                    }
                    fire();
                }, wait);
            };

            fire();
        });
    });
}

rpc.exports = { providerlfi };
