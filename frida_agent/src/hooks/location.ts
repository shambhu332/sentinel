/*
 * Background location-request observation (D_025).
 *
 * Hooks:
 *   - android.location.LocationManager.requestLocationUpdates
 *       (every overload — the API ships ~6 of them across
 *       LocationListener vs. PendingIntent variants).
 *   - com.google.android.gms.location.FusedLocationProviderClient
 *       .requestLocationUpdates (best-effort — class is absent on
 *       devices without Play Services).
 *
 * For every call we record:
 *   - api: source method label (LM / FLP).
 *   - caller_class: best-effort top-of-stack class name (skipping
 *       Thread / hook frames).
 *   - importance: ActivityManager.RunningAppProcessInfo.importance at
 *       call time — the canonical "is this process in the
 *       foreground" reading.
 *   - interval_ms / priority: pulled from the request object when
 *       available (LocationRequest.getInterval, getPriority on FLP).
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendLocationUpdateRequested, sendError } from "../lib/send.js";

const HOOK_FRAME_PREFIXES = [
    "java.lang.Thread",
    "dalvik.system.VMStack",
    // Frida-injected frames generally do not show up in the Java
    // stack-trace, but be defensive.
];

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 6; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

function callerClass(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            if (cls.indexOf("android.location.") === 0) continue;
            if (cls.indexOf("com.google.android.gms.location.") === 0) continue;
            let skip = false;
            for (let p = 0; p < HOOK_FRAME_PREFIXES.length; p++) {
                if (cls.indexOf(HOOK_FRAME_PREFIXES[p]) === 0) {
                    skip = true; break;
                }
            }
            if (skip) continue;
            return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

function currentImportance(): number {
    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const ctx = ActivityThread.currentApplication();
        if (!ctx) return -1;
        const AM = Java.use("android.app.ActivityManager");
        const am = ctx.getSystemService("activity");
        if (!am) return -1;
        const Info = Java.use(
            "android.app.ActivityManager$RunningAppProcessInfo",
        );
        const info = Info.$new();
        AM.getMyMemoryState(info);
        return Number(info.importance.value);
    } catch (_) { return -1; }
}

function safeNumber(value: any): number | undefined {
    try {
        const n = Number(value);
        if (Number.isFinite(n)) return n;
    } catch (_) { /* swallow */ }
    return undefined;
}

function extractLocationManagerRequest(args: any[]): {
    interval_ms?: number;
    priority?: number;
} {
    // LocationManager.requestLocationUpdates has many shapes:
    //   (String provider, long minTime, float minDist, LocationListener)
    //   (LocationRequest, Executor, LocationListener)
    //   (String provider, LocationRequest, Executor, LocationListener)
    //   (String provider, long minTime, float minDist, PendingIntent)
    // We pull a "minTime"-shaped Number out of arg[1] when present.
    if (args.length >= 4 && typeof args[1] === "number") {
        return { interval_ms: safeNumber(args[1]) };
    }
    if (args.length >= 1 && args[0] && args[0].getInterval) {
        try {
            return {
                interval_ms: safeNumber(args[0].getInterval()),
                priority: undefined,
            };
        } catch (_) { /* swallow */ }
    }
    return {};
}

function extractFlpRequest(args: any[]): {
    interval_ms?: number;
    priority?: number;
} {
    // FusedLocationProviderClient.requestLocationUpdates(LocationRequest,
    //                                                     LocationCallback,
    //                                                     Looper)
    if (args.length >= 1 && args[0]) {
        try {
            const interval = args[0].getInterval
                ? safeNumber(args[0].getInterval()) : undefined;
            const priority = args[0].getPriority
                ? safeNumber(args[0].getPriority()) : undefined;
            return { interval_ms: interval, priority };
        } catch (_) { /* swallow */ }
    }
    return {};
}

export function installLocationHooks(): number {
    let installed = 0;

    // ---- LocationManager ----
    try {
        const LM = Java.use("android.location.LocationManager");
        const overloads = LM.requestLocationUpdates
            ? LM.requestLocationUpdates.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    const extras = extractLocationManagerRequest(args);
                    sendLocationUpdateRequested({
                        api: "LocationManager.requestLocationUpdates",
                        caller_class: callerClass(),
                        importance: currentImportance(),
                        interval_ms: extras.interval_ms,
                        priority: extras.priority,
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- FusedLocationProviderClient ----
    try {
        const FLP = Java.use(
            "com.google.android.gms.location.FusedLocationProviderClient",
        );
        const overloads = FLP.requestLocationUpdates
            ? FLP.requestLocationUpdates.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    const extras = extractFlpRequest(args);
                    sendLocationUpdateRequested({
                        api: "FusedLocationProviderClient.requestLocationUpdates",
                        caller_class: callerClass(),
                        importance: currentImportance(),
                        interval_ms: extras.interval_ms,
                        priority: extras.priority,
                        stack: shortStack(),
                    });
                } catch (e) {
                    sendError(`location.flp report: ${String(e)}`);
                }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip — Play Services absent */ }

    return installed;
}
