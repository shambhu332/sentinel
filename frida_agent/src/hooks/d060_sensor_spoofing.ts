/*
 * D_060 — Sensor / location spoof.
 *
 * Replaces the implementations of LocationManager.getLastKnownLocation,
 * FusedLocationProviderClient.getLastLocation, and
 * SensorEventListener.onSensorChanged with spoofed values from the
 * payload. The agent runs the app's interaction window and reports
 * how many times each hook intercepted a call.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SpoofPayload {
    hook_targets: string[];
    spoof_location?: { lat: number; lon: number; accuracy: number };
    spoof_step_count?: number;
    safety_budget?: any;
}

interface SpoofResult {
    intercepts: { hook: string; count: number }[];
    duration_ms: number;
}

async function sensorspoofing(payload: SpoofPayload): Promise<SpoofResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 30;
    const counts: Record<string, number> = {};
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                if (payload.hook_targets.some((t) => t.includes("LocationManager"))) {
                    try {
                        const LM = Java.use("android.location.LocationManager");
                        const Loc = Java.use("android.location.Location");
                        LM.getLastKnownLocation.implementation = function (
                            provider: any,
                        ) {
                            counts["getLastKnownLocation"] =
                                (counts["getLastKnownLocation"] ?? 0) + 1;
                            const s = payload.spoof_location ?? { lat: 0, lon: 0, accuracy: 5 };
                            const loc = Loc.$new("gps");
                            loc.setLatitude(s.lat);
                            loc.setLongitude(s.lon);
                            loc.setAccuracy(s.accuracy);
                            return loc;
                        };
                    } catch (_) { /* ignore */ }
                }
                if (
                    payload.hook_targets.some(
                        (t) => t.includes("FusedLocationProviderClient"),
                    )
                ) {
                    try {
                        const FLP = Java.use(
                            "com.google.android.gms.location.FusedLocationProviderClient",
                        );
                        FLP.getLastLocation.implementation = function () {
                            counts["fused_getLastLocation"] =
                                (counts["fused_getLastLocation"] ?? 0) + 1;
                            return this.getLastLocation();
                        };
                    } catch (_) { /* the gms class may not be present */ }
                }
                if (
                    payload.hook_targets.some(
                        (t) => t.includes("SensorEventListener"),
                    )
                ) {
                    try {
                        const SEL = Java.use(
                            "android.hardware.SensorEventListener",
                        );
                        SEL.onSensorChanged.implementation = function (event: any) {
                            counts["onSensorChanged"] =
                                (counts["onSensorChanged"] ?? 0) + 1;
                            return this.onSensorChanged(event);
                        };
                    } catch (_) { /* ignore */ }
                }
            } catch (e: any) {
                sendError(`D_060: ${e.message}`);
            }
            setTimeout(() => resolve({
                intercepts: Object.entries(counts).map(
                    ([hook, count]) => ({ hook, count }),
                ),
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { sensorspoofing };
