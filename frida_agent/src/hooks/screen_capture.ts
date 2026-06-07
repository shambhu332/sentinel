/*
 * Screen-capture / MediaProjection observation (D_019).
 *
 * Hooks:
 *   - android.media.projection.MediaProjectionManager.getMediaProjection
 *   - android.media.projection.MediaProjection.createVirtualDisplay
 *   - android.media.ImageReader.acquireLatestImage / acquireNextImage
 *   - android.media.MediaRecorder.setVideoSource
 *
 * Pure observer. Reports the events; the Python ScreenCaptureAgent
 * classifies the pipeline.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendProjectionStarted,
    sendVirtualDisplayCreated,
    sendImageReaderUsed,
    sendMediaRecorderVideoSource,
    sendError,
} from "../lib/send.js";

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 4; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

export function installScreenCaptureHooks(): number {
    let installed = 0;

    // ---- MediaProjectionManager.getMediaProjection(int, Intent) ----
    try {
        const Mgr = Java.use(
            "android.media.projection.MediaProjectionManager",
        );
        const ov = Mgr.getMediaProjection.overload(
            "int", "android.content.Intent",
        );
        ov.implementation = function (resultCode: number, data: any) {
            const out = ov.call(this, resultCode, data);
            try {
                if (out !== null) {
                    sendProjectionStarted({
                        result_code: resultCode,
                        stack: shortStack(),
                    });
                }
            } catch (_) { /* swallow */ }
            return out;
        };
        installed++;
    } catch (_) { /* class absent */ }

    // ---- MediaProjection.createVirtualDisplay ----
    try {
        const Proj = Java.use("android.media.projection.MediaProjection");
        const overloads = Proj.createVirtualDisplay.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    // args[0]=name, args[1]=width, args[2]=height,
                    // args[3]=dpi, args[4]=flags, args[5]=surface, ...
                    const w = typeof args[1] === "number" ? args[1] : undefined;
                    const h = typeof args[2] === "number" ? args[2] : undefined;
                    const d = typeof args[3] === "number" ? args[3] : undefined;
                    let surfaceType = "<unknown>";
                    if (args.length >= 6 && args[5]) {
                        try {
                            surfaceType = String(args[5].getClass().getName());
                        } catch (_) { /* swallow */ }
                    }
                    sendVirtualDisplayCreated({
                        width: w, height: h, dpi: d,
                        surface_type: surfaceType,
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- ImageReader.acquireLatestImage / acquireNextImage ----
    try {
        const Reader = Java.use("android.media.ImageReader");
        const apis = ["acquireLatestImage", "acquireNextImage"];
        for (let i = 0; i < apis.length; i++) {
            const name = apis[i];
            try {
                (Reader as any)[name].implementation = function () {
                    try {
                        sendImageReaderUsed({
                            api: name, stack: shortStack(),
                        });
                    } catch (_) { /* swallow */ }
                    return (this as any)[name]();
                };
                installed++;
            } catch (_) { /* method may differ */ }
        }
    } catch (_) { /* skip */ }

    // ---- MediaRecorder.setVideoSource(int) ----
    try {
        const Rec = Java.use("android.media.MediaRecorder");
        Rec.setVideoSource.implementation = function (src: number) {
            try {
                sendMediaRecorderVideoSource({
                    source: src,
                    stack: shortStack(),
                });
            } catch (_) { /* swallow */ }
            return this.setVideoSource(src);
        };
        installed++;
    } catch (_) { /* skip */ }

    return installed;
}
