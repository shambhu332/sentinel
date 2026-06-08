/*
 * Clipboard read observation (D_036).
 *
 * Hooks:
 *   - android.content.ClipboardManager.getPrimaryClip
 *   - android.content.ClipboardManager.getPrimaryClipDescription
 *   - android.content.ClipboardManager.addPrimaryClipChangedListener
 *
 * D_001's ClipboardLeakAgent hooks the *write* side
 * (setPrimaryClip). D_036 covers reads / listener registration.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendClipboardReadObserved, sendError } from "../lib/send.js";

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

function callerClass(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            if (cls.indexOf("android.content.ClipboardManager") === 0) continue;
            if (cls.indexOf("java.lang.Thread") === 0) continue;
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
        const Info = Java.use(
            "android.app.ActivityManager$RunningAppProcessInfo",
        );
        const info = Info.$new();
        AM.getMyMemoryState(info);
        return Number(info.importance.value);
    } catch (_) { return -1; }
}

function classifyShape(clip: any): string {
    if (!clip) return "empty";
    try {
        const count = Number(clip.getItemCount());
        if (count === 0) return "empty";
        const item = clip.getItemAt(0);
        const raw = item ? item.getText() : null;
        if (!raw) return "non_text";
        const s = String(raw);
        if (!s) return "empty";
        if (/^\d{4,8}$/.test(s)) return "otp_like";
        if (/^https?:\/\//i.test(s)) return "url";
        if (/^(?:\d[ -]?){13,19}$/.test(s.replace(/\s/g, ""))) return "credit_card";
        if (s.length <= 16) return "short";
        return "arbitrary";
    } catch (_) { return "unknown"; }
}

function emit(api: string, clip: any): void {
    try {
        sendClipboardReadObserved({
            api,
            caller_class: callerClass(),
            importance: currentImportance(),
            content_shape: classifyShape(clip),
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`clipboard.read.emit: ${String(e)}`);
    }
}

export function installClipboardReadHooks(): number {
    let installed = 0;
    let CM: any;
    try { CM = Java.use("android.content.ClipboardManager"); }
    catch (_) { return 0; }

    try {
        if (CM.getPrimaryClip) {
            const ov = CM.getPrimaryClip.overload();
            ov.implementation = function () {
                const clip = ov.call(this);
                try { emit("getPrimaryClip", clip); }
                catch (_) { /* swallow */ }
                return clip;
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    try {
        if (CM.getPrimaryClipDescription) {
            const ov = CM.getPrimaryClipDescription.overload();
            ov.implementation = function () {
                try { emit("getPrimaryClipDescription", null); }
                catch (_) { /* swallow */ }
                return ov.call(this);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    try {
        if (CM.addPrimaryClipChangedListener) {
            const ov = CM.addPrimaryClipChangedListener.overload(
                "android.content.ClipboardManager$OnPrimaryClipChangedListener",
            );
            ov.implementation = function (listener: any) {
                try { emit("addPrimaryClipChangedListener", null); }
                catch (_) { /* swallow */ }
                return ov.call(this, listener);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    return installed;
}
