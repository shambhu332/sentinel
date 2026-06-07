/*
 * Window-flag + sensitive-input hooks (D_002).
 *
 *   - EditText.setInputType — emit "ui.sensitive_input_seen" whenever
 *     a password / numeric-PIN input type is attached to a field.
 *   - Window.setFlags / Window.addFlags — emit "ui.window_flags" with
 *     the resulting flag set; secure=true if FLAG_SECURE (0x2000) is
 *     present.
 *
 * The Python agent (FlagSecureMissingAgent) joins these by Activity.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendSensitiveInputSeen,
    sendWindowFlags,
    sendError,
} from "../lib/send.js";

const TYPE_TEXT_VARIATION_PASSWORD            = 0x00000080;
const TYPE_TEXT_VARIATION_VISIBLE_PASSWORD    = 0x00000090;
const TYPE_TEXT_VARIATION_WEB_PASSWORD        = 0x000000e0;
const TYPE_NUMBER_VARIATION_PASSWORD          = 0x00000010;
const TYPE_CLASS_TEXT                         = 0x00000001;
const TYPE_CLASS_NUMBER                       = 0x00000002;
const FLAG_SECURE                             = 0x00002000;

function inputIsSensitive(t: number): boolean {
    const cls = t & 0x0000000f;
    const variation = t & 0x00000ff0;
    if (cls === TYPE_CLASS_TEXT) {
        return variation === TYPE_TEXT_VARIATION_PASSWORD
            || variation === TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            || variation === TYPE_TEXT_VARIATION_WEB_PASSWORD;
    }
    if (cls === TYPE_CLASS_NUMBER) {
        return variation === TYPE_NUMBER_VARIATION_PASSWORD;
    }
    return false;
}

function currentActivity(): string {
    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const at = ActivityThread.currentActivityThread();
        const records = at.mActivities.value;
        const keys = records.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {
            const rec = records.get(keys[i]);
            if (!rec.paused.value) {
                return String(rec.activity.value.getClass().getName());
            }
        }
    } catch (_e) { /* swallow — best effort */ }
    return "<unknown>";
}

export function installWindowFlagHooks(): number {
    let installed = 0;

    // ---- EditText.setInputType ----
    try {
        const EditText = Java.use("android.widget.EditText");
        EditText.setInputType.implementation = function (type: number) {
            try {
                if (inputIsSensitive(type)) {
                    let field = "<unnamed>";
                    try {
                        const idHint = this.getHint();
                        if (idHint) field = String(idHint);
                        else {
                            const idInt = this.getId();
                            field = `id=${idInt}`;
                        }
                    } catch (_) { /* keep default */ }
                    sendSensitiveInputSeen({
                        activity: currentActivity(),
                        field,
                    });
                }
            } catch (e) {
                sendError(`input-type hook: ${String(e)}`);
            }
            return this.setInputType(type);
        };
        installed++;
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") === -1) {
            sendError(`EditText install: ${msg}`);
        }
    }

    // ---- Window.setFlags ----
    try {
        const Window = Java.use("android.view.Window");
        Window.setFlags.implementation = function (
            flags: number, mask: number,
        ) {
            const result = this.setFlags(flags, mask);
            try {
                sendWindowFlags({
                    activity: currentActivity(),
                    flags: flags & mask,
                    secure: ((flags & mask) & FLAG_SECURE) !== 0,
                });
            } catch (e) {
                sendError(`window.setFlags hook: ${String(e)}`);
            }
            return result;
        };
        installed++;

        Window.addFlags.implementation = function (flags: number) {
            const result = this.addFlags(flags);
            try {
                sendWindowFlags({
                    activity: currentActivity(),
                    flags,
                    secure: (flags & FLAG_SECURE) !== 0,
                });
            } catch (e) {
                sendError(`window.addFlags hook: ${String(e)}`);
            }
            return result;
        };
        installed++;
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") === -1) {
            sendError(`Window install: ${msg}`);
        }
    }

    return installed;
}
