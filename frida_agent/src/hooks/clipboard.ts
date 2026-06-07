/*
 * Clipboard hooks (D_001).
 *
 * We instrument every Java entry point onto the system clipboard:
 *   ClipboardManager.setPrimaryClip(ClipData)
 *   ClipboardManager.getPrimaryClip()
 *
 * For writes we exfiltrate the ClipData label + the first item's text
 * (truncated). The Python-side ClipboardLeakAgent applies the
 * credential-shape heuristics; this script keeps zero policy.
 *
 * For reads we capture a short caller stack so the agent can tell the
 * system paste UI from the app polling the clipboard.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendClipboardWrite,
    sendClipboardRead,
    sendError,
} from "../lib/send.js";

const TEXT_PREVIEW_MAX = 96;

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        // Skip the Frida thunk frames; take the next 4 callers.
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 4; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_e) {
        return "";
    }
}

function previewText(t: unknown): string {
    if (t === null || t === undefined) return "";
    const s = String(t);
    if (s.length <= TEXT_PREVIEW_MAX) return s;
    return s.substring(0, TEXT_PREVIEW_MAX) + "…";
}

export function installClipboardHooks(): number {
    let installed = 0;
    try {
        const ClipboardManager = Java.use("android.content.ClipboardManager");

        ClipboardManager.setPrimaryClip.implementation = function (clip: any) {
            try {
                let label = "";
                let text = "";
                let mimeTypes: string[] = [];
                if (clip) {
                    const desc = clip.getDescription();
                    if (desc) {
                        label = String(desc.getLabel() || "");
                        const n = desc.getMimeTypeCount();
                        for (let i = 0; i < n; i++) {
                            mimeTypes.push(String(desc.getMimeType(i)));
                        }
                    }
                    const itemCount = clip.getItemCount();
                    if (itemCount > 0) {
                        const item = clip.getItemAt(0);
                        text = previewText(item.getText() || item.coerceToText
                                            ? item.coerceToText(null) : "");
                    }
                }
                sendClipboardWrite({
                    label,
                    text,
                    mime_types: mimeTypes,
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`clipboard.write hook: ${String(e)}`);
            }
            return this.setPrimaryClip(clip);
        };
        installed++;

        ClipboardManager.getPrimaryClip.implementation = function () {
            const result = this.getPrimaryClip();
            try {
                let mimeTypes: string[] = [];
                if (result) {
                    const desc = result.getDescription();
                    if (desc) {
                        const n = desc.getMimeTypeCount();
                        for (let i = 0; i < n; i++) {
                            mimeTypes.push(String(desc.getMimeType(i)));
                        }
                    }
                }
                sendClipboardRead({
                    mime_types: mimeTypes,
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`clipboard.read hook: ${String(e)}`);
            }
            return result;
        };
        installed++;
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") === -1) {
            sendError(`clipboard install: ${msg}`);
        }
    }
    return installed;
}
