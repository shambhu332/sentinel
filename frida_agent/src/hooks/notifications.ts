/*
 * Notification observation hook (D_012).
 *
 * Hooks NotificationManager.notify(int, Notification). For every
 * posted Notification we extract:
 *
 *   - channel id and importance (via NotificationManager
 *     .getNotificationChannel),
 *   - visibility flag,
 *   - whether a public version was attached,
 *   - title (extras.android.title) and text (extras.android.text /
 *     android.bigText). Long values are truncated before send.
 *
 * Pure observer. Does not alter the Notification.
 */
import { Java } from "../lib/java_ready.js";
import { sendNotificationPosted, sendError } from "../lib/send.js";

const PREVIEW_MAX = 160;

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

function trunc(t: unknown): string {
    if (t === null || t === undefined) return "";
    const s = String(t);
    return s.length <= PREVIEW_MAX ? s : s.substring(0, PREVIEW_MAX) + "…";
}

function readExtras(notif: any): { title: string; text: string } {
    const out = { title: "", text: "" };
    try {
        const extras = notif.extras.value || notif.extras;
        if (!extras) return out;
        const titleObj = extras.getCharSequence
            ? extras.getCharSequence("android.title")
            : extras.get("android.title");
        const textObj = extras.getCharSequence
            ? extras.getCharSequence("android.text")
            : extras.get("android.text");
        const bigTextObj = extras.getCharSequence
            ? extras.getCharSequence("android.bigText")
            : extras.get("android.bigText");
        out.title = trunc(titleObj);
        out.text = trunc(bigTextObj || textObj);
    } catch (_) { /* swallow */ }
    return out;
}

function importanceOf(nm: any, channelId: string): number | undefined {
    try {
        if (!channelId || !nm.getNotificationChannel) return undefined;
        const ch = nm.getNotificationChannel(channelId);
        if (!ch) return undefined;
        return ch.getImportance();
    } catch (_) { return undefined; }
}

export function installNotificationHooks(): number {
    let installed = 0;
    try {
        const NM = Java.use("android.app.NotificationManager");
        NM.notify.overload(
            "int", "android.app.Notification",
        ).implementation = function (id: number, notif: any) {
            try {
                const visibility = notif.visibility !== undefined
                    ? Number(notif.visibility.value !== undefined
                             ? notif.visibility.value : notif.visibility)
                    : undefined;
                const channelId = notif.getChannelId
                    ? String(notif.getChannelId())
                    : "";
                const importance = importanceOf(this, channelId);
                const hasPublic = !!(notif.publicVersion
                    && notif.publicVersion.value);
                const { title, text } = readExtras(notif);
                sendNotificationPosted({
                    channel_id: channelId,
                    channel_importance: importance,
                    visibility,
                    has_public_version: hasPublic,
                    title, text,
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`notification.notify hook: ${String(e)}`);
            }
            return this.notify(id, notif);
        };
        installed++;
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") === -1) {
            sendError(`notification install: ${msg}`);
        }
    }
    return installed;
}
