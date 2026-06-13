/*
 * D_049 — Notification OTP-leak monitor.
 *
 * Hooks NotificationManager.notify and captures the title + text
 * content of every notification posted during the scan window.
 * Also captures the visibility setting (PUBLIC / PRIVATE / SECRET)
 * so the agent can flag OTP content that would render on the
 * lockscreen.
 *
 * Passive monitor — no active triggering. The caller decides how
 * long to listen.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface NotifyEvent {
    id: number;
    channel: string;
    title: string;
    text_preview: string;
    visibility: number;          // 1=PUBLIC 0=PRIVATE -1=SECRET
    is_otp_shape: boolean;
}

interface NotifySummary {
    captured: NotifyEvent[];
    total: number;
    otp_with_public_visibility: number;
    duration_ms: number;
}

const OTP_RE = /\b(otp|verification|code|pin|2fa)\b/i;

async function notificationsnoop(
    payload: { safety_budget?: any },
): Promise<NotifySummary> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 20;
    const start = Date.now();
    const captured: NotifyEvent[] = [];

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const NM = Java.use("android.app.NotificationManager");
                NM.notify.overload(
                    "java.lang.String", "int", "android.app.Notification",
                ).implementation = function (
                    tag: any, id: any, notification: any,
                ) {
                    try {
                        const extras = notification.extras.value;
                        const title = String(extras.getCharSequence("android.title") || "");
                        const text = String(extras.getCharSequence("android.text") || "");
                        const visibility = notification.visibility.value;
                        captured.push({
                            id: id,
                            channel: String(notification.getChannelId()),
                            title: title.slice(0, 80),
                            text_preview: text.slice(0, 200),
                            visibility,
                            is_otp_shape: OTP_RE.test(`${title} ${text}`),
                        });
                    } catch (_) { /* ignore parse */ }
                    return this.notify(tag, id, notification);
                };
            } catch (e: any) {
                sendError(`D_049: ${e.message}`);
            }
            setTimeout(() => {
                const otp_public = captured.filter(
                    (e) => e.is_otp_shape && e.visibility === 1,
                ).length;
                resolve({
                    captured: captured.slice(0, 100),
                    total: captured.length,
                    otp_with_public_visibility: otp_public,
                    duration_ms: Date.now() - start,
                });
            }, window_s * 1000);
        });
    });
}

rpc.exports = { notificationsnoop };
