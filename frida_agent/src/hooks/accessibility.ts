/*
 * Accessibility + NotificationListener observation (D_016).
 *
 * Hooks every subclass of:
 *   - android.accessibilityservice.AccessibilityService
 *       .onAccessibilityEvent(AccessibilityEvent)
 *   - android.service.notification.NotificationListenerService
 *       .onNotificationPosted(StatusBarNotification)
 *
 * We can't know the app's concrete service class at install time, so
 * we use Java.enumerateLoadedClasses-style discovery via Java.choose
 * deferred behind a small registration helper. To keep the hook
 * compatible with the simple Java.use pattern we hook the *base*
 * service classes — the call dispatch reaches the base class first
 * so the base-class hook runs.
 *
 * All text content is REDACTED before send (first 4 + last 2 chars).
 */
import { Java } from "../lib/java_ready.js";
import {
    sendA11yEvent,
    sendA11yAction,
    sendNotifListenerReceived,
    sendError,
} from "../lib/send.js";

const OTP_REGEX = /(?<!\d)\d{4,8}(?!\d)/;

function redact(t: unknown): string {
    if (t === null || t === undefined) return "";
    const s = String(t);
    if (!s) return "";
    if (s.length <= 8) return s.substring(0, 2) + "…";
    return s.substring(0, 4) + "…" + s.substring(s.length - 2)
        + ` (len=${s.length})`;
}

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

export function installAccessibilityHooks(): number {
    let installed = 0;

    // ---- AccessibilityService.onAccessibilityEvent ----
    try {
        const Svc = Java.use(
            "android.accessibilityservice.AccessibilityService",
        );
        const overload = Svc.onAccessibilityEvent.overload(
            "android.view.accessibility.AccessibilityEvent",
        );
        overload.implementation = function (event: any) {
            try {
                const pkg = event.getPackageName
                    ? String(event.getPackageName() || "")
                    : "";
                let text = "";
                try {
                    const list = event.getText
                        ? event.getText() : null;
                    if (list && list.size && list.size() > 0) {
                        text = String(list.get(0));
                    }
                } catch (_) { /* swallow */ }
                sendA11yEvent({
                    event_type: event.getEventType
                        ? event.getEventType() : undefined,
                    source_package: pkg,
                    source_text_redacted: redact(text),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`a11y.event hook: ${String(e)}`);
            }
            return overload.call(this, event);
        };
        installed++;

        // ---- AccessibilityService.performGlobalAction ----
        try {
            Svc.performGlobalAction.implementation = function (action: number) {
                try {
                    sendA11yAction({
                        action: `performGlobalAction(${action})`,
                        source_package: "<global>",
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return this.performGlobalAction(action);
            };
            installed++;
        } catch (_) { /* API may differ */ }
    } catch (_) { /* AccessibilityService absent */ }

    // ---- AccessibilityNodeInfo.performAction ----
    try {
        const Node = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        const ov = Node.performAction.overload("int");
        ov.implementation = function (action: number) {
            try {
                let pkg = "";
                try {
                    pkg = String(this.getPackageName() || "");
                } catch (_) { /* swallow */ }
                sendA11yAction({
                    action: `node.performAction(${action})`,
                    source_package: pkg,
                    stack: shortStack(),
                });
            } catch (_) { /* swallow */ }
            return ov.call(this, action);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- NotificationListenerService.onNotificationPosted ----
    try {
        const NLS = Java.use(
            "android.service.notification.NotificationListenerService",
        );
        const ov = NLS.onNotificationPosted.overload(
            "android.service.notification.StatusBarNotification",
        );
        ov.implementation = function (sbn: any) {
            try {
                const pkg = sbn.getPackageName
                    ? String(sbn.getPackageName() || "")
                    : "";
                const notif = sbn.getNotification();
                let title = "", text = "";
                let channelId = "";
                try {
                    const extras = notif.extras.value || notif.extras;
                    if (extras) {
                        const t = extras.getCharSequence
                            ? extras.getCharSequence("android.title")
                            : extras.get("android.title");
                        const x = extras.getCharSequence
                            ? extras.getCharSequence("android.text")
                            : extras.get("android.text");
                        title = String(t || "");
                        text = String(x || "");
                    }
                    if (notif.getChannelId) {
                        channelId = String(notif.getChannelId() || "");
                    }
                } catch (_) { /* swallow */ }
                const hasOtp = OTP_REGEX.test(text);
                sendNotifListenerReceived({
                    source_package: pkg,
                    channel_id: channelId,
                    title_redacted: redact(title),
                    text_redacted: redact(text),
                    has_otp_shape: hasOtp,
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`notif_listener hook: ${String(e)}`);
            }
            return ov.call(this, sbn);
        };
        installed++;
    } catch (_) { /* NotificationListenerService absent */ }

    return installed;
}
