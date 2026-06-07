/*
 * SMS permission / Retriever-API observation (D_018).
 *
 * Hooks:
 *   - android.content.BroadcastReceiver.onReceive — filtered to SMS
 *     actions (SMS_RECEIVED / WAP_PUSH_RECEIVED). Captures sender +
 *     redacted body.
 *   - android.content.ContentResolver.query — captured when URI
 *     starts with content://sms or content://mms-sms.
 *   - com.google.android.gms.auth.api.phone.SmsRetrieverClient
 *     .startSmsRetriever / startSmsUserConsent (best-effort — class
 *     may be absent on devices without Play Services).
 */
import { Java } from "../lib/java_ready.js";
import {
    sendSmsBroadcast,
    sendSmsProviderQuery,
    sendSmsRetrieverStarted,
    sendError,
} from "../lib/send.js";

const OTP_REGEX = /(?<!\d)\d{4,8}(?!\d)/;
const SMS_ACTIONS = [
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.WAP_PUSH_RECEIVED",
];

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

function isSmsAction(action: string): boolean {
    if (!action) return false;
    for (let i = 0; i < SMS_ACTIONS.length; i++) {
        if (action === SMS_ACTIONS[i]) return true;
    }
    return false;
}

function extractSmsContent(intent: any): {
    sender: string;
    body: string;
} {
    let sender = "";
    let body = "";
    try {
        const Telephony = Java.use(
            "android.provider.Telephony$Sms$Intents",
        );
        const messages = Telephony.getMessagesFromIntent(intent);
        if (messages && messages.length > 0) {
            const first = messages[0];
            sender = String(first.getOriginatingAddress() || "");
            // Concatenate multi-part SMS bodies
            const parts: string[] = [];
            for (let i = 0; i < messages.length; i++) {
                parts.push(String(messages[i].getMessageBody() || ""));
            }
            body = parts.join("");
        }
    } catch (_) {
        // Fall back to manual PDU parsing — too brittle to do here.
    }
    return { sender, body };
}

export function installSmsHooks(): number {
    let installed = 0;

    // ---- BroadcastReceiver.onReceive ----
    try {
        const Receiver = Java.use("android.content.BroadcastReceiver");
        Receiver.onReceive.implementation = function (ctx: any, intent: any) {
            try {
                const action = intent && intent.getAction
                    ? String(intent.getAction() || "")
                    : "";
                if (isSmsAction(action)) {
                    const { sender, body } = extractSmsContent(intent);
                    sendSmsBroadcast({
                        sender: redact(sender),
                        body_redacted: redact(body),
                        has_otp_shape: OTP_REGEX.test(body),
                        source_method: action,
                        stack: shortStack(),
                    });
                }
            } catch (e) {
                sendError(`sms.broadcast hook: ${String(e)}`);
            }
            return this.onReceive(ctx, intent);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- ContentResolver.query ----
    try {
        const Resolver = Java.use("android.content.ContentResolver");
        // Hook the most common 5-arg overload. Other overloads
        // (Bundle-based, API 26+ variations) follow the same pattern;
        // we'd add them as more are observed in real captures.
        const ov = Resolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;",
            "java.lang.String", "[Ljava.lang.String;",
            "java.lang.String",
        );
        ov.implementation = function (uri: any, p: any, s: any, sa: any, so: any) {
            try {
                const uriStr = uri ? String(uri.toString()) : "";
                if (uriStr.indexOf("content://sms") === 0
                    || uriStr.indexOf("content://mms-sms") === 0) {
                    sendSmsProviderQuery({
                        uri: uriStr,
                        stack: shortStack(),
                    });
                }
            } catch (_) { /* swallow */ }
            return ov.call(this, uri, p, s, sa, so);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- SmsRetrieverClient ----
    try {
        const Retriever = Java.use(
            "com.google.android.gms.auth.api.phone.SmsRetrieverClient",
        );
        const overloads = Retriever.startSmsRetriever
            ? Retriever.startSmsRetriever.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    sendSmsRetrieverStarted({
                        api: "startSmsRetriever",
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
        const consentOverloads = Retriever.startSmsUserConsent
            ? Retriever.startSmsUserConsent.overloads : [];
        for (let i = 0; i < consentOverloads.length; i++) {
            const ov = consentOverloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    sendSmsRetrieverStarted({
                        api: "startSmsUserConsent",
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* Play services not on device — fine */ }

    return installed;
}
