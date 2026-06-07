/*
 * Runtime-registration observation (D_020 / D_021 / D_022).
 *
 * Hooks:
 *   - Context.registerReceiver (every overload)
 *   - PendingIntent.getActivity / getActivities / getBroadcast / getService
 *   - LocalServerSocket.<init>
 *
 * Pure observer. Reports the call args without altering behaviour.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendDynamicReceiverRegistered,
    sendPendingIntentCreated,
    sendLocalSocketServerCreated,
    sendError,
} from "../lib/send.js";

const RECEIVER_EXPORTED = 0x2;
const RECEIVER_NOT_EXPORTED = 0x4;

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

function actionsOf(filter: any): string[] {
    const out: string[] = [];
    try {
        if (filter && filter.countActions) {
            const n = filter.countActions();
            for (let i = 0; i < n; i++) {
                out.push(String(filter.getAction(i)));
            }
        }
    } catch (_) { /* swallow */ }
    return out;
}

function reportReceiver(
    receiver: any, filter: any, permission: any, flags: number,
    hasExplicit: boolean,
): void {
    try {
        let receiverClass = "<null>";
        if (receiver) {
            try { receiverClass = String(receiver.getClass().getName()); }
            catch (_) { /* swallow */ }
        }
        sendDynamicReceiverRegistered({
            receiver_class: receiverClass,
            actions: actionsOf(filter),
            flags,
            has_explicit_export: hasExplicit,
            permission: permission ? String(permission) : "",
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`receiver.register hook: ${String(e)}`);
    }
}

export function installRegistrationHooks(): number {
    let installed = 0;

    // ---- Context.registerReceiver ----
    try {
        const Context = Java.use("android.content.Context");

        const hookOverload = (
            params: string[],
            extractor: (
                args: any[],
            ) => { receiver: any; filter: any;
                   permission: any; flags: number;
                   hasExplicit: boolean },
        ) => {
            try {
                Context.registerReceiver.overload(...params)
                    .implementation = function (...args: any[]) {
                        const d = extractor(args);
                        reportReceiver(
                            d.receiver, d.filter,
                            d.permission, d.flags, d.hasExplicit,
                        );
                        return Context.registerReceiver
                            .overload(...params).apply(this, args);
                    };
                installed++;
            } catch (_) { /* overload absent on this API */ }
        };

        hookOverload(
            ["android.content.BroadcastReceiver", "android.content.IntentFilter"],
            (a) => ({
                receiver: a[0], filter: a[1],
                permission: null, flags: 0, hasExplicit: false,
            }),
        );
        hookOverload(
            ["android.content.BroadcastReceiver",
             "android.content.IntentFilter", "int"],
            (a) => ({
                receiver: a[0], filter: a[1],
                permission: null,
                flags: typeof a[2] === "number" ? a[2] : 0,
                hasExplicit: !!(
                    (typeof a[2] === "number")
                    && (a[2] & (RECEIVER_EXPORTED | RECEIVER_NOT_EXPORTED))
                ),
            }),
        );
        hookOverload(
            ["android.content.BroadcastReceiver",
             "android.content.IntentFilter",
             "java.lang.String", "android.os.Handler"],
            (a) => ({
                receiver: a[0], filter: a[1],
                permission: a[2],
                flags: 0, hasExplicit: false,
            }),
        );
        hookOverload(
            ["android.content.BroadcastReceiver",
             "android.content.IntentFilter",
             "java.lang.String", "android.os.Handler", "int"],
            (a) => ({
                receiver: a[0], filter: a[1],
                permission: a[2],
                flags: typeof a[4] === "number" ? a[4] : 0,
                hasExplicit: !!(
                    (typeof a[4] === "number")
                    && (a[4] & (RECEIVER_EXPORTED | RECEIVER_NOT_EXPORTED))
                ),
            }),
        );
    } catch (_) { /* skip */ }

    // ---- PendingIntent factories ----
    try {
        const PI = Java.use("android.app.PendingIntent");
        const factories = [
            "getActivity", "getBroadcast", "getService",
            "getForegroundService",
        ];
        for (let i = 0; i < factories.length; i++) {
            const name = factories[i];
            try {
                const overloads = (PI as any)[name].overloads;
                for (let j = 0; j < overloads.length; j++) {
                    const ov = overloads[j];
                    ov.implementation = function (...args: any[]) {
                        try {
                            // Typical args: ctx, requestCode, intent, flags
                            // Locate the Intent + the int flags by type
                            let intent: any = null;
                            let flags = 0;
                            for (let k = 0; k < args.length; k++) {
                                if (args[k] && args[k].$className === undefined
                                        && typeof args[k] === "number") {
                                    flags = args[k];
                                }
                                if (args[k] && args[k].getAction) {
                                    intent = args[k];
                                }
                            }
                            let action = "", hasComponent = false;
                            if (intent) {
                                try { action = String(intent.getAction() || ""); }
                                catch (_) { /* swallow */ }
                                try {
                                    hasComponent = !!intent.getComponent();
                                } catch (_) { /* swallow */ }
                            }
                            sendPendingIntentCreated({
                                factory: name,
                                flags,
                                intent_action: action,
                                intent_has_component: hasComponent,
                                stack: shortStack(),
                            });
                        } catch (e) {
                            sendError(`pi.${name} hook: ${String(e)}`);
                        }
                        return ov.apply(this, args);
                    };
                    installed++;
                }
            } catch (_) { /* factory absent */ }
        }
    } catch (_) { /* skip */ }

    // ---- LocalServerSocket ----
    try {
        const LSS = Java.use("android.net.LocalServerSocket");
        const overloads = LSS.$init.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    let namespace = "FILESYSTEM";
                    let name = "";
                    if (args.length === 1) {
                        // ctor(String) — FILESYSTEM
                        name = String(args[0]);
                    } else if (args.length >= 2) {
                        // ctor(String, Namespace) — explicit
                        name = String(args[0]);
                        try { namespace = String(args[1].toString()); }
                        catch (_) { /* swallow */ }
                    }
                    sendLocalSocketServerCreated({
                        namespace, name,
                        stack: shortStack(),
                    });
                } catch (e) {
                    sendError(`lss.<init> hook: ${String(e)}`);
                }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* class absent */ }

    return installed;
}
