/*
 * Implicit-intent dispatch hooks (D_015).
 *
 * Watches Context.startActivity / sendBroadcast / bindService /
 * startService for Intents without an explicit target and reports the
 * extras-key set so the Python agent can flag credential-named keys.
 *
 * We never serialise the Intent extras values — only the key set —
 * because values are often Parcelables of arbitrary type and may
 * carry the secret itself.
 */
import { Java } from "../lib/java_ready.js";
import { sendIntentDispatched, sendError } from "../lib/send.js";

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

function describeIntent(intent: any): {
    action: string;
    hasComponent: boolean;
    pkg: string;
    extras: string[];
} {
    let action = "";
    let hasComponent = false;
    let pkg = "";
    let extras: string[] = [];
    try {
        const a = intent.getAction ? intent.getAction() : null;
        action = a ? String(a) : "";
    } catch (_) { /* swallow */ }
    try {
        const c = intent.getComponent ? intent.getComponent() : null;
        hasComponent = !!c;
    } catch (_) { /* swallow */ }
    try {
        const p = intent.getPackage ? intent.getPackage() : null;
        pkg = p ? String(p) : "";
    } catch (_) { /* swallow */ }
    try {
        const b = intent.getExtras ? intent.getExtras() : null;
        if (b && b.keySet) {
            const keys = b.keySet().toArray();
            for (let i = 0; i < keys.length; i++) {
                extras.push(String(keys[i]));
            }
        }
    } catch (_) { /* swallow */ }
    return { action, hasComponent, pkg, extras };
}

function emit(method: string, intent: any): void {
    try {
        const d = describeIntent(intent);
        sendIntentDispatched({
            method,
            action: d.action,
            has_component: d.hasComponent,
            package: d.pkg,
            extras: d.extras,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`intent.${method}: ${String(e)}`);
    }
}

export function installIntentDispatchHooks(): number {
    let installed = 0;
    try {
        const Context = Java.use("android.content.Context");

        const hook = (
            name: string, paramTypes: string[],
        ) => {
            try {
                (Context as any)[name].overload(...paramTypes)
                    .implementation = function (...args: any[]) {
                        const intent = args[0];
                        if (intent) emit(name, intent);
                        return (Context as any)[name]
                            .overload(...paramTypes).apply(this, args);
                    };
                installed++;
            } catch (_) { /* overload absent on this API */ }
        };

        hook("startActivity", ["android.content.Intent"]);
        hook("startActivity",
             ["android.content.Intent", "android.os.Bundle"]);
        hook("sendBroadcast", ["android.content.Intent"]);
        hook("sendBroadcast",
             ["android.content.Intent", "java.lang.String"]);
        hook("startService", ["android.content.Intent"]);
        hook("bindService",
             ["android.content.Intent",
              "android.content.ServiceConnection", "int"]);
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") === -1) {
            sendError(`intent_dispatch install: ${msg}`);
        }
    }
    return installed;
}
