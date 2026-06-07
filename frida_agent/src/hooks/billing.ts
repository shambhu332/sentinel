/*
 * Billing / IAP observation hooks (D_008).
 *
 * Watches the Google Play Billing Library v3+ entry points the app
 * uses to consume a Purchase. We never modify the result; we emit
 * one event per observed Purchase and one per acknowledgePurchase
 * call so the Python agent can correlate them with mitmproxy flows.
 *
 * We probe two class FQCNs so the hook works under both the
 * standalone library (`com.android.billingclient.api.*`) and the
 * shaded JetPack package (`androidx.billingclient.*`) if present.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendPurchaseObserved,
    sendFeatureUnlock,
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

function tokenPrefix(token: string): string {
    if (!token) return "";
    const t = String(token);
    return t.substring(0, Math.min(16, t.length));
}

function emitPurchase(p: any): void {
    try {
        if (!p) return;
        sendPurchaseObserved({
            sku: String(p.getSku ? p.getSku() : (p.getProducts ? p.getProducts().toString() : "")),
            purchase_state: p.getPurchaseState ? p.getPurchaseState() : undefined,
            order_id: String(p.getOrderId ? p.getOrderId() : ""),
            token_prefix: tokenPrefix(
                p.getPurchaseToken ? p.getPurchaseToken() : "",
            ),
            acknowledged: p.isAcknowledged ? !!p.isAcknowledged() : false,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`billing.purchase emit: ${String(e)}`);
    }
}

function hookBillingClasses(prefix: string): number {
    let installed = 0;

    // Purchase class — hook the constructor that the library uses to
    // build a Purchase out of the Play app's JSON. Both v3 and v5
    // expose Purchase(String, String) constructors.
    try {
        const Purchase = Java.use(`${prefix}.Purchase`);
        const overloads = Purchase.$init.overloads;
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                const r = ov.apply(this, args);
                try {
                    emitPurchase(this);
                } catch (_) { /* swallow */ }
                return r;
            };
            installed++;
        }
    } catch (_) { /* class absent */ }

    // BillingClient.acknowledgePurchase — confirm the ack call fires.
    try {
        const BC = Java.use(`${prefix}.BillingClient`);
        const overloads = BC.acknowledgePurchase
            ? BC.acknowledgePurchase.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    sendFeatureUnlock({
                        entitlement: "acknowledge_purchase",
                        source: `${prefix}.BillingClient`,
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    return installed;
}

export function installBillingHooks(): number {
    let installed = 0;
    installed += hookBillingClasses("com.android.billingclient.api");
    installed += hookBillingClasses("androidx.billingclient.api");
    return installed;
}
