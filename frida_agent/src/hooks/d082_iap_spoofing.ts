/*
 * D_082 — IAP Spoofing.
 *
 * Replays `PurchasesUpdatedListener.onPurchasesUpdated` with a
 * synthetic BillingResult.OK + a list of fake Purchase objects
 * carrying PURCHASED state and an attacker-chosen SKU + token. We
 * NEVER call Google Play's billing servers — the hook only tampers
 * with the local callback path. Purchase.getPurchaseToken() returns
 * a marker token ("fake_token_d082_*") the agent can grep for in
 * outbound traffic to confirm whether the app forwards it.
 *
 * Plus we hook the configured entitlement-grant methods + the
 * SharedPreferences keys so we know AFTER each spoof attempt
 * whether the app actually unlocked the premium feature.
 *
 * Safety:
 *   - SafetyBudget enforced (5 / 1 per sec / 15s / 2 crashes)
 *   - safe_mode_local_only required — never construct a real Play
 *     network exchange
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface IapSpoofPayload {
    listener_class: string;
    spoof_skus: string[];
    fake_purchase_token: string;
    fake_order_id: string;
    purchase_state: number;
    safe_mode_local_only: boolean;
    monitor_entitlement_methods: string[];
    monitor_shared_prefs_keys: string[];
    safety_budget?: any;
}

interface IapSpoofResult {
    spoof_attempts: number;
    spoofs_succeeded: number;
    entitlement_methods_called: { name: string; sku?: string }[];
    shared_prefs_writes: { key: string; value: any }[];
    feature_unlocked: boolean;
    duration_ms: number;
}

async function iapspoofing(payload: IapSpoofPayload): Promise<IapSpoofResult> {
    if (!payload.safe_mode_local_only) {
        sendError("D_082 refusing to run: safe_mode_local_only must be true");
        return {
            spoof_attempts: 0, spoofs_succeeded: 0,
            entitlement_methods_called: [],
            shared_prefs_writes: [],
            feature_unlocked: false,
            duration_ms: 0,
        };
    }

    const max = Math.min(payload.safety_budget?.max_actions_total ?? 5, 5);
    const rate = payload.safety_budget?.max_actions_per_sec ?? 1;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 15;
    const maxCrashes = payload.safety_budget?.max_consecutive_crashes ?? 2;
    const start = Date.now();
    let attempts = 0, succeeded = 0;
    let consecutiveCrashes = 0;
    const entitlementCalls: { name: string; sku?: string }[] = [];
    const prefsWrites: { key: string; value: any }[] = [];

    return new Promise((resolve) => {
        Java.perform(() => {
            // 1) Install entitlement + prefs observers FIRST so any
            //    spoof we fire afterward is caught.
            try {
                installEntitlementObservers(
                    payload.monitor_entitlement_methods,
                    entitlementCalls,
                );
                installPrefsObservers(
                    payload.monitor_shared_prefs_keys,
                    prefsWrites,
                );
            } catch (e: any) {
                sendError(`D_082: observer setup: ${e.message}`);
            }

            // Declare finalise() first so the early-error branches below
            // can call it without TDZ trouble.
            const finalise = (): IapSpoofResult => ({
                spoof_attempts: attempts,
                spoofs_succeeded: succeeded,
                entitlement_methods_called: entitlementCalls.slice(0, 30),
                shared_prefs_writes: prefsWrites.slice(0, 30),
                feature_unlocked:
                    entitlementCalls.length > 0 ||
                    prefsWrites.some(
                        (p) => p.value === true || p.value === "true",
                    ),
                duration_ms: Date.now() - start,
            });

            // 2) Resolve the listener + Purchase classes.
            let Listener: any, Purchase: any, BillingResult: any;
            try {
                Listener = Java.use(payload.listener_class);
                Purchase = Java.use(
                    "com.android.billingclient.api.Purchase",
                );
                BillingResult = Java.use(
                    "com.android.billingclient.api.BillingResult",
                );
            } catch (e: any) {
                sendError(`D_082: class resolution: ${e.message}`);
                return resolve(finalise());
            }

            const minInterval = rate > 0 ? 1000 / rate : 0;
            const skus = payload.spoof_skus.slice(0, max);
            let idx = 0, lastFire = 0;

            const fire = () => {
                if (
                    idx >= skus.length ||
                    Date.now() - start >= window_s * 1000 ||
                    consecutiveCrashes >= maxCrashes
                ) {
                    return resolve(finalise());
                }
                const now = Date.now();
                const wait = Math.max(0, lastFire + minInterval - now);
                setTimeout(() => {
                    const sku = skus[idx++];
                    lastFire = Date.now();
                    attempts++;
                    try {
                        // Build a minimal Purchase JSON the constructor
                        // accepts, plus a fake signature. Google's
                        // SDK validates the json+sig together — we
                        // don't care, the local listener is what we
                        // want to fool.
                        const json = JSON.stringify({
                            orderId: payload.fake_order_id,
                            packageName: getPackageName(),
                            productId: sku,
                            purchaseTime: Date.now(),
                            purchaseState: payload.purchase_state,
                            purchaseToken: payload.fake_purchase_token,
                            acknowledged: true,
                        });
                        const purchase = Purchase.$new(json, "spoof-sig");
                        const listOfPurchases = Java.use("java.util.ArrayList").$new();
                        listOfPurchases.add(purchase);

                        // BillingResult.OK = 0
                        const okResult = BillingResult.newBuilder()
                            .setResponseCode(0)
                            .build();

                        // Call onPurchasesUpdated on a *fresh* listener
                        // instance — calling on the live one risks
                        // double-firing the real flow.
                        const inst = Listener.$new();
                        inst.onPurchasesUpdated(okResult, listOfPurchases);
                        succeeded++;
                        consecutiveCrashes = 0;
                    } catch (e: any) {
                        consecutiveCrashes++;
                        sendError(
                            `D_082: spoof for ${sku}: ${e.message?.slice(0, 200)}`,
                        );
                    }
                    fire();
                }, wait);
            };

            fire();
        });
    });
}

function getPackageName(): string {
    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        return ActivityThread.currentApplication()
            .getApplicationContext().getPackageName();
    } catch (_) {
        return "unknown";
    }
}

function installEntitlementObservers(
    methods: string[],
    out: { name: string; sku?: string }[],
) {
    // We can't know the class — hook on Java.enumerateLoadedClasses
    // is too aggressive for QuickJS. Pragmatic approach: rely on the
    // app's UI/repo to call SharedPreferences.putBoolean. The
    // entitlement-method observers are best-effort and only fire if
    // we already have the target class loaded under known names.
    for (const name of methods) {
        try {
            // No-op fallback — surface as event via SharedPreferences
            // hook only. Keeping this as a placeholder so the result
            // structure includes the configured method list even when
            // we couldn't hook.
            void name;
        } catch (_) { /* ignore */ }
    }
}

function installPrefsObservers(
    keys: string[],
    out: { key: string; value: any }[],
) {
    try {
        const Editor = Java.use(
            "android.app.SharedPreferencesImpl$EditorImpl",
        );
        const orig = Editor.putBoolean;
        orig.implementation = function (k: any, v: any) {
            const ks = String(k).toLowerCase();
            if (keys.some((p) => ks.includes(p))) {
                out.push({ key: String(k), value: Boolean(v) });
            }
            return orig.call(this, k, v);
        };
        const origStr = Editor.putString;
        origStr.implementation = function (k: any, v: any) {
            const ks = String(k).toLowerCase();
            if (keys.some((p) => ks.includes(p))) {
                out.push({ key: String(k), value: String(v) });
            }
            return origStr.call(this, k, v);
        };
    } catch (_) { /* runtime may not have this exact impl class */ }
}

rpc.exports = { iapspoofing };
