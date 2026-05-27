/*
 * System/platform pinning hooks.
 *
 * Ported from the legacy CERT_PINNING_BYPASS_HOOK constant
 * (X509TrustManagerExtensions, Conscrypt.Platform). New additions:
 *   - javax.net.ssl.X509TrustManager.checkServerTrusted — the base
 *     interface every TLS stack ultimately reaches; bypassed via
 *     Java.choose so each concrete implementation gets instrumented
 *   - java.security.cert.CertPathValidator.validate — last-resort
 *     cert chain validation hook for stacks that build their own
 *     trust chain instead of going through a TrustManager
 */
import { Java } from "../lib/java_ready.js";
import { sendBypass, sendBypassFailed } from "../lib/send.js";
import { HookResult } from "./crypto.js";

function tryHook(result: HookResult, label: string, fn: () => void): void {
    result.attempted.push(label);
    try {
        fn();
        result.succeeded.push(label);
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") !== -1) {
            return;
        }
        result.failed.push({ library: label, reason: msg });
        sendBypassFailed(label, msg);
    }
}

export function installSystemHooks(result: HookResult): void {
    tryHook(result, "X509TrustManagerExtensions", () => {
        const TMExt = Java.use("android.net.http.X509TrustManagerExtensions");
        TMExt.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;",
            "java.lang.String",
            "java.lang.String",
        ).implementation = function (
            this: any, _chain: unknown, _authType: string, host: string,
        ) {
            sendBypass({
                library: "X509TrustManagerExtensions",
                method: "checkServerTrusted",
                host,
            });
            return Java.use("java.util.Collections").emptyList();
        };
    });

    tryHook(result, "Conscrypt.Platform", () => {
        const Plat = Java.use("org.conscrypt.Platform");
        Plat.checkServerTrusted.overload(
            "javax.net.ssl.X509TrustManager",
            "[Ljava.security.cert.X509Certificate;",
            "java.lang.String",
            "javax.net.ssl.SSLSession",
        ).implementation = function (
            this: any, _tm: unknown, _chain: unknown,
            _authType: string, _session: unknown,
        ) {
            sendBypass({
                library: "Conscrypt.Platform",
                method: "checkServerTrusted",
                host: "",
            });
        };
    });

    tryHook(result, "X509TrustManager", () => {
        // The base interface — every concrete TrustManager implements
        // checkServerTrusted. Enumerate currently-loaded implementations
        // via Java.choose so app-specific or vendor-provided managers
        // are instrumented too, not just the AOSP defaults.
        const baseName = "javax.net.ssl.X509TrustManager";
        const hooked = new Set<string>();

        Java.choose(baseName, {
            onMatch(instance: any) {
                try {
                    const className = instance.$className as string;
                    if (hooked.has(className)) return;
                    hooked.add(className);
                    const cls = Java.use(className);
                    if (typeof cls.checkServerTrusted === "undefined") return;
                    cls.checkServerTrusted.overloads.forEach((overload: any) => {
                        try {
                            overload.implementation = function (
                                this: any, ..._args: unknown[]
                            ) {
                                sendBypass({
                                    library: `X509TrustManager:${className}`,
                                    method: "checkServerTrusted",
                                });
                            };
                        } catch {
                            // overload not instrumentable
                        }
                    });
                } catch {
                    // skip impls we can't use
                }
            },
            onComplete() { /* no-op */ },
        });
    });

    tryHook(result, "CertPathValidator", () => {
        const CPV = Java.use("java.security.cert.CertPathValidator");
        CPV.validate.overload(
            "java.security.cert.CertPath",
            "java.security.cert.CertPathParameters",
        ).implementation = function (
            this: any, path: any, params: any,
        ) {
            sendBypass({
                library: "CertPathValidator",
                method: "validate",
            });
            return this.validate(path, params);
        };
    });
}
