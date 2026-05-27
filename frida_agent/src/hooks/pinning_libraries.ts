/*
 * Misc third-party pinning / TLS library hooks.
 *
 * Each block follows the same pattern: try to Java.use the class
 * and replace its check/verify method with a no-op (or an observation
 * tap, where bypassing would crash the app). A ClassNotFoundException
 * means the library isn't bundled in this APK and we silently skip;
 * any other throw is a real setup failure and is surfaced via
 * tls.bypass_failed.
 *
 * Libraries covered:
 *   - TrustKit (DataTheorem)
 *   - Volley (com.android.volley.toolbox.HurlStack)
 *   - Cronet (org.chromium.net.CronetEngine$Builder)
 *   - Apache HttpClient (org.apache.http.conn.ssl.AbstractVerifier)
 *   - Network Security Config bypass (system component)
 *   - Square Picasso (uses OkHttp under the hood)
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

export function installLibraryHooks(result: HookResult): void {
    tryHook(result, "TrustKit", () => {
        const TK = Java.use(
            "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
        );
        TK.verify.overload(
            "java.lang.String", "javax.net.ssl.SSLSession",
        ).implementation = function (
            this: any, hostname: string, _session: unknown,
        ) {
            sendBypass({
                library: "TrustKit",
                method: "OkHostnameVerifier.verify",
                host: hostname,
            });
            return true;
        };
    });

    tryHook(result, "Volley.HurlStack", () => {
        // Volley's HurlStack#openConnection is where SSLSocketFactory
        // is applied; observing the constructor + setSslSocketFactory
        // is enough to flag pinning configuration.
        const HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
        if (typeof HurlStack.setSslSocketFactory !== "undefined") {
            HurlStack.setSslSocketFactory.implementation = function (
                this: any, factory: any,
            ) {
                sendBypass({
                    library: "Volley.HurlStack",
                    method: "setSslSocketFactory",
                    extra: { configured: factory !== null },
                });
                return this.setSslSocketFactory(factory);
            };
        }
    });

    tryHook(result, "Cronet.Builder", () => {
        const Builder = Java.use("org.chromium.net.CronetEngine$Builder");
        Builder.build.overload().implementation = function (this: any) {
            sendBypass({
                library: "Cronet.Builder",
                method: "build",
            });
            return this.build();
        };
        // Cronet's public pinning API:
        if (typeof Builder.addPublicKeyPins !== "undefined") {
            Builder.addPublicKeyPins.overloads.forEach((overload: any) => {
                try {
                    overload.implementation = function (
                        this: any, ...args: unknown[]
                    ) {
                        sendBypass({
                            library: "Cronet.Builder",
                            method: "addPublicKeyPins",
                            host: String(args[0] || ""),
                        });
                        // Returning `this` after a no-op would bypass
                        // the pin entirely; we observe but still apply.
                        return overload.apply(this, args as any[]);
                    };
                } catch {
                    // overload mismatch on this Cronet build
                }
            });
        }
    });

    tryHook(result, "Apache.AbstractVerifier", () => {
        const AV = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AV.verify.overload(
            "java.lang.String", "javax.net.ssl.SSLSession",
        ).implementation = function (
            this: any, hostname: string, _session: unknown,
        ) {
            sendBypass({
                library: "Apache.AbstractVerifier",
                method: "verify",
                host: hostname,
            });
        };
    });

    tryHook(result, "NetworkSecurityConfig", () => {
        // Network Security Config (NSC) controls trust anchors at the
        // platform level. The Builder is an internal API but observing
        // setTrustAnchors() flags apps that programmatically replace
        // the trust store at runtime.
        const NSC = Java.use(
            "android.security.net.config.NetworkSecurityConfig$Builder",
        );
        if (typeof NSC.addCertificatesEntryRef !== "undefined") {
            NSC.addCertificatesEntryRef.overloads.forEach((overload: any) => {
                try {
                    overload.implementation = function (
                        this: any, ...args: unknown[]
                    ) {
                        sendBypass({
                            library: "NetworkSecurityConfig",
                            method: "addCertificatesEntryRef",
                        });
                        return overload.apply(this, args as any[]);
                    };
                } catch {
                    // overload mismatch
                }
            });
        }
    });

    tryHook(result, "Picasso.OkHttp3Downloader", () => {
        // Square Picasso just delegates to OkHttp; observe the
        // constructor so we know the app routes image loads through it.
        const Downloader = Java.use("com.squareup.picasso.OkHttp3Downloader");
        const ctors = Downloader.$init.overloads;
        ctors.forEach((overload: any) => {
            try {
                overload.implementation = function (
                    this: any, ...args: unknown[]
                ) {
                    sendBypass({
                        library: "Picasso.OkHttp3Downloader",
                        method: "$init",
                    });
                    return overload.apply(this, args as any[]);
                };
            } catch {
                // overload mismatch
            }
        });
    });
}
