/*
 * OkHttp pinning hooks.
 *
 * Ported from the legacy CERT_PINNING_BYPASS_HOOK constant in
 * frida_runner.py (CertificatePinner.check + check$okhttp + the
 * OkHostnameVerifier path). New additions in this file:
 *   - okhttp3.OkHttpClient$Builder.certificatePinner — observes
 *     setup-time pinning configuration before any request fires
 *   - okhttp3.OkHostnameVerifier emits a distinct library label
 *     ("okhttp.OkHostnameVerifier") so the diagnostics summary
 *     attributes it to OkHttp and not the generic catch-all
 *   - Interceptor.intercept chain instrumentation — detects custom
 *     pinning logic that apps build via OkHttp interceptors
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

export function installOkHttpHooks(result: HookResult): void {
    tryHook(result, "okhttp.CertificatePinner", () => {
        const Pinner = Java.use("okhttp3.CertificatePinner");

        Pinner.check.overload(
            "java.lang.String", "java.util.List",
        ).implementation = function (this: any, hostname: string, _certs: unknown) {
            sendBypass({
                library: "okhttp.CertificatePinner",
                method: "check(String, List)",
                host: hostname,
            });
        };

        try {
            Pinner["check$okhttp"].overload(
                "java.lang.String", "kotlin.jvm.functions.Function0",
            ).implementation = function (
                this: any, hostname: string, _fn: unknown,
            ) {
                sendBypass({
                    library: "okhttp.CertificatePinner",
                    method: "check$okhttp",
                    host: hostname,
                });
            };
        } catch {
            // older OkHttp without the Kotlin extension overload
        }
    });

    tryHook(result, "okhttp.OkHttpClient$Builder.certificatePinner", () => {
        const Builder = Java.use("okhttp3.OkHttpClient$Builder");
        Builder.certificatePinner.overload(
            "okhttp3.CertificatePinner",
        ).implementation = function (this: any, pinner: any) {
            sendBypass({
                library: "okhttp.OkHttpClient$Builder",
                method: "certificatePinner",
                extra: { configured: pinner !== null },
            });
            return this.certificatePinner(pinner);
        };
    });

    tryHook(result, "okhttp.OkHostnameVerifier", () => {
        const OKHV = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OKHV.verify.overload(
            "java.lang.String", "javax.net.ssl.SSLSession",
        ).implementation = function (
            this: any, hostname: string, _session: unknown,
        ) {
            sendBypass({
                library: "okhttp.OkHostnameVerifier",
                method: "OkHostnameVerifier.verify",
                host: hostname,
            });
            return true;
        };
    });

    tryHook(result, "okhttp.Interceptor", () => {
        // Hook the Interceptor interface itself — every concrete
        // implementation (including app-built custom pinning ones)
        // gets observed when its intercept() runs.
        const Interceptor = Java.use("okhttp3.Interceptor");
        const Chain = Java.use("okhttp3.Interceptor$Chain");
        Interceptor.intercept.overload(
            "okhttp3.Interceptor$Chain",
        ).implementation = function (this: any, chain: any) {
            try {
                const req = chain.request();
                const url = req ? String(req.url().host()) : "";
                sendBypass({
                    library: "okhttp.Interceptor",
                    method: "intercept",
                    host: url,
                    extra: { implementor: this.$className },
                });
            } catch {
                // chain may be in an unusual state — observation only
            }
            return this.intercept(chain);
        };
        // Reference Chain to ensure the symbol resolves on this device.
        void Chain;
    });
}
