/*
 * Custom HostnameVerifier bypass observation (D_029).
 *
 * Strategy: hook every concrete implementation of
 * javax.net.ssl.HostnameVerifier loaded into the app. For each call
 * we run the *platform default* verifier (HttpsURLConnection
 * .getDefaultHostnameVerifier()) against the same hostname + session
 * in parallel and compare results. An accepted=true /
 * default_would_accept=false asymmetry is the TLS bypass.
 *
 * We don't enumerate classloaders by hand — instead we lazy-hook via
 * Java.enumerateClassLoaders + Java.choose. The result count gives
 * the agent's diagnostic summary something useful to report.
 *
 * Pure observer (the original verify call's verdict is returned
 * untouched).
 */
import { Java } from "../lib/java_ready.js";
import {
    sendHostnameVerifierInvoked,
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

let defaultVerifier: any = null;

function defaultWouldAccept(host: string, session: any): boolean {
    try {
        if (!defaultVerifier) {
            const HttpsURLConnection = Java.use(
                "javax.net.ssl.HttpsURLConnection",
            );
            defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        }
        if (!defaultVerifier) return false;
        return Boolean(defaultVerifier.verify(host, session));
    } catch (_) { return false; }
}

function instrumentClass(cls: string): boolean {
    try {
        const Klass: any = Java.use(cls);
        if (!Klass.verify) return false;

        const ov = Klass.verify.overload(
            "java.lang.String", "javax.net.ssl.SSLSession",
        );
        ov.implementation = function (host: any, session: any) {
            const accepted = ov.call(this, host, session);
            try {
                const hostStr = host ? String(host) : "";
                const defaultOk = defaultWouldAccept(hostStr, session);
                sendHostnameVerifierInvoked({
                    verifier_class: cls,
                    hostname: hostStr,
                    accepted: Boolean(accepted),
                    default_would_accept: defaultOk,
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`hv.emit: ${String(e)}`);
            }
            return accepted;
        };
        return true;
    } catch (_) { return false; }
}

export function installHostnameVerifierHooks(): number {
    let installed = 0;
    try {
        // Enumerate every Java class loaded so far and instrument the
        // ones that look like a HostnameVerifier / TrustManager.
        (Java as any).enumerateLoadedClasses({
            onMatch(name: string) {
                const probe = name.toLowerCase();
                if (probe.indexOf("hostname") === -1
                    && probe.indexOf("verifier") === -1
                    && probe.indexOf("trust") === -1) {
                    return;
                }
                if (instrumentClass(name)) installed++;
            },
            onComplete() { /* noop */ },
        });
    } catch (_) { /* skip */ }
    return installed;
}
