/*
 * X509TrustManager bypass observation (D_038).
 *
 * Strategy: enumerate every loaded class whose name contains
 * "TrustManager" / "Trust" and instrument its checkServerTrusted
 * (X509Certificate[], String). In parallel we run the platform
 * default X509TrustManager — obtained once via TrustManagerFactory
 * .init(null) — against the same chain + authType. The asymmetry
 * accepted=true / default_would_accept=false is the bypass.
 *
 * Pure observer — the original verdict is returned untouched.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendTrustManagerInvoked,
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

let defaultTrustManager: any = null;

function getDefaultTrustManager(): any {
    if (defaultTrustManager) return defaultTrustManager;
    try {
        const TmfCls = Java.use("javax.net.ssl.TrustManagerFactory");
        const tmf = TmfCls.getInstance(TmfCls.getDefaultAlgorithm());
        tmf.init(null);
        const tms = tmf.getTrustManagers();
        for (let i = 0; i < tms.length; i++) {
            const cls = String(tms[i].getClass().getName());
            if (cls.indexOf("X509") !== -1
                || cls.toLowerCase().indexOf("trust") !== -1) {
                defaultTrustManager = tms[i];
                return defaultTrustManager;
            }
        }
        if (tms.length > 0) defaultTrustManager = tms[0];
        return defaultTrustManager;
    } catch (_) { return null; }
}

function chainSubject(chain: any): string {
    try {
        if (!chain || chain.length === 0) return "";
        return String(chain[0].getSubjectDN().getName());
    } catch (_) { return ""; }
}

function defaultAccepts(chain: any, authType: string): boolean {
    const tm = getDefaultTrustManager();
    if (!tm) return false;
    try {
        tm.checkServerTrusted(chain, authType);
        return true;
    } catch (_) { return false; }
}

function instrumentClass(cls: string): boolean {
    try {
        const Klass: any = Java.use(cls);
        if (!Klass.checkServerTrusted) return false;
        const ov = Klass.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;",
            "java.lang.String",
        );
        ov.implementation = function (chain: any, authType: any) {
            let accepted = true;
            try { ov.call(this, chain, authType); }
            catch (e) { accepted = false; throw e; }
            finally {
                try {
                    const authStr = String(authType || "");
                    const defaultOk = defaultAccepts(chain, authStr);
                    sendTrustManagerInvoked({
                        tm_class: cls,
                        chain_subject: chainSubject(chain),
                        auth_type: authStr,
                        accepted,
                        default_would_accept: defaultOk,
                        stack: shortStack(),
                    });
                } catch (e2) {
                    sendError(`trust_manager.emit: ${String(e2)}`);
                }
            }
        };
        return true;
    } catch (_) { return false; }
}

export function installTrustManagerHooks(): number {
    let installed = 0;
    try {
        (Java as any).enumerateLoadedClasses({
            onMatch(name: string) {
                const probe = name.toLowerCase();
                if (probe.indexOf("trustmanager") === -1
                    && probe.indexOf("x509") === -1) {
                    return;
                }
                if (instrumentClass(name)) installed++;
            },
            onComplete() { /* noop */ },
        });
    } catch (_) { /* skip */ }
    return installed;
}
