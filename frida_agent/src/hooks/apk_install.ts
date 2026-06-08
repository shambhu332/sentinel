/*
 * In-app APK install observation (D_030).
 *
 * Hooks:
 *   - android.content.pm.PackageInstaller$Session.openWrite
 *       -> snapshot the most-recent URL.openConnection scheme that
 *          fed bytes into the session. The download flow is
 *          typically URL.openStream / HttpURLConnection.connect ->
 *          read -> OutputStream.write into the session's output.
 *          We capture the scheme of any URL opened in the same
 *          process and treat the most recent one as the source.
 *   - android.content.pm.PackageInstaller$Session.commit
 *       -> emit apk_install.committed with the source scheme and a
 *          flag indicating whether a signature-comparing API was
 *          observed between openWrite and commit.
 *   - java.net.URL.openConnection (track most-recent scheme).
 *   - android.content.pm.PackageManager.getPackageArchiveInfo
 *       -> when called between openWrite and commit, set
 *          signature_verified=true.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendApkInstallCommitted, sendError } from "../lib/send.js";

let lastUrlScheme: string = "";
let lastUrl: string = "";
let inExtractWindow: boolean = false;
let signatureSeen: boolean = false;
let signatureClassSeen: string = "";

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 5; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

export function installApkInstallHooks(): number {
    let installed = 0;

    // ---- URL.openConnection — track scheme ----
    try {
        const URL = Java.use("java.net.URL");
        const ov = URL.openConnection.overload();
        ov.implementation = function () {
            try {
                lastUrl = String(this.toExternalForm());
                lastUrlScheme = String(this.getProtocol() || "").toLowerCase();
            } catch (_) { /* swallow */ }
            return ov.call(this);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- PackageInstaller$Session.openWrite ----
    try {
        const Session = Java.use(
            "android.content.pm.PackageInstaller$Session",
        );
        const ovWrite = Session.openWrite ? Session.openWrite.overloads : [];
        for (let i = 0; i < ovWrite.length; i++) {
            const ov = ovWrite[i];
            ov.implementation = function (...args: any[]) {
                inExtractWindow = true;
                signatureSeen = false;
                signatureClassSeen = "";
                return ov.apply(this, args);
            };
            installed++;
        }

        // ---- PackageInstaller$Session.commit ----
        const ovCommit = Session.commit ? Session.commit.overloads : [];
        for (let i = 0; i < ovCommit.length; i++) {
            const ov = ovCommit[i];
            ov.implementation = function (...args: any[]) {
                try {
                    let sessionId = -1;
                    try { sessionId = Number(this.getSessionId()); }
                    catch (_) { /* swallow */ }
                    sendApkInstallCommitted({
                        session_id: sessionId,
                        source_scheme: lastUrlScheme,
                        source_url: lastUrl,
                        signature_verified: signatureSeen,
                        signature_class_seen: signatureClassSeen,
                        stack: shortStack(),
                    });
                } catch (e) {
                    sendError(`apk_install.commit: ${String(e)}`);
                }
                inExtractWindow = false;
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- PackageManager.getPackageArchiveInfo — signature gate ----
    try {
        const PM = Java.use("android.content.pm.PackageManager");
        const ov = PM.getPackageArchiveInfo
            ? PM.getPackageArchiveInfo.overloads : [];
        for (let i = 0; i < ov.length; i++) {
            const o = ov[i];
            o.implementation = function (...args: any[]) {
                if (inExtractWindow) {
                    signatureSeen = true;
                    signatureClassSeen = "PackageManager.getPackageArchiveInfo";
                }
                return o.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- Signature.equals — second signal ----
    try {
        const Sig = Java.use("android.content.pm.Signature");
        Sig.equals.implementation = function (other: any) {
            if (inExtractWindow) {
                signatureSeen = true;
                signatureClassSeen = "Signature.equals";
            }
            return this.equals(other);
        };
        installed++;
    } catch (_) { /* skip */ }

    return installed;
}
