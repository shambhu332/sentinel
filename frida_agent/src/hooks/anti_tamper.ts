/*
 * Anti-tamper observation hooks (D_004).
 *
 * Watches the four classic detection APIs. We do NOT alter return
 * values — this is a pure observer. The Python AntiTamperCoverageAgent
 * classifies what categories the app exercises.
 *
 *  - root:      File.exists / Runtime.exec / ProcessBuilder
 *  - emulator:  Build.* static getters
 *  - integrity: PackageManager.getPackageInfo (signatures requested)
 *  - debugger:  android.os.Debug.isDebuggerConnected
 */
import { Java } from "../lib/java_ready.js";
import { sendTamperCheck, sendError } from "../lib/send.js";

const ROOT_PATH_TOKENS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "magisk", "supersu", "busybox",
];

function looksRootPath(p: string): boolean {
    const lower = p.toLowerCase();
    for (const tok of ROOT_PATH_TOKENS) {
        if (lower.indexOf(tok) !== -1) return true;
    }
    return false;
}

const PKG_INFO_GET_SIGNATURES = 0x40;
const PKG_INFO_GET_SIGNING_CERTIFICATES = 0x08000000;

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

export function installAntiTamperHooks(): number {
    let installed = 0;

    // ---- root: File.exists on suspicious paths ----
    try {
        const JFile = Java.use("java.io.File");
        JFile.exists.implementation = function () {
            const result = this.exists();
            try {
                const p = String(this.getAbsolutePath());
                if (looksRootPath(p)) {
                    sendTamperCheck("root_check", {
                        api: "File.exists",
                        value: p,
                        result: !!result,
                        stack: shortStack(),
                    });
                }
            } catch (e) { sendError(`tamper.file.exists: ${String(e)}`); }
            return result;
        };
        installed++;
    } catch (e) {
        sendError(`tamper.file install: ${String(e)}`);
    }

    // ---- root: Runtime.exec(String) ----
    try {
        const Runtime = Java.use("java.lang.Runtime");
        const overload = Runtime.exec.overload("java.lang.String");
        overload.implementation = function (cmd: string) {
            try {
                if (cmd && looksRootPath(String(cmd))) {
                    sendTamperCheck("root_check", {
                        api: "Runtime.exec",
                        value: String(cmd),
                        stack: shortStack(),
                    });
                }
            } catch (e) { sendError(`tamper.runtime.exec: ${String(e)}`); }
            return overload.call(this, cmd);
        };
        installed++;
    } catch (_) { /* overload may differ on some ROMs */ }

    // ---- emulator: Build static field reads ----
    try {
        const Build = Java.use("android.os.Build");
        // Reading static fields doesn't trigger interceptable methods,
        // but a typical app constructs them via .toString() on
        // getRadioVersion / getSerial — and most importantly checks
        // FINGERPRINT for "generic"/"sdk_gphone". We hook getRadioVersion
        // and a couple of cheap getter methods, then *also* watch the
        // hardware-feature query routinely used as an emulator tell.
        try {
            Build.getRadioVersion.implementation = function () {
                const out = this.getRadioVersion();
                sendTamperCheck("emulator_check", {
                    api: "Build.getRadioVersion",
                    value: String(out),
                    stack: shortStack(),
                });
                return out;
            };
            installed++;
        } catch (_) { /* may not exist on every API */ }
    } catch (_) { /* skip if Build absent */ }

    // ---- emulator: SystemProperties.get for ro.kernel.qemu etc. ----
    try {
        const SP = Java.use("android.os.SystemProperties");
        SP.get.overload("java.lang.String").implementation = function (k: string) {
            const out = SP.get.overload("java.lang.String").call(this, k);
            try {
                const key = String(k || "");
                if (key.indexOf("qemu") !== -1
                    || key.indexOf("kernel") !== -1
                    || key.indexOf("ro.product") !== -1) {
                    sendTamperCheck("emulator_check", {
                        api: "SystemProperties.get",
                        value: key,
                        result: String(out),
                        stack: shortStack(),
                    });
                }
            } catch (_) { /* swallow */ }
            return out;
        };
        installed++;
    } catch (_) { /* hidden API on some ROMs */ }

    // ---- integrity: PackageManager.getPackageInfo(name, flags) ----
    try {
        const PM = Java.use("android.content.pm.PackageManager");
        const o = PM.getPackageInfo.overload(
            "java.lang.String", "int",
        );
        o.implementation = function (name: string, flags: number) {
            const out = o.call(this, name, flags);
            try {
                if ((flags & PKG_INFO_GET_SIGNATURES)
                    || (flags & PKG_INFO_GET_SIGNING_CERTIFICATES)) {
                    sendTamperCheck("integrity_check", {
                        api: "PackageManager.getPackageInfo",
                        value: String(name),
                        result: `flags=0x${(flags >>> 0).toString(16)}`,
                        stack: shortStack(),
                    });
                }
            } catch (e) {
                sendError(`tamper.pminfo: ${String(e)}`);
            }
            return out;
        };
        installed++;
    } catch (_) { /* overload may differ */ }

    // ---- debugger: Debug.isDebuggerConnected ----
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            const out = this.isDebuggerConnected();
            try {
                sendTamperCheck("debugger_check", {
                    api: "Debug.isDebuggerConnected",
                    result: !!out,
                    stack: shortStack(),
                });
            } catch (_) { /* swallow */ }
            return out;
        };
        installed++;
    } catch (_) { /* skip if absent */ }

    return installed;
}
