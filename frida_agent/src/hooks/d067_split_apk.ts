/*
 * D_067 — SplitInstallManager hijack probe.
 *
 * Cannot deliver a literal malicious split APK from a Frida hook
 * (would need a self-signed split signed with the app's key). What
 * we CAN do: hook startInstall, observe the install verification
 * sequence, and report whether any code path skips PackageManager
 * signature comparison entirely. Reports the verification call
 * shape the app actually performs.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SplitPayload {
    simulate_malicious_split?: boolean;
    safety_budget?: any;
}
interface SplitResult {
    start_install_calls: number;
    signature_checks_observed: number;
    duration_ms: number;
}

async function splitapkfuzzer(payload: SplitPayload): Promise<SplitResult> {
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 60;
    let installs = 0, sigChecks = 0;
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const SIM = Java.use(
                    "com.google.android.play.core.splitinstall.SplitInstallManager",
                );
                SIM.startInstall.implementation = function (req: any) {
                    installs++;
                    return this.startInstall(req);
                };
            } catch (_) { /* class may not exist */ }
            try {
                const PM = Java.use("android.content.pm.PackageManager");
                PM.checkSignatures.overload(
                    "java.lang.String", "java.lang.String",
                ).implementation = function (a: any, b: any) {
                    sigChecks++;
                    return this.checkSignatures(a, b);
                };
            } catch (e: any) {
                sendError(`D_067: ${e.message}`);
            }
            setTimeout(() => resolve({
                start_install_calls: installs,
                signature_checks_observed: sigChecks,
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { splitapkfuzzer };
