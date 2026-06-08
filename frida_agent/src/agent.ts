/*
 * SENTINEL Frida agent entry point.
 *
 * Order of operations:
 *   1. Native hooks fire first — they don't need the Java bridge and
 *      have to be installed before the app's native code starts
 *      issuing TLS handshakes
 *   2. Wait for Java bridge availability (poll, 100ms tick, 3s ceiling)
 *   3. Install crypto + pinning hooks inside Java.perform
 *   4. Emit one tls.hooks_summary event so the Python side sees what
 *      ran, what worked, and what failed
 */
import { waitForJava } from "./lib/java_ready.js";
import { sendError } from "./lib/send.js";
import { HookResult, installCryptoHooks } from "./hooks/crypto.js";
import { installOkHttpHooks } from "./hooks/pinning_okhttp.js";
import { installSystemHooks } from "./hooks/pinning_system.js";
import { installLibraryHooks } from "./hooks/pinning_libraries.js";
import { installWebViewHooks } from "./hooks/pinning_webview.js";
import { installNativeHooks } from "./hooks/pinning_native.js";
import { installClipboardHooks } from "./hooks/clipboard.js";
import { installWindowFlagHooks } from "./hooks/window_flags.js";
import { installBiometricHooks } from "./hooks/biometric.js";
import { installAntiTamperHooks } from "./hooks/anti_tamper.js";
import { installCodeLoadingHooks } from "./hooks/code_loading.js";
import { installCryptoIvHooks } from "./hooks/crypto_iv.js";
import { installBillingHooks } from "./hooks/billing.js";
import { installWebViewRuntimeHooks } from "./hooks/webview_runtime.js";
import { installNotificationHooks } from "./hooks/notifications.js";
import { installIntentDispatchHooks } from "./hooks/intent_dispatch.js";
import { installAccessibilityHooks } from "./hooks/accessibility.js";
import { installSmsHooks } from "./hooks/sms.js";
import { installScreenCaptureHooks } from "./hooks/screen_capture.js";
import { installRegistrationHooks } from "./hooks/registrations.js";
import { installContentProviderHooks } from "./hooks/content_provider.js";
import { installFileProviderHooks } from "./hooks/file_provider.js";
import { installLocationHooks } from "./hooks/location.js";
import { installKeystoreHooks } from "./hooks/keystore.js";
import { installZipHooks } from "./hooks/zip.js";
import { installRandomHooks } from "./hooks/random.js";
import { installHostnameVerifierHooks } from "./hooks/hostname_verifier.js";
import { installApkInstallHooks } from "./hooks/apk_install.js";
import { installJsonDeserializeHooks } from "./hooks/json_deserialize.js";
import { installSqliteHooks } from "./hooks/sqlite.js";
import { installReflectionInvokeHooks } from "./hooks/reflection_invoke.js";
import { emitHooksSummary } from "./hooks/diagnostics.js";

// Native hooks first — independent of Java bridge readiness.
let nativeHooks = 0;
try {
    nativeHooks = installNativeHooks();
} catch (e) {
    sendError(`native setup: ${String(e)}`);
}

waitForJava("sentinel-agent", () => {
    const result: HookResult = { attempted: [], succeeded: [], failed: [] };
    let subclassesHooked = 0;

    try { installCryptoHooks(result); }
    catch (e) { sendError(`crypto: ${String(e)}`); }

    try { installOkHttpHooks(result); }
    catch (e) { sendError(`okhttp: ${String(e)}`); }

    try { installSystemHooks(result); }
    catch (e) { sendError(`system: ${String(e)}`); }

    try { installLibraryHooks(result); }
    catch (e) { sendError(`libraries: ${String(e)}`); }

    try {
        const wv = installWebViewHooks();
        subclassesHooked = wv.subclassesHooked;
        result.attempted.push(wv.libraryLabel);
        result.succeeded.push(wv.libraryLabel);
    } catch (e) {
        sendError(`webview: ${String(e)}`);
    }

    try { installClipboardHooks(); }
    catch (e) { sendError(`clipboard: ${String(e)}`); }

    try { installWindowFlagHooks(); }
    catch (e) { sendError(`window_flags: ${String(e)}`); }

    try { installBiometricHooks(); }
    catch (e) { sendError(`biometric: ${String(e)}`); }

    try { installAntiTamperHooks(); }
    catch (e) { sendError(`anti_tamper: ${String(e)}`); }

    try { installCodeLoadingHooks(); }
    catch (e) { sendError(`code_loading: ${String(e)}`); }

    try { installCryptoIvHooks(); }
    catch (e) { sendError(`crypto_iv: ${String(e)}`); }

    try { installBillingHooks(); }
    catch (e) { sendError(`billing: ${String(e)}`); }

    try { installWebViewRuntimeHooks(); }
    catch (e) { sendError(`webview_runtime: ${String(e)}`); }

    try { installNotificationHooks(); }
    catch (e) { sendError(`notifications: ${String(e)}`); }

    try { installIntentDispatchHooks(); }
    catch (e) { sendError(`intent_dispatch: ${String(e)}`); }

    try { installAccessibilityHooks(); }
    catch (e) { sendError(`accessibility: ${String(e)}`); }

    try { installSmsHooks(); }
    catch (e) { sendError(`sms: ${String(e)}`); }

    try { installScreenCaptureHooks(); }
    catch (e) { sendError(`screen_capture: ${String(e)}`); }

    try { installRegistrationHooks(); }
    catch (e) { sendError(`registrations: ${String(e)}`); }

    try { installContentProviderHooks(); }
    catch (e) { sendError(`content_provider: ${String(e)}`); }

    try { installFileProviderHooks(); }
    catch (e) { sendError(`file_provider: ${String(e)}`); }

    try { installLocationHooks(); }
    catch (e) { sendError(`location: ${String(e)}`); }

    try { installKeystoreHooks(); }
    catch (e) { sendError(`keystore: ${String(e)}`); }

    try { installZipHooks(); }
    catch (e) { sendError(`zip: ${String(e)}`); }

    try { installRandomHooks(); }
    catch (e) { sendError(`random: ${String(e)}`); }

    try { installHostnameVerifierHooks(); }
    catch (e) { sendError(`hostname_verifier: ${String(e)}`); }

    try { installApkInstallHooks(); }
    catch (e) { sendError(`apk_install: ${String(e)}`); }

    try { installJsonDeserializeHooks(); }
    catch (e) { sendError(`json_deserialize: ${String(e)}`); }

    try { installSqliteHooks(); }
    catch (e) { sendError(`sqlite: ${String(e)}`); }

    try { installReflectionInvokeHooks(); }
    catch (e) { sendError(`reflection_invoke: ${String(e)}`); }

    try { emitHooksSummary(result, subclassesHooked, nativeHooks); }
    catch (e) { sendError(`summary: ${String(e)}`); }
});
