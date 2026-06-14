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
import { installActivityResultHooks } from "./hooks/activity_result.js";
import { installLogLeakHooks } from "./hooks/log_leak.js";
import { installClipboardReadHooks } from "./hooks/clipboard_read.js";
import { installTrustManagerHooks } from "./hooks/trust_manager.js";
import { installOkhttpLoggingHooks } from "./hooks/okhttp_logging.js";
import { installBiometricPromptHooks } from "./hooks/biometric_prompt.js";
import { emitHooksSummary } from "./hooks/diagnostics.js";
import "./hooks/biometric_unwrapper.js";
import "./hooks/pending_intent_esc.js";
import "./hooks/scheme_confuser.js";

// God-Mode + Experimental tier hooks (D_042-D_072).
// These register rpc.exports entries the Python orchestrator invokes
// on-demand at Phase 4.5 — they do not install Java.perform listeners
// at agent load time. Safe to import unconditionally.
import "./hooks/d042_deep_link_bomb.js";
import "./hooks/d043_hidden_api_hunter.js";
import "./hooks/d044_biometric_replay.js";
import "./hooks/d045_sqlite_prober.js";
import "./hooks/d046_race_trigger.js";
import "./hooks/d047_memory_dump.js";
import "./hooks/d048_webview_xss.js";
import "./hooks/d049_notification_snoop.js";
import "./hooks/d050_pinning_stress_test.js";
import "./hooks/d051_service_leaker.js";
import "./hooks/d052_symbolic_intent.js";
import "./hooks/d053_side_channel.js";
import "./hooks/d054_graphql_fuzzer.js";
import "./hooks/d055_native_heap.js";
import "./hooks/d056_biometric_timing.js";
import "./hooks/d057_state_poisoner.js";
import "./hooks/d058_websocket_injector.js";
import "./hooks/d059_clipboard_hijack.js";
import "./hooks/d060_sensor_spoofing.js";
import "./hooks/d061_key_extractor.js";
import "./hooks/d062_binder_bomb.js";
import "./hooks/d063_provider_sqli.js";
import "./hooks/d064_job_hijacker.js";
import "./hooks/d065_file_provider_fuzzer.js";
import "./hooks/d066_a11y_abuser.js";
import "./hooks/d067_split_apk.js";
import "./hooks/d068_wearable_bridge.js";
import "./hooks/d070_pip_spy.js";
import "./hooks/d071_twa_breaker.js";
import "./hooks/d072_jni_shadow.js";

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

    try { installActivityResultHooks(); }
    catch (e) { sendError(`activity_result: ${String(e)}`); }

    try { installLogLeakHooks(); }
    catch (e) { sendError(`log_leak: ${String(e)}`); }

    try { installClipboardReadHooks(); }
    catch (e) { sendError(`clipboard_read: ${String(e)}`); }

    try { installTrustManagerHooks(); }
    catch (e) { sendError(`trust_manager: ${String(e)}`); }

    try { installOkhttpLoggingHooks(); }
    catch (e) { sendError(`okhttp_logging: ${String(e)}`); }

    try { installBiometricPromptHooks(); }
    catch (e) { sendError(`biometric_prompt: ${String(e)}`); }

    try { emitHooksSummary(result, subclassesHooked, nativeHooks); }
    catch (e) { sendError(`summary: ${String(e)}`); }
});
