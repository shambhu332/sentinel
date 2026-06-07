/*
 * Typed wrappers around Frida's global `send()`. Every event passes
 * through one of these helpers so the Python side gets a consistent
 * payload shape. Each helper enforces a discriminated 'kind' field
 * and structured payload, making the orchestrator's event parsing
 * resilient to refactors here.
 */

export function sendCipher(algorithm: string, provider?: string, overload?: string): void {
    send({ kind: "crypto.cipher", algorithm, provider, overload });
}

export function sendDigest(algorithm: string): void {
    send({ kind: "crypto.digest", algorithm });
}

export function sendKeygen(algorithm: string): void {
    send({ kind: "crypto.keygen", algorithm });
}

export function sendMac(algorithm: string): void {
    send({ kind: "crypto.mac", algorithm });
}

export function sendSecureRandom(variant: string): void {
    send({ kind: "crypto.secure_random", variant });
}

export function sendSecretKeyFactory(algorithm: string): void {
    send({ kind: "crypto.secret_key_factory", algorithm });
}

export function sendKeyPairGenerator(algorithm: string): void {
    send({ kind: "crypto.keypair_generator", algorithm });
}

export function sendCryptoHooksInstalled(count: number, fallback?: boolean): void {
    send({ kind: "crypto.hooks_installed", count, fallback });
}

export interface BypassEvent {
    library: string;
    method: string;
    host?: string;
    extra?: Record<string, unknown>;
}

export function sendBypass(e: BypassEvent): void {
    send({ kind: "tls.bypass", ...e });
}

export function sendBypassFailed(library: string, error: string): void {
    send({ kind: "tls.bypass_failed", library, error });
}

export function sendHooksSummary(summary: {
    attempted: string[];
    succeeded: string[];
    failed: { library: string; reason: string }[];
    subclass_hooks_added: number;
    native_hooks_added: number;
}): void {
    send({ kind: "tls.hooks_summary", ...summary });
}

export function sendError(message: string): void {
    send({ kind: "error", message });
}

/* ------- Sprint 8.3: clipboard / window-flags / biometric ------- */

export function sendClipboardWrite(p: {
    label?: string;
    text?: string;
    mime_types?: string[];
    stack?: string;
}): void {
    send({ kind: "clipboard.write", ...p });
}

export function sendClipboardRead(p: {
    mime_types?: string[];
    stack?: string;
}): void {
    send({ kind: "clipboard.read", ...p });
}

export function sendSensitiveInputSeen(p: {
    activity: string;
    field: string;
}): void {
    send({ kind: "ui.sensitive_input_seen", ...p });
}

export function sendWindowFlags(p: {
    activity: string;
    flags: number;
    secure: boolean;
}): void {
    send({ kind: "ui.window_flags", ...p });
}

export function sendBiometricPrompt(p: {
    activity?: string;
    authenticators?: number;
    device_credential_allowed?: boolean;
    crypto_object?: boolean;
    negative_button?: string;
    stack?: string;
}): void {
    send({ kind: "biometric.prompt", ...p });
}

/* ------- Sprint 8.4: anti-tamper + dynamic code loading ------- */

export function sendTamperCheck(category: string, p: {
    api: string;
    value?: string;
    result?: unknown;
    stack?: string;
}): void {
    send({ kind: `tamper.${category}`, ...p });
}

export function sendDexLoad(p: {
    loader_class: string;
    path?: string;
    stack?: string;
}): void {
    send({ kind: "code_loading.dex_load", ...p });
}

export function sendNativeLoad(p: {
    loader_class: string;
    path?: string;
    stack?: string;
}): void {
    send({ kind: "code_loading.native_load", ...p });
}

export function sendRuntimeExec(p: {
    loader_class: string;
    path?: string;
    stack?: string;
}): void {
    send({ kind: "code_loading.exec", ...p });
}

/* ------- D_006: runtime IV / key reuse ------- */

export function sendIvConstructed(p: {
    algorithm: string;
    iv_hex: string;
    iv_len?: number;
    constant_pattern?: string;
    stack?: string;
}): void {
    send({ kind: "crypto.iv_constructed", ...p });
}

export function sendSecretKeyCreated(p: {
    algorithm: string;
    key_hex: string;
    key_len?: number;
    stack?: string;
}): void {
    send({ kind: "crypto.secret_key_created", ...p });
}

/* ------- D_008: billing / IAP ------- */

export function sendPurchaseObserved(p: {
    sku?: string;
    purchase_state?: number;
    order_id?: string;
    token_prefix?: string;
    acknowledged?: boolean;
    stack?: string;
}): void {
    send({ kind: "billing.purchase_observed", ...p });
}

export function sendFeatureUnlock(p: {
    entitlement?: string;
    source?: string;
    stack?: string;
}): void {
    send({ kind: "billing.feature_unlock", ...p });
}

/* ------- D_011: WebView runtime ------- */

export function sendWebViewJsInterface(p: {
    name?: string;
    object_class?: string;
    exposed_methods?: string[];
    stack?: string;
}): void {
    send({ kind: "webview.js_interface_added", ...p });
}

export function sendWebViewLoad(p: {
    url?: string;
    scheme?: string;
    stack?: string;
}): void {
    send({ kind: "webview.load", ...p });
}

export function sendWebViewSetting(p: {
    setting: string;
    value: unknown;
    stack?: string;
}): void {
    send({ kind: "webview.settings", ...p });
}

export function sendWebViewDebugging(enabled: boolean): void {
    send({ kind: "webview.debugging", enabled });
}

/* ------- D_012: notification leak ------- */

export function sendNotificationPosted(p: {
    channel_id?: string;
    channel_importance?: number;
    visibility?: number;
    has_public_version?: boolean;
    title?: string;
    text?: string;
    stack?: string;
}): void {
    send({ kind: "notification.posted", ...p });
}
