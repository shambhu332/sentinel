/**
 * WebView Debug Enabler — Sentinel
 * ==================================
 * Enables WebView remote debugging (chrome://inspect) and Chrome DevTools
 * Protocol access for hybrid app investigation.
 *
 * Also forces WebContentsDebuggingEnabled on all WebView instances
 * regardless of BuildConfig.DEBUG.
 *
 * Usage:
 *   frida -U -f com.target.app -l webview-debug.js
 *   Then open chrome://inspect in Chrome desktop browser.
 *
 * Note: Requires USB debugging enabled on device.
 */
Java.perform(function () {

    // ── Force setWebContentsDebuggingEnabled globally ─────────────────
    try {
        const WV = Java.use('android.webkit.WebView');
        WV.setWebContentsDebuggingEnabled.implementation = function (enabled) {
            send({ tag: 'webview_debug', event: 'setWebContentsDebuggingEnabled', requested: enabled, forcing: true });
            return this.setWebContentsDebuggingEnabled(true);
        };
        // Force it immediately
        WV.setWebContentsDebuggingEnabled(true);
        send({ tag: 'webview_debug', event: 'force_enabled' });
    } catch (e) { send({ tag: 'webview_debug', hook_error: 'setWebContentsDebuggingEnabled', error: e.message }); }

    // ── Hook WebView constructors to enable debugging on every instance ─
    try {
        const WV2 = Java.use('android.webkit.WebView');
        // Patch each new WebView at construction time via onAttachedToWindow
        WV2.onAttachedToWindow.implementation = function () {
            try { Java.use('android.webkit.WebView').setWebContentsDebuggingEnabled(true); } catch (_) {}
            return this.onAttachedToWindow();
        };
    } catch (e) {}

    // ── Enable verbose JS console logs → Frida ────────────────────────
    try {
        const WVC = Java.use('android.webkit.ConsoleMessage');
        const WVClient = Java.use('android.webkit.WebChromeClient');
        WVClient.onConsoleMessage.overload('android.webkit.ConsoleMessage').implementation = function (msg) {
            send({ tag: 'webview_debug', event: 'console', level: msg.messageLevel().toString(),
                message: msg.message(), source: msg.sourceId(), line: msg.lineNumber() });
            return this.onConsoleMessage(msg);
        };
    } catch (e) {}

    // ── Expose JS bridge for interactive investigation ─────────────────
    try {
        const WV3 = Java.use('android.webkit.WebView');
        WV3.addJavascriptInterface.implementation = function (obj, name) {
            send({ tag: 'webview_debug', event: 'js_bridge_registered', name, class: obj.getClass().getName() });
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) {}

    send({ tag: 'webview_debug', event: 'init_complete',
        status: 'WebView debugging enabled — open chrome://inspect in Chrome' });
});
