/**
 * WebView Monitor — Sentinel
 * ===========================
 * Monitors WebView URL loads, JavaScript interface registrations,
 * security settings, SSL errors, and JS evaluation.
 *
 * Findings emitted via send():
 *   - loadUrl calls (including file:// and javascript: URIs)
 *   - addJavascriptInterface registrations (XSS bridge)
 *   - setJavaScriptEnabled(true)
 *   - setAllowFileAccessFromFileURLs(true) — high risk
 *   - onReceivedSslError handler status
 *   - evaluateJavascript payloads
 *
 * Usage:
 *   frida -U -f com.target.app -l webview-monitor.js
 */
Java.perform(function () {

    // ── loadUrl ───────────────────────────────────────────────────────
    try {
        const WV = Java.use('android.webkit.WebView');
        WV.loadUrl.overload('java.lang.String').implementation = function (url) {
            send({ tag: 'webview', event: 'loadUrl', url,
                risk: url.startsWith('javascript:') ? 'HIGH_JS_INJECTION' :
                      url.startsWith('file://')     ? 'MED_FILE_ACCESS'   : 'LOW' });
            return this.loadUrl(url);
        };
        WV.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
            send({ tag: 'webview', event: 'loadUrl(headers)', url });
            return this.loadUrl(url, headers);
        };
        WV.loadData.implementation = function (data, mimeType, encoding) {
            send({ tag: 'webview', event: 'loadData', mime: mimeType, data_preview: data.slice(0, 200) });
            return this.loadData(data, mimeType, encoding);
        };
        WV.loadDataWithBaseURL.implementation = function (baseUrl, data, mime, enc, hist) {
            send({ tag: 'webview', event: 'loadDataWithBaseURL', baseUrl,
                risk: baseUrl && baseUrl.startsWith('file://') ? 'HIGH_FILE_BASE' : 'LOW' });
            return this.loadDataWithBaseURL(baseUrl, data, mime, enc, hist);
        };
    } catch (e) { send({ tag: 'webview', hook_error: 'loadUrl', error: e.message }); }

    // ── evaluateJavascript ────────────────────────────────────────────
    try {
        const WV2 = Java.use('android.webkit.WebView');
        WV2.evaluateJavascript.implementation = function (script, cb) {
            send({ tag: 'webview', event: 'evaluateJavascript', preview: script.slice(0, 300) });
            return this.evaluateJavascript(script, cb);
        };
    } catch (e) { send({ tag: 'webview', hook_error: 'evaluateJavascript', error: e.message }); }

    // ── addJavascriptInterface ────────────────────────────────────────
    try {
        const WV3 = Java.use('android.webkit.WebView');
        WV3.addJavascriptInterface.implementation = function (obj, name) {
            send({ tag: 'webview', event: 'addJavascriptInterface', name, class: obj.getClass().getName(),
                note: 'XSS bridge: JS can call @JavascriptInterface methods on this object' });
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) { send({ tag: 'webview', hook_error: 'addJavascriptInterface', error: e.message }); }

    // ── WebSettings: dangerous flags ──────────────────────────────────
    try {
        const WS = Java.use('android.webkit.WebSettings');
        WS.setJavaScriptEnabled.implementation = function (enabled) {
            send({ tag: 'webview', event: 'setJavaScriptEnabled', enabled });
            return this.setJavaScriptEnabled(enabled);
        };
        WS.setAllowFileAccess.implementation = function (allow) {
            if (allow) send({ tag: 'webview', event: 'setAllowFileAccess', allow, risk: 'MEDIUM' });
            return this.setAllowFileAccess(allow);
        };
        WS.setAllowFileAccessFromFileURLs.implementation = function (allow) {
            if (allow) send({ tag: 'webview', event: 'setAllowFileAccessFromFileURLs', allow, risk: 'HIGH' });
            return this.setAllowFileAccessFromFileURLs(allow);
        };
        WS.setAllowUniversalAccessFromFileURLs.implementation = function (allow) {
            if (allow) send({ tag: 'webview', event: 'setAllowUniversalAccessFromFileURLs', allow, risk: 'CRITICAL' });
            return this.setAllowUniversalAccessFromFileURLs(allow);
        };
    } catch (e) { send({ tag: 'webview', hook_error: 'WebSettings', error: e.message }); }

    // ── WebViewClient: SSL errors ─────────────────────────────────────
    try {
        const WVC = Java.use('android.webkit.WebViewClient');
        WVC.onReceivedSslError.implementation = function (view, handler, error) {
            const action = 'proceed_would_bypass_ssl';
            send({ tag: 'webview', event: 'onReceivedSslError', error: error.toString(), action });
            // Do NOT auto-proceed — observe only. Bypass handled by ssl-pinning-bypass.js.
            return this.onReceivedSslError(view, handler, error);
        };
        WVC.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String')
        .implementation = function (view, url) {
            send({ tag: 'webview', event: 'shouldOverrideUrlLoading', url });
            return this.shouldOverrideUrlLoading(view, url);
        };
    } catch (e) { send({ tag: 'webview', hook_error: 'WebViewClient', error: e.message }); }

    send({ tag: 'webview', event: 'init_complete', status: 'WebView monitor loaded' });
});
