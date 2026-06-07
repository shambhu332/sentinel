/*
 * WebView runtime hooks (D_011).
 *
 * Watches the security-relevant entry points on android.webkit.WebView
 * and android.webkit.WebSettings without altering behaviour. One
 * event per observed call. The Python agent (WebViewRuntimeAgent)
 * cross-references bridges against loaded origins and classifies
 * severity.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendWebViewJsInterface,
    sendWebViewLoad,
    sendWebViewSetting,
    sendWebViewDebugging,
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

function exposedMethods(obj: any): string[] {
    const out: string[] = [];
    try {
        const cls = obj.getClass();
        const methods = cls.getMethods();
        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            // Only enumerate methods carrying @JavascriptInterface —
            // they are the actually-callable surface from JS on API
            // 17+.
            const ann = m.getAnnotations();
            let jsCallable = false;
            for (let a = 0; a < ann.length; a++) {
                if (String(ann[a]).indexOf("JavascriptInterface") !== -1) {
                    jsCallable = true;
                    break;
                }
            }
            if (jsCallable) {
                out.push(String(m.getName()));
            }
        }
    } catch (_) { /* swallow */ }
    return out;
}

function schemeOf(url: string): string {
    if (!url) return "";
    const i = url.indexOf(":");
    if (i <= 0) return "";
    return url.substring(0, i).toLowerCase();
}

export function installWebViewRuntimeHooks(): number {
    let installed = 0;

    // ---- WebView.addJavascriptInterface(Object, String) ----
    try {
        const WV = Java.use("android.webkit.WebView");
        WV.addJavascriptInterface.overload(
            "java.lang.Object", "java.lang.String",
        ).implementation = function (obj: any, name: string) {
            try {
                sendWebViewJsInterface({
                    name: String(name),
                    object_class: obj ? String(obj.getClass().getName())
                                       : "<null>",
                    exposed_methods: obj ? exposedMethods(obj) : [],
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`webview.bridge hook: ${String(e)}`);
            }
            return this.addJavascriptInterface(obj, name);
        };
        installed++;

        // ---- WebView.loadUrl(String) ----
        try {
            WV.loadUrl.overload("java.lang.String").implementation =
                function (url: string) {
                    try {
                        sendWebViewLoad({
                            url: String(url),
                            scheme: schemeOf(String(url)),
                            stack: shortStack(),
                        });
                    } catch (_) { /* swallow */ }
                    return this.loadUrl(url);
                };
            installed++;
        } catch (_) { /* overload may differ */ }

        // ---- WebView.loadUrl(String, Map) ----
        try {
            WV.loadUrl.overload(
                "java.lang.String", "java.util.Map",
            ).implementation = function (url: string, hdrs: any) {
                try {
                    sendWebViewLoad({
                        url: String(url),
                        scheme: schemeOf(String(url)),
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return this.loadUrl(url, hdrs);
            };
            installed++;
        } catch (_) { /* may not be present */ }

        // ---- WebView.setWebContentsDebuggingEnabled(boolean) (static) ----
        try {
            WV.setWebContentsDebuggingEnabled.implementation = function (b: boolean) {
                try { sendWebViewDebugging(!!b); }
                catch (_) { /* swallow */ }
                return this.setWebContentsDebuggingEnabled(b);
            };
            installed++;
        } catch (_) { /* static method on API 19+ */ }
    } catch (_) { /* WebView absent */ }

    // ---- WebSettings setters ----
    try {
        const WS = Java.use("android.webkit.WebSettings");

        const hookBool = (name: string) => {
            try {
                (WS as any)[name].implementation = function (b: boolean) {
                    try {
                        sendWebViewSetting({
                            setting: name, value: !!b, stack: shortStack(),
                        });
                    } catch (_) { /* swallow */ }
                    return (this as any)[name](b);
                };
                installed++;
            } catch (_) { /* setter not present on this API */ }
        };
        hookBool("setJavaScriptEnabled");
        hookBool("setAllowFileAccess");
        hookBool("setAllowFileAccessFromFileURLs");
        hookBool("setAllowUniversalAccessFromFileURLs");
        hookBool("setAllowContentAccess");

        try {
            WS.setMixedContentMode.implementation = function (mode: number) {
                try {
                    sendWebViewSetting({
                        setting: "setMixedContentMode",
                        value: mode,
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return this.setMixedContentMode(mode);
            };
            installed++;
        } catch (_) { /* API 21+ */ }
    } catch (_) { /* WebSettings absent */ }

    return installed;
}
