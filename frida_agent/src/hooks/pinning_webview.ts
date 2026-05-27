/*
 * WebView pinning hook with subclass enumeration.
 *
 * The legacy CERT_PINNING_BYPASS_HOOK only patched the base
 * android.webkit.WebViewClient.onReceivedSslError. Almost every real
 * Android app extends WebViewClient and overrides that method, so
 * dynamic dispatch runs the subclass override and our base-class hook
 * never fires.
 *
 * This module:
 *   1. Hooks the base class (catches direct WebViewClient uses)
 *   2. Enumerates every currently-loaded class, finds subclasses of
 *      WebViewClient, and hooks each subclass's onReceivedSslError
 *      directly so the subclass override is replaced
 *   3. Intercepts ClassLoader.loadClass so subclasses loaded LATER
 *      (after our setup runs) are also hooked the moment they appear
 *
 * Also patches onReceivedHttpAuthRequest for the same subclasses, which
 * apps sometimes use to silently accept proxy/server credentials and
 * leak them through a hostile network.
 */
import { Java } from "../lib/java_ready.js";
import { sendBypass, sendBypassFailed } from "../lib/send.js";

export interface WebViewHookResult {
    libraryLabel: string;
    subclassesHooked: number;
}

const BASE_CLASS = "android.webkit.WebViewClient";

function hookOnReceivedSslError(cls: any, libraryLabel: string): boolean {
    if (typeof cls.onReceivedSslError === "undefined") return false;
    try {
        cls.onReceivedSslError.implementation = function (
            this: any, _view: unknown, handler: any, error: any,
        ) {
            let url = "";
            try { url = error ? String(error.getUrl()) : ""; } catch { /* */ }
            sendBypass({
                library: libraryLabel,
                method: "onReceivedSslError",
                host: url,
            });
            try { handler.proceed(); } catch { /* handler may be null */ }
        };
        return true;
    } catch {
        return false;
    }
}

function hookOnReceivedHttpAuthRequest(cls: any, libraryLabel: string): boolean {
    if (typeof cls.onReceivedHttpAuthRequest === "undefined") return false;
    try {
        cls.onReceivedHttpAuthRequest.implementation = function (
            this: any, view: unknown, handler: any,
            host: string, realm: string,
        ) {
            sendBypass({
                library: libraryLabel,
                method: "onReceivedHttpAuthRequest",
                host: String(host || ""),
                extra: { realm: String(realm || "") },
            });
            return this.onReceivedHttpAuthRequest(view, handler, host, realm);
        };
        return true;
    } catch {
        return false;
    }
}

export function installWebViewHooks(): WebViewHookResult {
    let subclassesHooked = 0;

    try {
        const WebViewClientBase = Java.use(BASE_CLASS);

        // Step 1: hook the base class first.
        if (hookOnReceivedSslError(WebViewClientBase, "WebViewClient.base")) {
            subclassesHooked++;
        }
        hookOnReceivedHttpAuthRequest(WebViewClientBase, "WebViewClient.base");

        // Step 2: enumerate currently loaded classes and hook every
        // subclass's own onReceivedSslError override. Dynamic dispatch
        // means the subclass override runs instead of the base, so we
        // have to instrument each subclass directly.
        const WebViewClientClass = WebViewClientBase.class;
        const loaded: string[] = Java.enumerateLoadedClassesSync();

        loaded.forEach((className: string) => {
            if (className === BASE_CLASS) return;
            // Cheap pre-filter: skip system packages that can't possibly
            // contain custom WebViewClient subclasses (most loaded
            // classes). Saves Java.use() throws for ~99% of names.
            if (
                className.startsWith("java.")
                || className.startsWith("javax.")
                || className.startsWith("sun.")
                || className.startsWith("kotlin.")
                || className.startsWith("kotlinx.")
                || className.indexOf("$$") !== -1
            ) {
                return;
            }
            try {
                const cls = Java.use(className);
                if (!WebViewClientClass.isAssignableFrom(cls.class)) return;
                const label = `WebViewClient.subclass:${className}`;
                if (hookOnReceivedSslError(cls, label)) subclassesHooked++;
                hookOnReceivedHttpAuthRequest(cls, label);
            } catch {
                // skip classes we can't instrument
            }
        });

        // Step 3: catch classes loaded LATER via ClassLoader hook.
        try {
            const ClassLoader = Java.use("java.lang.ClassLoader");
            const loadClass = ClassLoader.loadClass.overload("java.lang.String");
            loadClass.implementation = function (this: any, name: string) {
                const loadedCls = loadClass.call(this, name);
                try {
                    if (
                        loadedCls
                        && name !== BASE_CLASS
                        && !name.startsWith("java.")
                        && !name.startsWith("javax.")
                        && WebViewClientClass.isAssignableFrom(loadedCls)
                    ) {
                        const cls = Java.use(name);
                        const label = `WebViewClient.subclass:${name}`;
                        if (hookOnReceivedSslError(cls, label)) {
                            subclassesHooked++;
                        }
                        hookOnReceivedHttpAuthRequest(cls, label);
                    }
                } catch {
                    // ignore — class not instrumentable
                }
                return loadedCls;
            };
        } catch (e) {
            // ClassLoader hook is best-effort; failures here don't
            // affect the already-installed subclass hooks.
            sendBypassFailed("WebViewClient.classloader", String(e));
        }
    } catch (e) {
        sendBypassFailed("WebViewClient", String(e));
    }

    return { libraryLabel: "WebViewClient.all", subclassesHooked };
}
