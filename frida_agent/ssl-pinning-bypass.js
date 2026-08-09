/**
 * SSL Pinning Bypass — Sentinel
 * ==============================
 * Coverage (STABLE):
 *   - TrustManagerImpl / Conscrypt (system TLS stack)
 *   - HttpsURLConnection default trust chain
 *   - OkHttp3 CertificatePinner.check()
 *   - Custom X509TrustManager (checkServerTrusted no-op)
 *   - WebViewClient.onReceivedSslError (proceed)
 *   - HostnameVerifier.verify() (returns true)
 *
 * Known gaps:
 *   - Flutter: uses BoringSSL natively — Java hooks don't reach it.
 *     Use native-root-detection-probe.js + SSL_CTX hooks for Flutter.
 *   - Network Security Config (NSC) static pins require smali patch or
 *     apktool + network_security_config.xml edit.
 *   - OkHttp certificate transparency (OkHttp 4.x+) may need
 *     additional CertificateTransparency interceptor hooks.
 *
 * Usage:
 *   frida -U -f com.example.app -l ssl-pinning-bypass.js --no-pause
 */

Java.perform(function () {

    // ─── TrustManagerImpl (Conscrypt / system stack) ───────────────────
    try {
        var TrustManagerImpl = Java.use(
            "com.android.org.conscrypt.TrustManagerImpl"
        );
        TrustManagerImpl.verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            send({ tag: "ssl_bypass", hook: "TrustManagerImpl.verifyChain", host: host });
            return untrustedChain;
        };
    } catch (e) { /* Conscrypt not present or already patched */ }

    // ─── X509TrustManager — checkServerTrusted ─────────────────────────
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
            send({ tag: "ssl_bypass", hook: "X509TrustManager.checkServerTrusted" });
        };
    } catch (e) { /* interface, implementations patched below */ }

    // Enumerate all X509TrustManager implementations at load time
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            try {
                if (name.indexOf("TrustManager") === -1) return;
                var cls = Java.use(name);
                if (!cls.checkServerTrusted) return;
                cls.checkServerTrusted.overload(
                    "[Ljava.security.cert.X509Certificate;",
                    "java.lang.String"
                ).implementation = function () {
                    send({ tag: "ssl_bypass", hook: "custom_TrustManager", class: name });
                };
            } catch (_) {}
        },
        onComplete: function () {},
    });

    // ─── OkHttp3 CertificatePinner ─────────────────────────────────────
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload(
            "java.lang.String", "java.util.List"
        ).implementation = function (hostname, peerCerts) {
            send({ tag: "ssl_bypass", hook: "OkHttp3.CertificatePinner.check", host: hostname });
        };
        // OkHttp 4.x overload
        CertPinner.check.overload(
            "java.lang.String", "kotlin.jvm.functions.Function0"
        ).implementation = function (hostname, certificateFn) {
            send({ tag: "ssl_bypass", hook: "OkHttp3.CertificatePinner.check(4.x)", host: hostname });
        };
    } catch (e) { /* OkHttp not present */ }

    // ─── WebViewClient.onReceivedSslError ──────────────────────────────
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            send({ tag: "ssl_bypass", hook: "WebViewClient.onReceivedSslError", error: error.toString() });
            handler.proceed();
        };
    } catch (e) {}

    // ─── HostnameVerifier ───────────────────────────────────────────────
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        // Enumerate custom implementations
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                try {
                    if (name.indexOf("HostnameVerifier") === -1 &&
                        name.indexOf("HostVerifier") === -1) return;
                    var cls = Java.use(name);
                    if (!cls.verify) return;
                    cls.verify.overload(
                        "java.lang.String", "javax.net.ssl.SSLSession"
                    ).implementation = function (hostname, session) {
                        send({ tag: "ssl_bypass", hook: "HostnameVerifier.verify", class: name, host: hostname });
                        return true;
                    };
                } catch (_) {}
            },
            onComplete: function () {},
        });
    } catch (e) {}

    // ─── HttpsURLConnection default SSLSocketFactory ────────────────────
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function (factory) {
            send({ tag: "ssl_bypass", hook: "HttpsURLConnection.setDefaultSSLSocketFactory" });
            // Allow but log so we know a custom factory was set
            this.setDefaultSSLSocketFactory(factory);
        };
    } catch (e) {}

    send({ tag: "ssl_bypass", hook: "init_complete", status: "SSL pinning bypass loaded" });
});
