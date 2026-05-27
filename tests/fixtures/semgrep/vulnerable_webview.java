package com.example.vuln;

import android.webkit.WebView;
import android.webkit.WebSettings;

public class VulnerableWebView {
    public void setup(WebView webView) {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        webView.addJavascriptInterface(new BridgeApi(), "AndroidBridge");
        webView.loadUrl("https://example.com/embedded");
    }

    static class BridgeApi {
        public String getAuthToken() {
            return "secret";
        }
    }
}
