package fixtures.taint;

import android.content.Intent;
import android.webkit.WebView;

/**
 * Intent extra flows directly into WebView.loadUrl. The sink's
 * vuln_class is WEBVIEW_XSS, distinct from SQL_INJECTION above —
 * lets the test confirm correct sink → vuln_class mapping.
 * Expected: 1 finding, vuln_class WEBVIEW_XSS, depth 0.
 */
public class WebviewXss {
    public void open(Intent intent, WebView wv) {
        String dest = intent.getStringExtra("url");
        wv.loadUrl(dest);
    }
}
