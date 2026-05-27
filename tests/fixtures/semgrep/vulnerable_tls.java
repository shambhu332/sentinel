package com.example.vuln;

import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class VulnerableTls {
    public void disableHostnameVerification(HttpsURLConnection conn) {
        conn.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

    public X509TrustManager trustEverything() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }
}
