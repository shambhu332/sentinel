
Java.perform(function() {
    // Detect + bypass OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation =
            function(hostname, peerCertificates) {
                send({agent_id:'D_002', event_type:'pinning_detected',
                      mechanism:'okhttp_certificate_pinner', host: hostname, timestamp: Date.now()});
                send({agent_id:'D_002', event_type:'ssl_bypass_applied',
                      mechanism:'okhttp_certificate_pinner', timestamp: Date.now()});
                // no-op: bypass
            };
    } catch(e) {
        send({agent_id:'D_002', event_type:'hook_error', error: e.message, hook:'CertificatePinner'});
    }

    // Detect + bypass WebViewClient.onReceivedSslError
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            send({agent_id:'D_002', event_type:'pinning_detected',
                  mechanism:'webview_ssl_error', timestamp: Date.now()});
            handler.proceed();
            send({agent_id:'D_002', event_type:'ssl_bypass_applied',
                  mechanism:'webview_ssl_error', timestamp: Date.now()});
        };
    } catch(e) {
        send({agent_id:'D_002', event_type:'hook_error', error: e.message, hook:'WebViewClient.onReceivedSslError'});
    }

    // Detect custom TrustManager (X509TrustManager)
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        TrustManagerFactory.getTrustManagers.implementation = function() {
            var tms = this.getTrustManagers();
            send({agent_id:'D_002', event_type:'trust_manager_observed',
                  count: tms.length, timestamp: Date.now()});
            return tms;
        };
    } catch(e) {
        send({agent_id:'D_002', event_type:'hook_error', error: e.message, hook:'TrustManagerFactory'});
    }
});
