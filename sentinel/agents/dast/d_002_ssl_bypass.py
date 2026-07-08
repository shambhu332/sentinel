"""D_002: Detect SSL pinning and validate universal bypass at runtime."""
from __future__ import annotations

from sentinel.agents.dast.base_dast_agent import BaseDASTAgent, RuntimeEvent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext

_FRIDA_JS = r"""
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
"""


class D002SSLBypassAgent(BaseDASTAgent):
    AGENT_ID = "D_002"
    VULN_CLASS = "SSL Pinning Bypass"
    _DESCRIPTION = "Detect SSL certificate pinning and validate bypass via Frida"

    def get_frida_script(self) -> str:
        return _FRIDA_JS

    async def analyze_events(
        self, events: list[RuntimeEvent], ctx: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []

        pinning_events = [e for e in events if e.event_type == "pinning_detected"]
        bypass_events = [e for e in events if e.event_type == "ssl_bypass_applied"]
        mechanisms = list({e.data.get("mechanism", "unknown") for e in pinning_events})

        if pinning_events and bypass_events:
            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.92,
                severity_rationale=(
                    f"SSL pinning present ({', '.join(mechanisms)}) but bypassed "
                    "via Frida hook — MITM traffic interception is possible."
                ),
                evidence={
                    "pinning_mechanisms": mechanisms,
                    "bypass_applied": True,
                    "pinning_event_count": len(pinning_events),
                    "bypass_event_count": len(bypass_events),
                },
                recommendation=(
                    "Implement multi-layer SSL pinning (OkHttp CertificatePinner + "
                    "Network Security Config). Add runtime integrity checks and obfuscation "
                    "to increase bypass difficulty. Rotate pins regularly."
                ),
                compliance_tags=["CWE-295", "CWE-297"],
                owasp="M3: Insecure Communication",
                masvs="MASVS-NETWORK-2",
                finding_category="Static_Tool",
            ))
        elif not pinning_events:
            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=Severity.MEDIUM,
                confidence=0.70,
                severity_rationale=(
                    "No SSL pinning detected at runtime — MITM attack possible "
                    "without Frida (rogue CA or proxy is sufficient)."
                ),
                evidence={
                    "pinning_mechanisms": [],
                    "bypass_applied": False,
                    "note": "No CertificatePinner or SSL error hooks triggered",
                },
                recommendation=(
                    "Implement certificate pinning using OkHttp CertificatePinner "
                    "or Android Network Security Config <pin-set>."
                ),
                compliance_tags=["CWE-295"],
                owasp="M3: Insecure Communication",
                masvs="MASVS-NETWORK-2",
                finding_category="Static_Tool",
            ))

        return findings
