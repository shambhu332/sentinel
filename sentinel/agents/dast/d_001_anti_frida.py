"""D_001: Detect and bypass anti-Frida / anti-debug checks at runtime."""
from __future__ import annotations

from sentinel.agents.dast.base_dast_agent import BaseDASTAgent, RuntimeEvent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext

_FRIDA_JS = r"""
Java.perform(function() {
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var sus = ['frida', 'gum-js', 'linjector', 'XposedBridge'];
            for (var i = 0; i < sus.length; i++) {
                if (path.indexOf(sus[i]) !== -1) {
                    send({agent_id:'D_001', event_type:'anti_frida_check',
                          check_type:'file_exists', path: path, timestamp: Date.now()});
                    return false;
                }
            }
            return this.exists();
        };
    } catch(e) {
        send({agent_id:'D_001', event_type:'hook_error', error: e.message, hook:'File.exists'});
    }

    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            send({agent_id:'D_001', event_type:'anti_frida_check',
                  check_type:'debugger_check', timestamp: Date.now()});
            return false;
        };
    } catch(e) {
        send({agent_id:'D_001', event_type:'hook_error', error: e.message, hook:'Debug.isDebuggerConnected'});
    }

    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function(key) {
            var emuKeys = ['ro.kernel.qemu', 'ro.debuggable', 'ro.build.fingerprint'];
            for (var i = 0; i < emuKeys.length; i++) {
                if (key === emuKeys[i]) {
                    send({agent_id:'D_001', event_type:'anti_frida_check',
                          check_type:'system_property', key: key, timestamp: Date.now()});
                }
            }
            return this.getProperty(key);
        };
    } catch(e) {
        send({agent_id:'D_001', event_type:'hook_error', error: e.message, hook:'System.getProperty'});
    }
});
"""


class D001AntiFridaAgent(BaseDASTAgent):
    AGENT_ID = "D_001"
    VULN_CLASS = "Anti-Tampering Detection"
    _DESCRIPTION = "Detect and bypass anti-Frida, anti-debug, and anti-emulator checks at runtime"

    def get_frida_script(self) -> str:
        return _FRIDA_JS

    async def analyze_events(
        self, events: list[RuntimeEvent], ctx: ScanContext
    ) -> list[Finding]:
        checks: list[dict] = [
            e.data for e in events if e.event_type == "anti_frida_check"
        ]
        if not checks:
            return []

        check_types = list({c.get("check_type", "unknown") for c in checks})
        severity = Severity.MEDIUM if len(check_types) >= 2 else Severity.LOW

        return [Finding(
            agent_id=self.AGENT_ID,
            session_id=ctx.session_id,
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=0.80,
            severity_rationale=(
                f"{len(checks)} anti-tampering events across "
                f"{len(check_types)} check type(s): {', '.join(check_types)}"
            ),
            evidence={
                "check_count": len(checks),
                "check_types": check_types,
                "checks": checks[:10],
                "bypass_applied": True,
            },
            recommendation=(
                "App relies on client-side root/debug detection which Frida bypassed trivially. "
                "Move security enforcement to the server side. Client-side checks add friction "
                "but are not a security control."
            ),
            compliance_tags=["CWE-656", "CWE-693"],
            owasp="M8: Security Decisions Via Untrusted Inputs",
            masvs="MASVS-RESILIENCE-1",
            finding_category="Static_Tool",
        )]
