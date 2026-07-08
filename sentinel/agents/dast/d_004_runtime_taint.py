"""D_004: Runtime taint tracking — Intent/SharedPrefs sources to WebView/SQL/exec sinks."""
from __future__ import annotations

from sentinel.agents.dast.base_dast_agent import BaseDASTAgent, RuntimeEvent
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext

_FRIDA_JS = r"""
Java.perform(function() {
    var sourcedValues = [];  // [{key, value, source_type}]

    function recordSource(sourceType, key, value) {
        if (value && value.length >= 4) {
            sourcedValues.push({source_type: sourceType, key: key, value: value});
            send({agent_id:'D_004', event_type:'taint_source',
                  source_type: sourceType, key: key,
                  value: value.substring(0, 200), timestamp: Date.now()});
        }
    }

    function checkTaint(sinkType, sinkValue) {
        if (!sinkValue) return;
        for (var i = 0; i < sourcedValues.length; i++) {
            var src = sourcedValues[i];
            if (src.value && sinkValue.indexOf(src.value) !== -1) {
                send({agent_id:'D_004', event_type:'taint_flow',
                      source_type: src.source_type, source_key: src.key,
                      sink_type: sinkType, sink_value: sinkValue.substring(0, 300),
                      tainted_value: src.value, timestamp: Date.now()});
            }
        }
        send({agent_id:'D_004', event_type:'taint_sink',
              sink_type: sinkType, value: sinkValue.substring(0, 300), timestamp: Date.now()});
    }

    // Source: Intent.getStringExtra
    try {
        var Intent = Java.use('android.content.Intent');
        Intent.getStringExtra.overload('java.lang.String').implementation = function(key) {
            var result = this.getStringExtra(key);
            if (result) recordSource('intent_extra', key, result.toString());
            return result;
        };
    } catch(e) {
        send({agent_id:'D_004', event_type:'hook_error', error: e.message, hook:'Intent.getStringExtra'});
    }

    // Source: SharedPreferences.getString
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        // Note: SharedPreferences is an interface; hook concrete implementations
        var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPreferencesImpl.getString.implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            if (result) recordSource('shared_prefs', key, result.toString());
            return result;
        };
    } catch(e) {
        send({agent_id:'D_004', event_type:'hook_error', error: e.message, hook:'SharedPreferences.getString'});
    }

    // Sink: WebView.loadUrl
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            checkTaint('webview_loadurl', url ? url.toString() : '');
            return this.loadUrl(url);
        };
    } catch(e) {
        send({agent_id:'D_004', event_type:'hook_error', error: e.message, hook:'WebView.loadUrl'});
    }

    // Sink: SQLiteDatabase.execSQL
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            checkTaint('sqlite_exec', sql ? sql.toString() : '');
            return this.execSQL(sql);
        };
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
            .implementation = function(sql, selArgs) {
                checkTaint('sqlite_query', sql ? sql.toString() : '');
                return this.rawQuery(sql, selArgs);
            };
    } catch(e) {
        send({agent_id:'D_004', event_type:'hook_error', error: e.message, hook:'SQLiteDatabase'});
    }

    // Sink: Runtime.exec
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            checkTaint('runtime_exec', cmd ? cmd.toString() : '');
            return this.exec(cmd);
        };
    } catch(e) {
        send({agent_id:'D_004', event_type:'hook_error', error: e.message, hook:'Runtime.exec'});
    }
});
"""

_SINK_SEVERITY: dict[str, tuple[Severity, str, str]] = {
    "webview_loadurl": (Severity.HIGH,    "Intent taint → WebView XSS",          "CWE-79"),
    "sqlite_exec":     (Severity.CRITICAL, "Intent taint → SQL injection",         "CWE-89"),
    "sqlite_query":    (Severity.CRITICAL, "Intent taint → SQL injection",         "CWE-89"),
    "runtime_exec":    (Severity.CRITICAL, "Intent taint → command injection",     "CWE-78"),
}


class D004RuntimeTaintAgent(BaseDASTAgent):
    AGENT_ID = "D_004"
    VULN_CLASS = "Runtime Taint Flow"
    _DESCRIPTION = "Track taint from Intent/SharedPrefs sources to WebView/SQL/exec sinks at runtime"

    def get_frida_script(self) -> str:
        return _FRIDA_JS

    async def analyze_events(
        self, events: list[RuntimeEvent], ctx: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        flows = [e for e in events if e.event_type == "taint_flow"]

        seen: set[str] = set()
        for flow in flows:
            sink_type = flow.data.get("sink_type", "unknown")
            source_key = flow.data.get("source_key", "unknown")
            dedup_key = f"{sink_type}:{source_key}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            sev, title, cwe = _SINK_SEVERITY.get(
                sink_type,
                (Severity.MEDIUM, f"Taint flow to {sink_type}", "CWE-20"),
            )

            findings.append(Finding(
                agent_id=self.AGENT_ID,
                session_id=ctx.session_id,
                vuln_class=self.VULN_CLASS,
                severity=sev,
                confidence=0.85,
                severity_rationale=(
                    f"Runtime taint confirmed: Intent extra '{source_key}' "
                    f"flows to {sink_type} without sanitization."
                ),
                evidence={
                    "source_type": flow.data.get("source_type"),
                    "source_key": source_key,
                    "sink_type": sink_type,
                    "tainted_value_preview": flow.data.get("tainted_value", "")[:100],
                    "sink_value_preview": flow.data.get("sink_value", "")[:200],
                },
                recommendation=(
                    f"Validate and sanitize all Intent extras before passing to {sink_type}. "
                    "Use parameterised queries for SQL, Content-Security-Policy for WebView, "
                    "and avoid Runtime.exec with user-controlled input."
                ),
                compliance_tags=[cwe, "CWE-20"],
                owasp="M1: Improper Platform Usage",
                masvs="MASVS-PLATFORM-2",
                finding_category="Static_Tool",
            ))

        return findings
