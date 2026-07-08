
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
