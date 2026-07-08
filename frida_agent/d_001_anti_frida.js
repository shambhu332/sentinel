
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
