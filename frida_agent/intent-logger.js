/**
 * Intent Logger — Sentinel
 * =========================
 * Passive IPC observer. Logs all incoming and outgoing intents across
 * Activities, Services, Receivers, Providers, and deep link handling.
 *
 * Useful for:
 *   - Mapping attack surface (what IPC entry points exist at runtime)
 *   - Observing nested intent relay (confused deputy)
 *   - Identifying exported components handling untrusted data
 *
 * Usage:
 *   frida -U -f com.target.app -l intent-logger.js
 */
Java.perform(function () {

    function descIntent(intent) {
        if (!intent) return '<null intent>';
        try {
            const action  = intent.getAction ? intent.getAction() : null;
            const data    = intent.getData   ? intent.getData()   : null;
            const comp    = intent.getComponent ? intent.getComponent() : null;
            const extras  = intent.getExtras ? intent.getExtras() : null;
            return {
                action:    action ? action.toString()  : null,
                data:      data   ? data.toString()    : null,
                component: comp   ? comp.toString()    : null,
                extras:    extras ? extras.toString()  : null,
            };
        } catch (e) { return '<describe failed: ' + e.message + '>'; }
    }

    // ── Activity.onCreate / onNewIntent ───────────────────────────────
    try {
        const Activity = Java.use('android.app.Activity');
        Activity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
            const intent = this.getIntent ? this.getIntent() : null;
            send({ tag: 'intent', event: 'Activity.onCreate', class: this.getClass().getName(), intent: descIntent(intent) });
            return this.onCreate(bundle);
        };
        Activity.onNewIntent.implementation = function (intent) {
            send({ tag: 'intent', event: 'Activity.onNewIntent', class: this.getClass().getName(), intent: descIntent(intent) });
            return this.onNewIntent(intent);
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'Activity', error: e.message }); }

    // ── Service.onStartCommand ────────────────────────────────────────
    try {
        const Service = Java.use('android.app.Service');
        Service.onStartCommand.implementation = function (intent, flags, startId) {
            send({ tag: 'intent', event: 'Service.onStartCommand', class: this.getClass().getName(), intent: descIntent(intent), flags, startId });
            return this.onStartCommand(intent, flags, startId);
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'Service', error: e.message }); }

    // ── BroadcastReceiver.onReceive ───────────────────────────────────
    try {
        const BR = Java.use('android.content.BroadcastReceiver');
        BR.onReceive.implementation = function (ctx, intent) {
            send({ tag: 'intent', event: 'BroadcastReceiver.onReceive', class: this.getClass().getName(), intent: descIntent(intent) });
            return this.onReceive(ctx, intent);
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'BroadcastReceiver', error: e.message }); }

    // ── Outbound: startActivity ───────────────────────────────────────
    try {
        const Context = Java.use('android.content.Context');
        Context.startActivity.overload('android.content.Intent').implementation = function (intent) {
            send({ tag: 'intent', event: 'startActivity', intent: descIntent(intent) });
            return this.startActivity(intent);
        };
        Context.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent, opts) {
            send({ tag: 'intent', event: 'startActivity(opts)', intent: descIntent(intent) });
            return this.startActivity(intent, opts);
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'Context.startActivity', error: e.message }); }

    // ── Outbound: sendBroadcast ───────────────────────────────────────
    try {
        const Context2 = Java.use('android.content.Context');
        Context2.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
            send({ tag: 'intent', event: 'sendBroadcast', intent: descIntent(intent) });
            return this.sendBroadcast(intent);
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'sendBroadcast', error: e.message }); }

    // ── Outbound: startService / bindService ──────────────────────────
    try {
        const Context3 = Java.use('android.content.Context');
        Context3.startService.overload('android.content.Intent').implementation = function (intent) {
            send({ tag: 'intent', event: 'startService', intent: descIntent(intent) });
            return this.startService(intent);
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'startService', error: e.message }); }

    // ── Deep link: getData on incoming intent ─────────────────────────
    try {
        const Intent = Java.use('android.content.Intent');
        Intent.getData.implementation = function () {
            const uri = this.getData();
            if (uri) send({ tag: 'intent', event: 'Intent.getData', uri: uri.toString() });
            return uri;
        };
        Intent.getDataString.implementation = function () {
            const s = this.getDataString();
            if (s) send({ tag: 'intent', event: 'Intent.getDataString', value: s });
            return s;
        };
    } catch (e) { send({ tag: 'intent', hook_error: 'Intent.getData', error: e.message }); }

    send({ tag: 'intent', event: 'init_complete', status: 'Intent logger loaded' });
});
