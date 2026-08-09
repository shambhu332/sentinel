/**
 * Flutter Channel Hook — Sentinel
 * =================================
 * Hooks Flutter method channels, event channels, and the platform
 * message bridge to observe bidirectional Dart↔Native communication.
 *
 * Approach: Flutter encodes platform messages as binary via the standard
 * codec or JSON codec. We hook at the MethodChannel Java side (the
 * platform plugin host) and at BinaryMessenger to capture raw bytes.
 *
 * Coverage:
 *   - MethodChannel: invokeMethod calls in both directions
 *   - EventChannel: stream subscriptions
 *   - BasicMessageChannel: raw message passing
 *   - FlutterJNI: low-level platform message dispatch
 *
 * Note: Dart-side logic runs in the Flutter engine (libflutter.so).
 *       For deep Dart inspection use Blutter + native SSL hooks.
 *
 * Usage:
 *   frida -U -f com.target.app -l flutter-channel-hook.js
 */
Java.perform(function () {

    function tryHook(className, method, impl) {
        try { Java.use(className)[method].implementation = impl; }
        catch (e) { send({ tag: 'flutter', hook_skip: className + '.' + method, reason: e.message }); }
    }

    // ── MethodChannel ─────────────────────────────────────────────────
    tryHook('io.flutter.plugin.common.MethodChannel', 'invokeMethod',
        function (method, args) {
            send({ tag: 'flutter', event: 'MethodChannel.invokeMethod', channel: this.name, method, args: String(args) });
            return this.invokeMethod(method, args);
        });

    tryHook('io.flutter.plugin.common.MethodChannel', 'setMethodCallHandler',
        function (handler) {
            const channelName = (() => { try { return this.name; } catch { return '<unknown>'; } })();
            send({ tag: 'flutter', event: 'MethodChannel.setMethodCallHandler', channel: channelName,
                handler: handler ? handler.getClass().getName() : null });
            return this.setMethodCallHandler(handler);
        });

    // ── EventChannel ──────────────────────────────────────────────────
    tryHook('io.flutter.plugin.common.EventChannel', 'setStreamHandler',
        function (handler) {
            send({ tag: 'flutter', event: 'EventChannel.setStreamHandler',
                handler: handler ? handler.getClass().getName() : null });
            return this.setStreamHandler(handler);
        });

    // ── BasicMessageChannel ───────────────────────────────────────────
    tryHook('io.flutter.plugin.common.BasicMessageChannel', 'send',
        function (message, callback) {
            send({ tag: 'flutter', event: 'BasicMessageChannel.send', message: String(message) });
            return this.send(message, callback);
        });

    // ── FlutterJNI — low-level dispatch ──────────────────────────────
    tryHook('io.flutter.embedding.engine.FlutterJNI', 'handlePlatformMessage',
        function (channel, message, replyId) {
            const preview = message ? Java.use('android.util.Base64').encodeToString(message, 0) : null;
            send({ tag: 'flutter', event: 'FlutterJNI.handlePlatformMessage', channel, replyId, payload_b64: preview });
            return this.handlePlatformMessage(channel, message, replyId);
        });

    tryHook('io.flutter.embedding.engine.FlutterJNI', 'invokePlatformMessageResponseCallback',
        function (replyId, message) {
            const preview = message ? Java.use('android.util.Base64').encodeToString(message, 0) : null;
            send({ tag: 'flutter', event: 'FlutterJNI.invokePlatformMessageResponseCallback', replyId, payload_b64: preview });
            return this.invokePlatformMessageResponseCallback(replyId, message);
        });

    // ── Flutter plugin registry ───────────────────────────────────────
    try {
        const PR = Java.use('io.flutter.embedding.engine.plugins.FlutterPlugin');
        send({ tag: 'flutter', event: 'plugin_registry_available' });
    } catch (_) {}

    send({ tag: 'flutter', event: 'init_complete', status: 'Flutter channel hooks loaded' });
});
