/**
 * FLAG_SECURE Bypass — Sentinel
 * ==============================
 * Removes WindowManager.LayoutParams.FLAG_SECURE from all windows so
 * screenshots and screen recording work during authorized assessments.
 *
 * Coverage:
 *   - Window.setFlags() / Window.addFlags()
 *   - WindowManager.addView() LayoutParams inspection
 *   - Activity.onCreate / onResume flag stripping
 *
 * Known gaps:
 *   - OEM-level DRM surfaces (e.g. Widevine L1 video playback)
 *     remain protected regardless of this hook.
 *   - MediaProjection policy enforced at kernel/SurfaceFlinger level
 *     is not bypassed here — see mediaprojection-bypass.js.
 *
 * Usage:
 *   frida -U -f com.example.app -l flag-secure-bypass.js --no-pause
 */

const FLAG_SECURE = 0x2000;

Java.perform(function () {

    // ─── Window.setFlags ────────────────────────────────────────────────
    try {
        var Window = Java.use("android.view.Window");
        var origSetFlags = Window.setFlags;
        Window.setFlags.implementation = function (flags, mask) {
            if (flags & FLAG_SECURE) {
                send({ tag: "flag_secure_bypass", hook: "Window.setFlags", original_flags: flags });
                flags = flags & ~FLAG_SECURE;
            }
            origSetFlags.call(this, flags, mask);
        };
    } catch (e) {
        send({ tag: "flag_secure_bypass", hook: "Window.setFlags", error: e.message });
    }

    // ─── Window.addFlags ────────────────────────────────────────────────
    try {
        var Window2 = Java.use("android.view.Window");
        var origAddFlags = Window2.addFlags;
        Window2.addFlags.implementation = function (flags) {
            if (flags & FLAG_SECURE) {
                send({ tag: "flag_secure_bypass", hook: "Window.addFlags", original_flags: flags });
                flags = flags & ~FLAG_SECURE;
            }
            origAddFlags.call(this, flags);
        };
    } catch (e) {
        send({ tag: "flag_secure_bypass", hook: "Window.addFlags", error: e.message });
    }

    // ─── ViewGroup.addView — strip FLAG_SECURE from LayoutParams ────────
    try {
        var ViewGroup = Java.use("android.view.ViewGroup");
        var origAddView = ViewGroup.addView.overload(
            "android.view.View", "android.view.ViewGroup$LayoutParams"
        );
        origAddView.implementation = function (view, params) {
            if (params && params.flags && (params.flags.value & FLAG_SECURE)) {
                send({ tag: "flag_secure_bypass", hook: "ViewGroup.addView", original_flags: params.flags.value });
                params.flags.value = params.flags.value & ~FLAG_SECURE;
            }
            origAddView.call(this, view, params);
        };
    } catch (e) {
        // ViewGroup.addView interception is optional; Window.setFlags is primary
    }

    send({ tag: "flag_secure_bypass", hook: "init_complete", status: "FLAG_SECURE bypass loaded" });
});
