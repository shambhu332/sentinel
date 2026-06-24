/*
 * Sample auto-login hook for SENTINEL's CredentialManager.
 *
 * Contract
 * --------
 * SENTINEL injects, ahead of this file, a global:
 *     globalThis.SENTINEL_AUTH = { username: "...", password: "..." }
 *
 * The script must signal completion exactly once via:
 *     send({ event: "auth.ok" })                          // success
 *     send({ event: "auth.fail", reason: "..." })         // failure
 *
 * Any uncaught exception or absence of a signal within
 * CredentialManager.auto_login()'s timeout is treated as auth_gated —
 * the dispatcher then routes the finding to the Auth-Gated bucket
 * with an LLM-generated severity rationale.
 *
 * This file is a generic template targeting the
 * "com.example.app" toy login screen (resource IDs username,
 * password, login_btn, home_root). Copy it to
 *     frida_agent/login_scripts/<your.package.name>.js
 * and adapt the lookups for the real app.
 */
(function () {
    function fail(reason) {
        try { send({ event: "auth.fail", reason: String(reason) }); }
        catch (_) { /* nothing we can do */ }
    }

    function ok() {
        try { send({ event: "auth.ok" }); } catch (_) {}
    }

    function run() {
        var creds = globalThis.SENTINEL_AUTH || {};
        if (!creds.username || !creds.password) {
            return fail("SENTINEL_AUTH not populated");
        }

        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var current = ActivityThread.currentActivityThread();
            var app = current.getApplication();
            if (app === null) return fail("application context unavailable");

            // Resolve the foreground Activity.
            var activities = current.mActivities.value;
            var activity = null;
            var keys = activities.keySet().toArray();
            for (var i = 0; i < keys.length; i++) {
                var record = activities.get(keys[i]);
                if (record.paused.value === false) {
                    activity = record.activity.value;
                    break;
                }
            }
            if (activity === null) return fail("no resumed activity");

            var EditText = Java.use("android.widget.EditText");
            var Button = Java.use("android.widget.Button");
            var resources = activity.getResources();
            var pkg = activity.getPackageName();

            function findById(name, klass) {
                var id = resources.getIdentifier(name, "id", pkg);
                if (id === 0) return null;
                var view = activity.findViewById(id);
                return view === null ? null : Java.cast(view, klass);
            }

            var userField = findById("username", EditText);
            var passField = findById("password", EditText);
            var loginBtn  = findById("login_btn", Button);
            if (!userField || !passField || !loginBtn) {
                return fail("login form widgets not found");
            }

            var Looper = Java.use("android.os.Looper");
            var Handler = Java.use("android.os.Handler");
            var handler = Handler.$new(Looper.getMainLooper());

            handler.post(Java.use("java.lang.Runnable").$new({
                run: function () {
                    try {
                        userField.setText(Java.use("java.lang.String").$new(creds.username));
                        passField.setText(Java.use("java.lang.String").$new(creds.password));
                        loginBtn.performClick();
                    } catch (e) {
                        fail("UI driver crash: " + e.message);
                    }
                },
            }));

            // Poll for the post-login screen marker.
            var attempts = 0;
            var poll = setInterval(function () {
                attempts++;
                try {
                    var homeId = resources.getIdentifier("home_root", "id", pkg);
                    if (homeId !== 0 && activity.findViewById(homeId) !== null) {
                        clearInterval(poll);
                        return ok();
                    }
                } catch (_) {}
                if (attempts >= 40) { // ~4 s @ 100 ms
                    clearInterval(poll);
                    fail("post-login marker (home_root) never appeared");
                }
            }, 100);
        } catch (e) {
            fail("hook setup crashed: " + e.message);
        }
    }

    if (typeof Java !== "undefined" && Java.available) {
        Java.perform(run);
    } else {
        var attempts = 0;
        var poll = setInterval(function () {
            attempts++;
            if (typeof Java !== "undefined" && Java.available) {
                clearInterval(poll);
                Java.perform(run);
            } else if (attempts >= 30) {
                clearInterval(poll);
                fail("Java bridge unavailable after 3s");
            }
        }, 100);
    }
})();
