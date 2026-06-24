/*
 * Sample auto-login hook — Material Design / TextInputLayout variant.
 *
 * Use this template when the target app's login screen uses Google's
 * Material Components (TextInputLayout + TextInputEditText) and a
 * MaterialButton labelled "Sign in" / "Log in" rather than raw
 * findViewById Resources lookups. The widget lookup walks the view
 * tree by class name, which is more robust against ProGuard renames.
 *
 * Same contract as the generic sample:
 *   - globalThis.SENTINEL_AUTH = { username, password }  injected before us.
 *   - send({ event: "auth.ok" })                          on success.
 *   - send({ event: "auth.fail", reason: "..." })         on failure.
 */
(function () {
    function fail(reason) {
        try { send({ event: "auth.fail", reason: String(reason) }); }
        catch (_) {}
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

            // Walk the decor view, collect every TextInputEditText and
            // the first MaterialButton with login-y label.
            var ViewGroup = Java.use("android.view.ViewGroup");
            var TextInputEditText = Java.use(
                "com.google.android.material.textfield.TextInputEditText",
            );
            var MaterialButton = Java.use(
                "com.google.android.material.button.MaterialButton",
            );

            var edits = [];
            var loginBtn = null;
            var loginLabelRe = /sign[\s_-]*in|log[\s_-]*in|continue|next/i;

            function walk(view) {
                if (view === null) return;
                if (Java.cast(view, TextInputEditText) !== null) {
                    edits.push(view);
                }
                if (Java.cast(view, MaterialButton) !== null) {
                    var label = view.getText();
                    if (label !== null && loginLabelRe.test(label.toString())) {
                        if (loginBtn === null) loginBtn = view;
                    }
                }
                if (Java.cast(view, ViewGroup) !== null) {
                    var group = Java.cast(view, ViewGroup);
                    var n = group.getChildCount();
                    for (var i = 0; i < n; i++) walk(group.getChildAt(i));
                }
            }
            walk(activity.getWindow().getDecorView());

            if (edits.length < 2) {
                return fail("expected ≥ 2 TextInputEditText; found " + edits.length);
            }
            if (loginBtn === null) {
                return fail("no MaterialButton labelled sign-in/log-in/continue");
            }

            // Heuristic: the first edit is username, the second password.
            // For apps that flip the order, set ``SENTINEL_AUTH.swap=true``
            // ahead of this script.
            var userIdx = creds.swap ? 1 : 0;
            var passIdx = creds.swap ? 0 : 1;
            var userField = edits[userIdx];
            var passField = edits[passIdx];

            var Looper = Java.use("android.os.Looper");
            var Handler = Java.use("android.os.Handler");
            var handler = Handler.$new(Looper.getMainLooper());

            handler.post(Java.use("java.lang.Runnable").$new({
                run: function () {
                    try {
                        userField.setText(
                            Java.use("java.lang.String").$new(creds.username),
                        );
                        passField.setText(
                            Java.use("java.lang.String").$new(creds.password),
                        );
                        loginBtn.performClick();
                    } catch (e) {
                        fail("UI driver crash: " + e.message);
                    }
                },
            }));

            // Success heuristic: the login activity finishes within 5s.
            // Apps that just swap fragments need a custom hook script.
            var startName = activity.getClass().getName();
            var attempts = 0;
            var poll = setInterval(function () {
                attempts++;
                try {
                    var keys2 = activities.keySet().toArray();
                    var stillSame = false;
                    for (var i = 0; i < keys2.length; i++) {
                        var rec = activities.get(keys2[i]);
                        if (rec.paused.value === false) {
                            if (rec.activity.value.getClass().getName() === startName) {
                                stillSame = true;
                            }
                            break;
                        }
                    }
                    if (!stillSame) {
                        clearInterval(poll);
                        return ok();
                    }
                } catch (_) {}
                if (attempts >= 50) {
                    clearInterval(poll);
                    fail("login activity still on screen after 5s");
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
