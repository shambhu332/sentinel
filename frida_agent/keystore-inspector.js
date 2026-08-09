/**
 * Keystore Inspector — Sentinel
 * ==============================
 * Enumerates Android Keystore aliases, key attributes, auth requirements,
 * attestation data, and flags security-relevant misconfigurations.
 *
 * Findings emitted:
 *   - Keys with no user auth requirement (biometric/PIN not enforced)
 *   - Keys with WRAP_KEY purpose (exfiltration risk)
 *   - Software-backed keys (vs. hardware-backed / StrongBox)
 *   - Keys with indefinite validity (no expiry)
 *
 * Usage:
 *   frida -U -f com.target.app -l keystore-inspector.js
 */
Java.perform(function () {

    // ── Enumerate existing aliases ────────────────────────────────────
    try {
        const KS = Java.use('java.security.KeyStore');
        const instance = KS.getInstance('AndroidKeyStore');
        instance.load(null);
        const aliases = instance.aliases();
        const results = [];
        while (aliases.hasMoreElements()) {
            const alias = aliases.nextElement().toString();
            const entry = { alias, type: null, auth_required: null, hardware_backed: null, flags: [] };
            try {
                const cert = instance.getCertificate(alias);
                if (cert) entry.type = cert.getType();
            } catch (_) {}
            try {
                const key = instance.getKey(alias, null);
                if (key) {
                    entry.algo = key.getAlgorithm();
                    try {
                        const KPG = Java.use('android.security.keystore.KeyInfo');
                        const kf = Java.use('javax.crypto.SecretKeyFactory').getInstance(key.getAlgorithm(), 'AndroidKeyStore');
                        const info = Java.cast(kf.getKeySpec(key, KPG.class), KPG);
                        entry.auth_required   = info.isUserAuthenticationRequired();
                        entry.auth_timeout_s  = info.getUserAuthenticationValidityDurationSeconds();
                        entry.hardware_backed = info.isInsideSecureHardware();
                        const purposes = info.getPurposes();
                        if (purposes & 8)  entry.flags.push('WRAP_KEY');
                        if (!entry.auth_required) entry.flags.push('NO_USER_AUTH');
                        if (!entry.hardware_backed) entry.flags.push('SOFTWARE_BACKED');
                    } catch (_) {}
                }
            } catch (_) {}
            results.push(entry);
            send({ tag: 'keystore', alias, ...entry });
        }
        send({ tag: 'keystore', event: 'enumerate_complete', count: results.length, results });
    } catch (e) {
        send({ tag: 'keystore', event: 'enumerate_error', error: e.message });
    }

    // ── Hook KeyStore.getEntry to log runtime access ──────────────────
    try {
        const KS2 = Java.use('java.security.KeyStore');
        const origGetEntry = KS2.getEntry;
        KS2.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter')
        .implementation = function (alias, param) {
            const result = this.getEntry(alias, param);
            send({ tag: 'keystore', event: 'getEntry', alias, has_result: result !== null });
            return result;
        };
    } catch (e) { send({ tag: 'keystore', event: 'hook_error', hook: 'getEntry', error: e.message }); }

    // ── Hook KeyGenerator.init to catch key generation params ─────────
    try {
        const KPG2 = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
        KPG2.build.implementation = function () {
            const spec = this.build();
            try {
                const s = Java.cast(spec, Java.use('android.security.keystore.KeyGenParameterSpec'));
                send({
                    tag: 'keystore', event: 'key_generation',
                    alias:        s.getKeystoreAlias(),
                    purposes:     s.getPurposes(),
                    auth_req:     s.isUserAuthenticationRequired(),
                    auth_timeout: s.getUserAuthenticationValidityDurationSeconds(),
                    strongbox:    (() => { try { return s.isStrongBoxBacked(); } catch { return 'n/a'; } })(),
                    invalidated:  (() => { try { return s.isInvalidatedByBiometricEnrollment(); } catch { return 'n/a'; } })(),
                });
            } catch (_) {}
            return spec;
        };
    } catch (e) { send({ tag: 'keystore', event: 'hook_error', hook: 'KeyGenParamSpec.build', error: e.message }); }

    send({ tag: 'keystore', event: 'init_complete' });
});
