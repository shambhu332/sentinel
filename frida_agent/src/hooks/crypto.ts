/*
 * Crypto observation hooks — ported from the legacy
 * CIPHER_GETINSTANCE_HOOK string in frida_runner.py, plus new
 * coverage for Mac (HMAC), SecureRandom, SecretKeyFactory, and
 * KeyPairGenerator.
 *
 * Every hook is wrapped in try/catch so a missing class (e.g. a
 * shrunken-out KeyGenerator) only skips that one hook rather than
 * aborting the whole crypto group.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendCipher,
    sendDigest,
    sendKeygen,
    sendMac,
    sendSecureRandom,
    sendSecretKeyFactory,
    sendKeyPairGenerator,
    sendCryptoHooksInstalled,
    sendError,
} from "../lib/send.js";

export interface HookResult {
    attempted: string[];
    succeeded: string[];
    failed: { library: string; reason: string }[];
}

function tryHook(result: HookResult, label: string, fn: () => void): void {
    result.attempted.push(label);
    try {
        fn();
        result.succeeded.push(label);
    } catch (e) {
        const msg = String(e);
        if (msg.indexOf("ClassNotFoundException") !== -1) {
            // Class absent on this app — not a failure, just skip
            return;
        }
        result.failed.push({ library: label, reason: msg });
    }
}

export function installCryptoHooks(result: HookResult): void {
    let installedCount = 0;

    tryHook(result, "crypto.Cipher", () => {
        const Cipher = Java.use("javax.crypto.Cipher");

        Cipher.getInstance.overload("java.lang.String").implementation =
            function (this: any, t: string) {
                sendCipher(t, undefined, "string");
                return this.getInstance(t);
            };

        Cipher.getInstance.overload(
            "java.lang.String", "java.lang.String",
        ).implementation = function (this: any, t: string, p: string) {
            sendCipher(t, p, "string_string");
            return this.getInstance(t, p);
        };

        Cipher.getInstance.overload(
            "java.lang.String", "java.security.Provider",
        ).implementation = function (this: any, t: string, p: any) {
            sendCipher(t, p ? p.getName() : "null", "string_provider");
            return this.getInstance(t, p);
        };

        installedCount += 3;
    });

    tryHook(result, "crypto.MessageDigest", () => {
        const MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation =
            function (this: any, a: string) {
                sendDigest(a);
                return this.getInstance(a);
            };
        installedCount += 1;
    });

    tryHook(result, "crypto.KeyGenerator", () => {
        const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.getInstance.overload("java.lang.String").implementation =
            function (this: any, a: string) {
                sendKeygen(a);
                return this.getInstance(a);
            };
        installedCount += 1;
    });

    tryHook(result, "crypto.Mac", () => {
        const Mac = Java.use("javax.crypto.Mac");
        Mac.getInstance.overload("java.lang.String").implementation =
            function (this: any, a: string) {
                sendMac(a);
                return this.getInstance(a);
            };
        installedCount += 1;
    });

    tryHook(result, "crypto.SecureRandom", () => {
        const SecureRandom = Java.use("java.security.SecureRandom");
        SecureRandom.$init.overload().implementation = function (this: any) {
            sendSecureRandom("default");
            return this.$init();
        };
        try {
            SecureRandom.$init.overload("[B").implementation =
                function (this: any, seed: any) {
                    sendSecureRandom("seeded");
                    return this.$init(seed);
                };
        } catch {
            // overload may be absent on stripped builds
        }
        installedCount += 1;
    });

    tryHook(result, "crypto.SecretKeyFactory", () => {
        const SecretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
        SecretKeyFactory.getInstance.overload("java.lang.String").implementation =
            function (this: any, a: string) {
                sendSecretKeyFactory(a);
                return this.getInstance(a);
            };
        installedCount += 1;
    });

    tryHook(result, "crypto.KeyPairGenerator", () => {
        const KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
        KeyPairGenerator.getInstance.overload("java.lang.String").implementation =
            function (this: any, a: string) {
                sendKeyPairGenerator(a);
                return this.getInstance(a);
            };
        installedCount += 1;
    });

    try {
        sendCryptoHooksInstalled(installedCount);
    } catch (e) {
        sendError(`crypto summary: ${String(e)}`);
    }
}
