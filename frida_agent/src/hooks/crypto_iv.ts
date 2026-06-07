/*
 * Crypto IV + SecretKey observation hooks (D_006).
 *
 * We hash the raw bytes on the device with SHA-256 and only ship the
 * first 16 hex characters. The hash gives the Python agent a stable
 * identity for "same bytes seen again" without ever exfiltrating
 * actual key or IV material.
 *
 * Hooks:
 *   javax.crypto.spec.IvParameterSpec.<init>(byte[])
 *   javax.crypto.spec.GCMParameterSpec.<init>(int, byte[])
 *   javax.crypto.spec.SecretKeySpec.<init>(byte[], String)
 */
import { Java } from "../lib/java_ready.js";
import {
    sendIvConstructed,
    sendSecretKeyCreated,
    sendError,
} from "../lib/send.js";

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 4; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

function sha256Prefix(bytes: any): string {
    try {
        const MD = Java.use("java.security.MessageDigest");
        const md = MD.getInstance("SHA-256");
        md.update(bytes);
        const digest = md.digest();
        // 8 bytes = 16 hex chars — enough to distinguish ~4 billion values.
        let s = "";
        for (let i = 0; i < 8 && i < digest.length; i++) {
            const b = digest[i] & 0xFF;
            s += (b < 16 ? "0" : "") + b.toString(16);
        }
        return s;
    } catch (_) { return ""; }
}

function constantPattern(bytes: any): string | undefined {
    try {
        const len = bytes.length;
        if (len === 0) return undefined;
        const b0 = bytes[0] & 0xFF;
        if (b0 === 0x00) {
            for (let i = 1; i < len; i++) {
                if ((bytes[i] & 0xFF) !== 0) return undefined;
            }
            return "zero";
        }
        if (b0 === 0xFF) {
            for (let i = 1; i < len; i++) {
                if ((bytes[i] & 0xFF) !== 0xFF) return undefined;
            }
            return "ff";
        }
        // All-ASCII printable + non-trivial repetition heuristic
        if (b0 >= 0x20 && b0 <= 0x7E) {
            for (let i = 1; i < len; i++) {
                const c = bytes[i] & 0xFF;
                if (c < 0x20 || c > 0x7E) return undefined;
            }
            return "ascii_const";
        }
    } catch (_) { /* swallow */ }
    return undefined;
}

export function installCryptoIvHooks(): number {
    let installed = 0;

    // ---- IvParameterSpec ----
    try {
        const Iv = Java.use("javax.crypto.spec.IvParameterSpec");
        Iv.$init.overload("[B").implementation = function (bytes: any) {
            try {
                if (bytes && bytes.length > 0) {
                    sendIvConstructed({
                        algorithm: "IvParameterSpec",
                        iv_hex: sha256Prefix(bytes),
                        iv_len: bytes.length,
                        constant_pattern: constantPattern(bytes),
                        stack: shortStack(),
                    });
                }
            } catch (e) {
                sendError(`crypto.iv hook: ${String(e)}`);
            }
            return this.$init(bytes);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- GCMParameterSpec ----
    try {
        const GCM = Java.use("javax.crypto.spec.GCMParameterSpec");
        GCM.$init.overload("int", "[B").implementation = function (
            tlen: number, bytes: any,
        ) {
            try {
                if (bytes && bytes.length > 0) {
                    sendIvConstructed({
                        algorithm: "GCMParameterSpec",
                        iv_hex: sha256Prefix(bytes),
                        iv_len: bytes.length,
                        constant_pattern: constantPattern(bytes),
                        stack: shortStack(),
                    });
                }
            } catch (e) {
                sendError(`crypto.gcm hook: ${String(e)}`);
            }
            return this.$init(tlen, bytes);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- SecretKeySpec ----
    try {
        const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B", "java.lang.String").implementation = function (
            bytes: any, algorithm: string,
        ) {
            try {
                if (bytes && bytes.length > 0) {
                    sendSecretKeyCreated({
                        algorithm: String(algorithm),
                        key_hex: sha256Prefix(bytes),
                        key_len: bytes.length,
                        stack: shortStack(),
                    });
                }
            } catch (e) {
                sendError(`crypto.sks hook: ${String(e)}`);
            }
            return this.$init(bytes, algorithm);
        };
        installed++;
    } catch (_) { /* skip */ }

    return installed;
}
