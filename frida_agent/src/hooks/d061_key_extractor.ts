/*
 * D_061 — Memory key extractor.
 *
 * Hooks SecretKeySpec.<init> and Cipher.init; on each call dumps the
 * key bytes (capped to max_bytes_per_key) and the algorithm name.
 * Reports back as base64 — the agent decodes server-side.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface KeyDump {
    algorithm: string;
    b64_first_bytes: string;
    length: number;
    site: string;
}

interface KeyExtractResult {
    dumps: KeyDump[];
    duration_ms: number;
}

async function keyextractor(
    payload: { max_bytes_per_key?: number; safety_budget?: any },
): Promise<KeyExtractResult> {
    const cap = Math.min(payload.max_bytes_per_key ?? 256, 1024);
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 60;
    const dumps: KeyDump[] = [];
    const start = Date.now();

    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                const Base64 = Java.use("android.util.Base64");
                SecretKeySpec.$init.overload(
                    "[B", "java.lang.String",
                ).implementation = function (keyBytes: any, algo: any) {
                    try {
                        const truncated = Java.array("byte",
                            Array.from(keyBytes).slice(0, cap) as any,
                        );
                        dumps.push({
                            algorithm: String(algo),
                            b64_first_bytes: Base64.encodeToString(truncated, 0),
                            length: keyBytes.length,
                            site: "SecretKeySpec<init>",
                        });
                    } catch (_) { /* ignore */ }
                    return this.$init(keyBytes, algo);
                };
                const Cipher = Java.use("javax.crypto.Cipher");
                Cipher.init.overload(
                    "int", "java.security.Key",
                ).implementation = function (mode: any, key: any) {
                    try {
                        if (key.getEncoded) {
                            const enc = key.getEncoded();
                            if (enc) {
                                const t = Java.array("byte",
                                    Array.from(enc).slice(0, cap) as any,
                                );
                                dumps.push({
                                    algorithm: String(key.getAlgorithm()),
                                    b64_first_bytes: Base64.encodeToString(t, 0),
                                    length: enc.length,
                                    site: "Cipher.init",
                                });
                            }
                        }
                    } catch (_) { /* ignore */ }
                    return this.init(mode, key);
                };
            } catch (e: any) {
                sendError(`D_061: ${e.message}`);
            }
            setTimeout(() => resolve({
                dumps: dumps.slice(0, 50),
                duration_ms: Date.now() - start,
            }), window_s * 1000);
        });
    });
}

rpc.exports = { keyextractor };
