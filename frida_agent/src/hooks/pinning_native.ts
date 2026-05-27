/*
 * Native-side TLS observation hooks.
 *
 * Apps that use Cronet, Flutter, React Native, or any NDK networking
 * call into libssl directly and never touch javax.net.ssl. Java hooks
 * are blind to those flows. This module attaches to libssl exports
 * via Frida's Interceptor so we can at least observe (and, where it's
 * safe, force) the verify mode.
 *
 * SSL_CTX_set_verify(SSL_CTX *ctx, int mode, callback)
 * SSL_set_verify(SSL *ssl, int mode, callback)
 *   mode = 0 (SSL_VERIFY_NONE) disables peer cert verification.
 *   We log every call and rewrite the mode argument to 0 so even
 *   apps that explicitly request SSL_VERIFY_PEER end up doing no
 *   verification — the classic native-bypass technique used by
 *   pentesters against Cronet/BoringSSL.
 *
 * Also probes libboringssl.so and libcrypto.so since some Android
 * versions split the symbols across those libraries.
 */

declare const Module: any;
declare const Interceptor: any;
declare const ptr: any;
declare function send(payload: any): void;

interface NativeTarget {
    library: string;
    symbol: string;
}

const TARGETS: NativeTarget[] = [
    { library: "libssl.so",       symbol: "SSL_CTX_set_verify" },
    { library: "libssl.so",       symbol: "SSL_set_verify"     },
    { library: "libboringssl.so", symbol: "SSL_CTX_set_verify" },
    { library: "libboringssl.so", symbol: "SSL_set_verify"     },
    { library: "libcrypto.so",    symbol: "SSL_CTX_set_verify" },
];

export function installNativeHooks(): number {
    let count = 0;

    TARGETS.forEach((t) => {
        let addr: any = null;
        try {
            addr = Module.findExportByName(t.library, t.symbol);
        } catch {
            // Module not loaded — skip
            return;
        }
        if (!addr) return;

        // Label drops the .so suffix for readability and to match the
        // canonical `libssl.SSL_CTX_set_verify` form used elsewhere.
        const labelBase = t.library.replace(/\.so$/, "");
        const label = `${labelBase}.${t.symbol}`;

        try {
            Interceptor.attach(addr, {
                onEnter(this: any, args: any) {
                    let originalMode = -1;
                    try { originalMode = args[1].toInt32(); } catch { /* */ }
                    send({
                        kind: "tls.bypass",
                        library: label,
                        method: "native_intercept",
                        extra: { original_mode: originalMode },
                    });
                    // Force SSL_VERIFY_NONE
                    try { args[1] = ptr("0"); } catch { /* */ }
                },
            });
            count++;
        } catch (e) {
            send({
                kind: "tls.bypass_failed",
                library: label,
                error: String(e),
            });
        }
    });

    return count;
}
