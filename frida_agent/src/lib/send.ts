/*
 * Typed wrappers around Frida's global `send()`. Every event passes
 * through one of these helpers so the Python side gets a consistent
 * payload shape. Each helper enforces a discriminated 'kind' field
 * and structured payload, making the orchestrator's event parsing
 * resilient to refactors here.
 */

export function sendCipher(algorithm: string, provider?: string, overload?: string): void {
    send({ kind: "crypto.cipher", algorithm, provider, overload });
}

export function sendDigest(algorithm: string): void {
    send({ kind: "crypto.digest", algorithm });
}

export function sendKeygen(algorithm: string): void {
    send({ kind: "crypto.keygen", algorithm });
}

export function sendMac(algorithm: string): void {
    send({ kind: "crypto.mac", algorithm });
}

export function sendSecureRandom(variant: string): void {
    send({ kind: "crypto.secure_random", variant });
}

export function sendSecretKeyFactory(algorithm: string): void {
    send({ kind: "crypto.secret_key_factory", algorithm });
}

export function sendKeyPairGenerator(algorithm: string): void {
    send({ kind: "crypto.keypair_generator", algorithm });
}

export function sendCryptoHooksInstalled(count: number, fallback?: boolean): void {
    send({ kind: "crypto.hooks_installed", count, fallback });
}

export interface BypassEvent {
    library: string;
    method: string;
    host?: string;
    extra?: Record<string, unknown>;
}

export function sendBypass(e: BypassEvent): void {
    send({ kind: "tls.bypass", ...e });
}

export function sendBypassFailed(library: string, error: string): void {
    send({ kind: "tls.bypass_failed", library, error });
}

export function sendHooksSummary(summary: {
    attempted: string[];
    succeeded: string[];
    failed: { library: string; reason: string }[];
    subclass_hooks_added: number;
    native_hooks_added: number;
}): void {
    send({ kind: "tls.hooks_summary", ...summary });
}

export function sendError(message: string): void {
    send({ kind: "error", message });
}
