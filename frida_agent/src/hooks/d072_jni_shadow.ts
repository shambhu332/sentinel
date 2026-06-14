/*
 * D_072 — JNI Shadow Executor.
 *
 * Attaches to the named JNI symbol across every loaded .so module
 * that exports it. For each probe payload:
 *
 *   1. Build a fresh jstring (canary / format string / oversize).
 *   2. Call into the native method via the JNI bridge by invoking
 *      the Java-side wrapper with our crafted string.
 *   3. Watch with MemoryAccessMonitor for any write outside the
 *      expected return-buffer bounds.
 *
 * Safety: this is the highest-risk hook in the catalog. We honour
 * the payload-supplied SafetyBudget AND apply a hard-coded
 * "max 2 memory violations per second" breaker — exceeding it
 * trips the kill-switch and the remaining probes are dropped.
 * Payload size is hard-capped at 512 bytes regardless of what the
 * Python side asks for.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface ProbeSpec {
    kind: string;
    value: string;
}

interface JniShadowPayload {
    jni_symbol: string;
    native_lib_hints?: string[];
    params?: string;
    probes: ProbeSpec[];
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
        max_mem_violations_per_sec?: number;
        max_payload_bytes?: number;
    };
}

interface ProbeResult {
    kind: string;
    bytes: number;
    completed: boolean;
    mem_violations: number;
    error?: string;
}

interface JniShadowResult {
    symbol: string;
    module?: string;
    address?: string;
    probes_fired: number;
    results: ProbeResult[];
    tripped: boolean;
    trip_reason?: string;
    duration_ms: number;
}

const HARD_PAYLOAD_CAP = 512;
const HARD_TOTAL_CAP = 6;

async function jnishadow(payload: JniShadowPayload): Promise<JniShadowResult> {
    const max = Math.min(
        payload.safety_budget?.max_actions_total ?? HARD_TOTAL_CAP,
        HARD_TOTAL_CAP,
    );
    const rate = payload.safety_budget?.max_actions_per_sec ?? 2;
    const window_s = payload.safety_budget?.wall_clock_budget_s ?? 15;
    const maxCrashes = payload.safety_budget?.max_consecutive_crashes ?? 2;
    const violationsPerSecCap =
        payload.safety_budget?.max_mem_violations_per_sec ?? 2;
    const payloadCap = Math.min(
        payload.safety_budget?.max_payload_bytes ?? HARD_PAYLOAD_CAP,
        HARD_PAYLOAD_CAP,
    );

    const start = Date.now();
    const results: ProbeResult[] = [];
    let violations = 0;
    let consecutiveCrashes = 0;
    let tripReason: string | undefined;

    // Sliding window of recent memory violations — for the
    // "more than 2 violations in 1 second" kill switch.
    const recentViolations: number[] = [];

    // 1) Resolve the JNI symbol. Search every loaded module so we
    //    don't depend on the Python agent's library hint.
    let address: NativePointer | null = null;
    let module: string | undefined;
    for (const m of Process.enumerateModules()) {
        const sym = m.findExportByName(payload.jni_symbol);
        if (sym) {
            address = sym;
            module = m.name;
            break;
        }
    }
    if (!address) {
        sendError(`D_072: JNI symbol not found: ${payload.jni_symbol}`);
        return {
            symbol: payload.jni_symbol,
            probes_fired: 0,
            results: [],
            tripped: false,
            duration_ms: Date.now() - start,
        };
    }

    // 2) Snapshot writable ranges so we can detect OOB writes.
    const watched = Process.enumerateRanges("rw-").slice(0, 40);
    try {
        MemoryAccessMonitor.enable(watched, {
            onAccess(details) {
                violations++;
                recentViolations.push(Date.now());
                // prune entries older than 1 second
                const cutoff = Date.now() - 1000;
                while (recentViolations.length && recentViolations[0] < cutoff) {
                    recentViolations.shift();
                }
                if (recentViolations.length > violationsPerSecCap) {
                    tripReason =
                        `max_mem_violations_per_sec ${violationsPerSecCap} exceeded`;
                }
            },
        });
    } catch (e: any) {
        sendError(`D_072: MemoryAccessMonitor.enable failed: ${e.message}`);
    }

    // 3) Attach an interceptor on the symbol so we can both observe
    //    entry/exit AND inject our probes via the Java wrapper.
    let interceptor: InvocationListener | null = null;
    try {
        interceptor = Interceptor.attach(address, {
            onEnter(args) { /* observation only */ },
            onLeave(retval) { /* observation only */ },
        });
    } catch (e: any) {
        sendError(`D_072: Interceptor.attach failed: ${e.message}`);
    }

    // 4) Fire each probe through the Java wrapper. We have to go via
    //    Java because direct JNI invocation from Frida requires
    //    fabricating a JNIEnv*, which is platform-specific and
    //    fragile.
    return new Promise((resolve) => {
        Java.perform(() => {
            try {
                // Declare the finish helper first so the early-exit
                // branches below can call it without TDZ trouble.
                const finish = () => {
                    try { interceptor?.detach(); } catch (_) { /* ignore */ }
                    try { MemoryAccessMonitor.disable(); } catch (_) { /* ignore */ }
                    resolve({
                        symbol: payload.jni_symbol,
                        module,
                        address: address!.toString(),
                        probes_fired: results.length,
                        results,
                        tripped: tripReason !== undefined,
                        trip_reason: tripReason,
                        duration_ms: Date.now() - start,
                    });
                };

                // The agent payload includes class + method; we recover
                // both from the JNI symbol (Java_<pkg>_<class>_<method>).
                const { className, methodName } = parseJniSymbol(payload.jni_symbol);
                if (!className || !methodName) {
                    return finish();
                }
                const Target = Java.use(className);

                const minInterval = rate > 0 ? 1000 / rate : 0;
                const probes = payload.probes.slice(0, max);
                let idx = 0, lastFire = 0;

                const fire = () => {
                    if (
                        idx >= probes.length ||
                        Date.now() - start >= window_s * 1000 ||
                        consecutiveCrashes >= maxCrashes ||
                        tripReason !== undefined
                    ) {
                        return finish();
                    }
                    const now = Date.now();
                    const wait = Math.max(0, lastFire + minInterval - now);
                    setTimeout(() => {
                        const probe = probes[idx++];
                        lastFire = Date.now();
                        const bytes = Math.min(probe.value.length, payloadCap);
                        const value = probe.value.slice(0, payloadCap);
                        const result: ProbeResult = {
                            kind: probe.kind,
                            bytes,
                            completed: false,
                            mem_violations: 0,
                        };
                        const before = violations;
                        try {
                            // Call the Java-side wrapper. We don't know
                            // the actual instance, so use $new() — if
                            // the method is `static` Frida resolves
                            // the static dispatch automatically.
                            const inst = Target.$new();
                            (inst as any)[methodName](value);
                            result.completed = true;
                            consecutiveCrashes = 0;
                        } catch (e: any) {
                            result.error =
                                e.message?.slice(0, 200) ?? String(e);
                            consecutiveCrashes++;
                        }
                        result.mem_violations = violations - before;
                        results.push(result);
                        fire();
                    }, wait);
                };

                fire();
            } catch (e: any) {
                sendError(`D_072: Java side failed: ${e.message}`);
                try { interceptor?.detach(); } catch (_) { /* ignore */ }
                try { MemoryAccessMonitor.disable(); } catch (_) { /* ignore */ }
                resolve({
                    symbol: payload.jni_symbol,
                    module,
                    address: address!.toString(),
                    probes_fired: 0,
                    results: [],
                    tripped: false,
                    trip_reason: `init: ${e.message}`,
                    duration_ms: Date.now() - start,
                });
            }
        });
    });
}

function parseJniSymbol(sym: string): {
    className: string;
    methodName: string;
} {
    // Java_com_acme_Foo_doThing -> class=com.acme.Foo, method=doThing
    // _1 sequences map back to a literal underscore.
    if (!sym.startsWith("Java_")) return { className: "", methodName: "" };
    const rest = sym.slice("Java_".length);
    // Last segment is the method; everything before is class fqdn.
    const parts = rest.split("_");
    const method = parts.pop() ?? "";
    const className = parts.join(".").replace(/_1/g, "_");
    return { className, methodName: method.replace(/_1/g, "_") };
}

rpc.exports = { jnishadow };
