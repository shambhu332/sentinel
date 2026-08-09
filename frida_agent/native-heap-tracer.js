/**
 * Native Heap Tracer — Sentinel
 * ==============================
 * Traces malloc, calloc, realloc, free with optional call stacks.
 * Useful for: memory corruption triage, UAF detection, heap spray analysis.
 *
 * CONFIG.targetLib: restrict tracing to allocations from a specific .so.
 *                   Empty = trace all (very noisy — use targetLib in practice).
 * CONFIG.minSize:   ignore allocations smaller than this (bytes).
 * CONFIG.captureStack: emit backtrace with each event (slower).
 *
 * Usage:
 *   frida -U -f com.target.app -l native-heap-tracer.js
 *
 * Note: At high allocation rates this will flood the Frida channel.
 *       Always set targetLib or minSize to reduce noise.
 */
'use strict';

const CONFIG = {
    targetLib:    '',       // e.g. 'libnative.so' — empty = all
    minSize:      64,       // ignore tiny allocs
    captureStack: false,    // enable for UAF / overflow triage
    maxEvents:    5000,     // hard cap before auto-disabling
};

let eventCount = 0;
const liveAllocs = new Map();

function shouldTrace(returnAddr) {
    if (!CONFIG.targetLib) return true;
    const m = Process.findModuleByAddress(returnAddr);
    return m && m.name.includes(CONFIG.targetLib);
}

function stack() {
    if (!CONFIG.captureStack) return null;
    try { return Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6).map(a => DebugSymbol.fromAddress(a).toString()); }
    catch { return null; }
}

function emit(event) {
    if (++eventCount > CONFIG.maxEvents) {
        if (eventCount === CONFIG.maxEvents + 1) send({ tag: 'heap', event: 'cap_reached', limit: CONFIG.maxEvents });
        return;
    }
    send({ tag: 'heap', ...event });
}

// ── malloc ────────────────────────────────────────────────────────────
const mallocPtr = Module.findExportByName('libc.so', 'malloc');
if (mallocPtr) {
    Interceptor.attach(mallocPtr, {
        onEnter(args) { this.size = args[0].toUInt32(); this.ra = this.returnAddress; },
        onLeave(ret) {
            if (this.size < CONFIG.minSize || !shouldTrace(this.ra)) return;
            const addr = ret.toString();
            liveAllocs.set(addr, { size: this.size, at: Date.now() });
            emit({ event: 'malloc', size: this.size, addr, stack: stack.call(this) });
        }
    });
}

// ── calloc ────────────────────────────────────────────────────────────
const callocPtr = Module.findExportByName('libc.so', 'calloc');
if (callocPtr) {
    Interceptor.attach(callocPtr, {
        onEnter(args) { this.count = args[0].toUInt32(); this.size = args[1].toUInt32(); this.ra = this.returnAddress; },
        onLeave(ret) {
            const total = this.count * this.size;
            if (total < CONFIG.minSize || !shouldTrace(this.ra)) return;
            const addr = ret.toString();
            liveAllocs.set(addr, { size: total, at: Date.now() });
            emit({ event: 'calloc', count: this.count, size: this.size, total, addr });
        }
    });
}

// ── realloc ───────────────────────────────────────────────────────────
const reallocPtr = Module.findExportByName('libc.so', 'realloc');
if (reallocPtr) {
    Interceptor.attach(reallocPtr, {
        onEnter(args) { this.oldPtr = args[0].toString(); this.newSize = args[1].toUInt32(); this.ra = this.returnAddress; },
        onLeave(ret) {
            if (this.newSize < CONFIG.minSize || !shouldTrace(this.ra)) return;
            const newAddr = ret.toString();
            const old = liveAllocs.get(this.oldPtr);
            liveAllocs.delete(this.oldPtr);
            liveAllocs.set(newAddr, { size: this.newSize, at: Date.now() });
            emit({ event: 'realloc', old_addr: this.oldPtr, old_size: old?.size, new_addr: newAddr, new_size: this.newSize });
        }
    });
}

// ── free ──────────────────────────────────────────────────────────────
const freePtr = Module.findExportByName('libc.so', 'free');
if (freePtr) {
    Interceptor.attach(freePtr, {
        onEnter(args) {
            const addr = args[0].toString();
            const alloc = liveAllocs.get(addr);
            if (alloc) {
                liveAllocs.delete(addr);
                if (alloc.size >= CONFIG.minSize && shouldTrace(this.returnAddress))
                    emit({ event: 'free', addr, size: alloc.size, lifetime_ms: Date.now() - alloc.at });
            }
        }
    });
}

// ── RPC ───────────────────────────────────────────────────────────────
rpc.exports = {
    liveAllocCount: () => liveAllocs.size,
    eventCount: () => eventCount,
    setConfig: (k, v) => { CONFIG[k] = v; return true; },
};

send({ tag: 'heap', event: 'init_complete', config: CONFIG });
