/**
 * Native Hook Helper — Sentinel
 * ==============================
 * Generic native/JNI helper for:
 *   - Finding and hooking exports by name
 *   - By-offset hooks within a known module
 *   - Module enumeration and base address lookup
 *   - Anti-debug bypass (ptrace, IsDebuggerPresent patterns)
 *   - Library load detection (dlopen hooks)
 *
 * Usage:
 *   frida -U -f com.target.app -l native-hook.js
 *   Then call RPC: hookExport(module, export), getBase(module), etc.
 *
 * RPC exports:
 *   listModules()             → array of {name, base, size}
 *   getBase(moduleName)       → base address string or null
 *   listExports(moduleName)   → array of {name, address}
 *   hookExport(mod, exp)      → hook and log calls to named export
 *   hookOffset(mod, offset)   → hook at module_base + offset
 */
'use strict';

// ── Module helpers ────────────────────────────────────────────────────
function listModules() {
    return Process.enumerateModules().map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
}

function getBase(name) {
    const m = Process.findModuleByName(name);
    return m ? m.base.toString() : null;
}

function listExports(modName) {
    const m = Process.findModuleByName(modName);
    if (!m) return [];
    return m.enumerateExports().map(e => ({ name: e.name, address: e.address.toString(), type: e.type }));
}

// ── Generic export hook ───────────────────────────────────────────────
function hookExport(modName, exportName) {
    try {
        const addr = Module.findExportByName(modName, exportName);
        if (!addr) { send({ tag: 'native', event: 'hook_error', reason: 'export not found', mod: modName, exp: exportName }); return false; }
        Interceptor.attach(addr, {
            onEnter(args) { send({ tag: 'native', event: 'call', mod: modName, fn: exportName, arg0: args[0], arg1: args[1], arg2: args[2] }); },
            onLeave(ret)  { send({ tag: 'native', event: 'ret',  mod: modName, fn: exportName, retval: ret }); }
        });
        send({ tag: 'native', event: 'hooked_export', mod: modName, fn: exportName, addr: addr.toString() });
        return true;
    } catch (e) { send({ tag: 'native', event: 'hook_error', mod: modName, fn: exportName, error: e.message }); return false; }
}

// ── By-offset hook ────────────────────────────────────────────────────
function hookOffset(modName, offset) {
    try {
        const base = Process.findModuleByName(modName);
        if (!base) { send({ tag: 'native', event: 'hook_error', reason: 'module not found', mod: modName }); return false; }
        const addr = base.base.add(offset);
        Interceptor.attach(addr, {
            onEnter(args) { send({ tag: 'native', event: 'call_offset', mod: modName, offset, arg0: args[0], arg1: args[1] }); },
            onLeave(ret)  { send({ tag: 'native', event: 'ret_offset',  mod: modName, offset, retval: ret }); }
        });
        send({ tag: 'native', event: 'hooked_offset', mod: modName, offset, addr: addr.toString() });
        return true;
    } catch (e) { send({ tag: 'native', event: 'hook_error', mod: modName, offset, error: e.message }); return false; }
}

// ── dlopen hook — detect library loads at runtime ────────────────────
try {
    const dlopen = Module.findExportByName(null, 'dlopen') || Module.findExportByName('libdl.so', 'dlopen');
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter(args) { this.path = args[0].isNull() ? null : args[0].readCString(); },
            onLeave(ret)  { if (this.path) send({ tag: 'native', event: 'dlopen', path: this.path, handle: ret.toString() }); }
        });
    }
} catch (e) {}

// ── Anti-debug bypass — ptrace self-check ────────────────────────────
try {
    const ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter(args) { this.req = args[0].toInt32(); },
            onLeave(ret) {
                // PTRACE_TRACEME = 0; apps use it to detect debuggers
                if (this.req === 0) { send({ tag: 'native', event: 'ptrace_self_check', spoofing_success: true }); ret.replace(ptr(0)); }
            }
        });
    }
} catch (e) {}

// ── RPC exports ───────────────────────────────────────────────────────
rpc.exports = { listModules, getBase, listExports, hookExport, hookOffset };

send({ tag: 'native', event: 'init_complete', modules: Process.enumerateModules().length });
