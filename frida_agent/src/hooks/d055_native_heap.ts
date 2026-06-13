/*
 * D_055 — Native heap memory-safety monitor.
 *
 * Registers a Process.setExceptionHandler that intercepts SIGSEGV /
 * SIGABRT / SIGBUS, captures the crash context (program counter,
 * stack-pointer, top 20 frames), and reports back. Also enumerates
 * each .so module's writable segments so the agent can correlate
 * crash addresses to library names.
 */

import { sendError } from "../lib/send.js";

interface HeapPayload {
    monitor_segments?: string;
    hook_signals?: string[];
    capture_stack_frames?: number;
    window_seconds?: number;
    safety_budget?: any;
}
interface HeapResult {
    modules: { name: string; base: string; size: number }[];
    crashes: {
        signal: string;
        pc: string;
        stack: string[];
        in_module?: string;
    }[];
    duration_ms: number;
}

async function nativeheap(payload: HeapPayload): Promise<HeapResult> {
    const window_s = payload.window_seconds ?? 60;
    const frames = payload.capture_stack_frames ?? 20;
    const crashes: any[] = [];
    const start = Date.now();

    const modules = Process.enumerateModules()
        .filter((m) => m.path.endsWith(".so"))
        .map((m) => ({
            name: m.name, base: m.base.toString(), size: m.size,
        }));

    Process.setExceptionHandler((details) => {
        try {
            const ctx = details.context as any;
            const pc = (ctx.pc ?? ctx.rip ?? ctx.eip ?? NULL).toString();
            const stack = Thread.backtrace(
                details.context, Backtracer.ACCURATE,
            )
                .slice(0, frames)
                .map((a) => a.toString());
            const mod = modules.find((m) => {
                const base = ptr(m.base);
                return pc >= base.toString() &&
                       ptr(pc).compare(base.add(m.size)) < 0;
            });
            crashes.push({
                signal: details.type,
                pc,
                stack,
                in_module: mod?.name,
            });
        } catch (_) { /* ignore */ }
        return false;  // do not suppress
    });

    return new Promise((resolve) => {
        setTimeout(() => resolve({
            modules: modules.slice(0, 100),
            crashes,
            duration_ms: Date.now() - start,
        }), window_s * 1000);
    });
}

rpc.exports = { nativeheap };
