/*
 * Diagnostics: assembles the per-run hook summary and emits it as a
 * single tls.hooks_summary event. The Python side parses this to show
 * which libraries were probed, which were present and bypassed, and
 * which failed — much richer than the legacy single tls.hooks_installed
 * event that only listed installed labels.
 *
 * Defined as its own module so individual hook files don't need to
 * know about the summary envelope; they just push into a HookResult
 * and this helper serialises it on agent shutdown.
 */
import { sendHooksSummary } from "../lib/send.js";
import { HookResult } from "./crypto.js";

export function emitHooksSummary(
    result: HookResult,
    subclassesHooked: number,
    nativeHooks: number,
): void {
    sendHooksSummary({
        attempted: result.attempted,
        succeeded: result.succeeded,
        failed: result.failed,
        subclass_hooks_added: subclassesHooked,
        native_hooks_added: nativeHooks,
    });
}
