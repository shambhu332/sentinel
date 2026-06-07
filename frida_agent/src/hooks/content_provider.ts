/*
 * ContentProvider URI-exposure observation (D_023).
 *
 * Hooks:
 *   - android.content.ContentResolver.openFileDescriptor (3 overloads)
 *       -> resolves the returned ParcelFileDescriptor to a real path
 *          via /proc/self/fd/<fd> and emits provider.uri_opened only
 *          when caller_uid != target_uid.
 *   - android.content.ContentResolver.openAssetFileDescriptor (same).
 *   - android.content.ContentResolver.query — inspects the returned
 *       Cursor for a "_data" / "file_path" / "path" column and emits
 *       provider.query_returned with the leaked paths.
 *
 * Pure observer — call args and return values are untouched.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendProviderUriOpened,
    sendProviderQueryReturned,
    sendError,
} from "../lib/send.js";

const PATH_COLUMNS = ["_data", "file_path", "path"];

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

function myUid(): number {
    try {
        const Process = Java.use("android.os.Process");
        return Number(Process.myUid());
    } catch (_) { return -1; }
}

function callingUid(): number {
    try {
        const Binder = Java.use("android.os.Binder");
        return Number(Binder.getCallingUid());
    } catch (_) { return -1; }
}

function resolveFd(pfd: any): string {
    if (!pfd) return "";
    try {
        const fd = Number(pfd.getFd ? pfd.getFd() : pfd.getFileDescriptor());
        if (!fd || fd < 0) return "";
        // /proc/self/fd/<n> is a symlink to the real path on Linux.
        const File = Java.use("java.io.File");
        const link = File.$new(`/proc/self/fd/${fd}`);
        return String(link.getCanonicalPath());
    } catch (_) { return ""; }
}

function extractCursorPaths(cursor: any): string[] {
    const out: string[] = [];
    if (!cursor) return out;
    try {
        const colCount = Number(cursor.getColumnCount());
        const colIdxs: number[] = [];
        for (let i = 0; i < colCount; i++) {
            const name = String(cursor.getColumnName(i) || "").toLowerCase();
            if (PATH_COLUMNS.indexOf(name) !== -1) colIdxs.push(i);
        }
        if (colIdxs.length === 0) return out;

        // Iterate by saving / restoring position so we don't disturb
        // the caller's cursor state.
        const savedPos = Number(cursor.getPosition());
        try {
            cursor.moveToPosition(-1);
            let rows = 0;
            while (cursor.moveToNext() && rows < 20) {
                for (let j = 0; j < colIdxs.length; j++) {
                    const v = cursor.getString(colIdxs[j]);
                    if (v) out.push(String(v));
                }
                rows++;
            }
        } finally {
            cursor.moveToPosition(savedPos);
        }
    } catch (_) { /* swallow — cursor may be one-shot or closed */ }
    return out;
}

function reportOpen(uri: any, mode: string, pfd: any): void {
    try {
        const caller = callingUid();
        const target = myUid();
        if (caller < 0 || target < 0 || caller === target) return;
        const realPath = resolveFd(pfd);
        if (!realPath) return;
        sendProviderUriOpened({
            caller_uid: caller,
            target_uid: target,
            uri: uri ? String(uri.toString()) : "",
            mode,
            real_path: realPath,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`provider.open report: ${String(e)}`);
    }
}

export function installContentProviderHooks(): number {
    let installed = 0;

    // ---- ContentResolver.openFileDescriptor ----
    try {
        const Resolver = Java.use("android.content.ContentResolver");
        const overloads = Resolver.openFileDescriptor
            ? Resolver.openFileDescriptor.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                const result = ov.apply(this, args);
                try {
                    const uri = args[0];
                    const mode = String(args[1] || "r");
                    reportOpen(uri, mode, result);
                } catch (_) { /* swallow */ }
                return result;
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- ContentResolver.openAssetFileDescriptor ----
    try {
        const Resolver = Java.use("android.content.ContentResolver");
        const overloads = Resolver.openAssetFileDescriptor
            ? Resolver.openAssetFileDescriptor.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                const result = ov.apply(this, args);
                try {
                    const uri = args[0];
                    const mode = String(args[1] || "r");
                    // AssetFileDescriptor wraps a ParcelFileDescriptor.
                    const pfd = result && result.getParcelFileDescriptor
                        ? result.getParcelFileDescriptor()
                        : result;
                    reportOpen(uri, mode, pfd);
                } catch (_) { /* swallow */ }
                return result;
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- ContentResolver.query ----
    try {
        const Resolver = Java.use("android.content.ContentResolver");
        const overloads = Resolver.query ? Resolver.query.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                const cursor = ov.apply(this, args);
                try {
                    const caller = callingUid();
                    const target = myUid();
                    if (caller >= 0 && target >= 0 && caller !== target) {
                        const paths = extractCursorPaths(cursor);
                        if (paths.length > 0) {
                            sendProviderQueryReturned({
                                caller_uid: caller,
                                target_uid: target,
                                uri: args[0] ? String(args[0].toString()) : "",
                                exposed_paths: paths,
                                stack: shortStack(),
                            });
                        }
                    }
                } catch (_) { /* swallow */ }
                return cursor;
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    return installed;
}
