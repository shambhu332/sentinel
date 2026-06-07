/*
 * FileProvider URI-minting observation (D_024).
 *
 * Hook:
 *   - androidx.core.content.FileProvider.getUriForFile (both overloads —
 *     3-arg legacy and 4-arg displayName variant).
 *
 * For every call we capture:
 *   - input_path:     File.getAbsolutePath() of the argument as
 *                     supplied to the call (pre-canonicalisation).
 *   - canonical_path: File.getCanonicalPath() (post-resolution).
 *   - is_symlink:     Files.isSymbolicLink(file.toPath()).
 *   - caller_controlled_segments: whether the input contained ".."
 *                     segments that the canonicaliser collapsed.
 *
 * Pure observer — original call args + return value are untouched.
 */
import { Java } from "../lib/java_ready.js";
import { sendFileProviderUriMinted, sendError } from "../lib/send.js";

const PROVIDER_CLASSES = [
    "androidx.core.content.FileProvider",
    "android.support.v4.content.FileProvider",
];

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

function safeAbsolute(file: any): string {
    try { return String(file.getAbsolutePath()); }
    catch (_) { return ""; }
}

function safeCanonical(file: any): string {
    try { return String(file.getCanonicalPath()); }
    catch (_) { return ""; }
}

function detectSymlink(file: any): boolean {
    try {
        const Files = Java.use("java.nio.file.Files");
        const path = file.toPath();
        return Boolean(Files.isSymbolicLink(path));
    } catch (_) {
        // Fall back: an absolute path that does not equal its
        // canonical path is a strong symlink hint.
        try {
            const abs = safeAbsolute(file);
            const can = safeCanonical(file);
            return Boolean(abs && can && abs !== can);
        } catch (_) { return false; }
    }
}

function hasTraversalSegment(absolute: string): boolean {
    if (!absolute) return false;
    const parts = absolute.split("/");
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === "..") return true;
    }
    return false;
}

function reportCall(authority: any, file: any): void {
    try {
        if (!file) return;
        const absolute = safeAbsolute(file);
        const canonical = safeCanonical(file);
        const isLink = detectSymlink(file);
        const traversal = hasTraversalSegment(absolute);

        // Skip the call when nothing interesting happened (the dev's
        // own code typically passes File objects fabricated from
        // getCacheDir() that already canonicalise to themselves).
        if (!isLink && !traversal && absolute === canonical) return;

        sendFileProviderUriMinted({
            authority: authority ? String(authority) : "",
            input_path: absolute,
            canonical_path: canonical,
            is_symlink: isLink,
            caller_controlled_segments: traversal,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`file_provider.report: ${String(e)}`);
    }
}

export function installFileProviderHooks(): number {
    let installed = 0;
    for (let c = 0; c < PROVIDER_CLASSES.length; c++) {
        const cls = PROVIDER_CLASSES[c];
        let Provider: any;
        try { Provider = Java.use(cls); }
        catch (_) { continue; }

        const overloads = Provider.getUriForFile
            ? Provider.getUriForFile.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    // Overloads:
                    //   (Context, String authority, File file)
                    //   (Context, String authority, File file, String displayName)
                    reportCall(args[1], args[2]);
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    }
    return installed;
}
