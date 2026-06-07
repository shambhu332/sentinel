/*
 * ZIP / archive extraction observation (D_027 — Zip Slip).
 *
 * Hooks:
 *   - java.util.zip.ZipInputStream.getNextEntry
 *       -> emit zip.entry_observed for every returned ZipEntry.
 *   - java.util.zip.ZipFile.getEntry / .entries
 *       -> emit zip.entry_observed for ZipFile-based traversal.
 *   - java.io.FileOutputStream.<init>(File) and (String)
 *       -> when the call stack contains a ZipInputStream.read frame,
 *          treat this write as part of an extraction loop. Compare
 *          the target file's canonical path against every live
 *          intended-dir candidate (parent directory) to decide
 *          whether the entry escaped.
 *
 * The "intended dir" inference is best-effort: we use
 * file.getParentFile().getCanonicalPath() of the *first* legal write
 * the extractor performs as the directory the dev meant. Subsequent
 * writes are checked for that prefix. False positives are bounded by
 * the traversal-shape filter on the Python side.
 *
 * Pure observer — call args / return values are untouched.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendZipEntryObserved,
    sendZipEntryExtracted,
    sendError,
} from "../lib/send.js";

let intendedDir: string = "";   // mutates across the agent's lifetime
let lastEntryName: string = "";

function shortStack(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 3; i < frames.length && out.length < 5; i++) {
            const f = frames[i];
            out.push(`${f.getClassName()}.${f.getMethodName()}`);
        }
        return out.join(" <- ");
    } catch (_) { return ""; }
}

function inZipReadStack(): boolean {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 0; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            const meth = String(frames[i].getMethodName());
            if ((cls === "java.util.zip.ZipInputStream"
                    || cls === "java.util.zip.ZipFile")
                && meth === "read") {
                return true;
            }
        }
    } catch (_) { /* swallow */ }
    return false;
}

function entryName(entry: any): string {
    try {
        if (!entry) return "";
        return String(entry.getName() || "");
    } catch (_) { return ""; }
}

function entrySize(entry: any): number | undefined {
    try {
        if (!entry || !entry.getSize) return undefined;
        const n = Number(entry.getSize());
        return Number.isFinite(n) ? n : undefined;
    } catch (_) { return undefined; }
}

function canonicalize(file: any): string {
    try {
        if (!file) return "";
        return String(file.getCanonicalPath());
    } catch (_) {
        try { return String(file.getAbsolutePath()); }
        catch (_) { return ""; }
    }
}

function fileFromArgs(args: any[]): { file: any; target: string } {
    try {
        if (args.length === 0) return { file: null, target: "" };
        const first = args[0];
        // (File) overload.
        if (first && typeof first.getAbsolutePath === "function") {
            return { file: first, target: String(first.getAbsolutePath()) };
        }
        // (String, ...) overload.
        if (typeof first === "string") {
            const FileCls = Java.use("java.io.File");
            const f = FileCls.$new(String(first));
            return { file: f, target: String(first) };
        }
    } catch (_) { /* swallow */ }
    return { file: null, target: "" };
}

function recordExtraction(args: any[]): void {
    if (!inZipReadStack()) return;
    try {
        const { file, target } = fileFromArgs(args);
        if (!target) return;
        const canonical = canonicalize(file);

        // Bootstrap intendedDir on the first benign write.
        if (!intendedDir && canonical) {
            try {
                if (file && file.getParentFile) {
                    const parent = file.getParentFile();
                    if (parent) intendedDir = canonicalize(parent);
                }
            } catch (_) { /* swallow */ }
        }

        const escaped = Boolean(
            intendedDir
            && canonical
            && canonical.indexOf(intendedDir) !== 0,
        );

        sendZipEntryExtracted({
            entry_name: lastEntryName,
            target_path: target,
            canonical_path: canonical,
            intended_dir: intendedDir,
            escaped_intended_dir: escaped,
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`zip.extract report: ${String(e)}`);
    }
}

export function installZipHooks(): number {
    let installed = 0;

    // ---- ZipInputStream.getNextEntry ----
    try {
        const ZIS = Java.use("java.util.zip.ZipInputStream");
        ZIS.getNextEntry.implementation = function () {
            const entry = this.getNextEntry();
            try {
                const name = entryName(entry);
                if (name) {
                    lastEntryName = name;
                    sendZipEntryObserved({
                        name,
                        size: entrySize(entry),
                        source: "ZipInputStream",
                        stack: shortStack(),
                    });
                }
            } catch (_) { /* swallow */ }
            return entry;
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- ZipFile.getEntry ----
    try {
        const ZF = Java.use("java.util.zip.ZipFile");
        const overloads = ZF.getEntry ? ZF.getEntry.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (name: string) {
                const entry = ov.call(this, name);
                try {
                    if (name) {
                        sendZipEntryObserved({
                            name: String(name),
                            source: "ZipFile.getEntry",
                            stack: shortStack(),
                        });
                    }
                } catch (_) { /* swallow */ }
                return entry;
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- FileOutputStream.<init> — gate by stack ----
    try {
        const FOS = Java.use("java.io.FileOutputStream");
        const overloads = FOS.$init ? FOS.$init.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try { recordExtraction(args); }
                catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    return installed;
}
