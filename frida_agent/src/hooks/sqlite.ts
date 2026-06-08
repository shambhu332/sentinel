/*
 * SQLite query observation (D_032).
 *
 * Hooks:
 *   - android.database.sqlite.SQLiteDatabase.rawQuery (all overloads)
 *   - android.database.sqlite.SQLiteDatabase.execSQL (all overloads)
 *   - android.database.sqlite.SQLiteDatabase.query  (the standard
 *     7-arg overload — the convenience one most apps reach for)
 *
 * For every call we emit the SQL string, the bind-args count, the
 * inferred top-of-stack caller class, and a short stack snippet.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import { sendSqliteQueryExecuted, sendError } from "../lib/send.js";

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

function callerClass(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            if (cls.indexOf("android.database.sqlite.") === 0) continue;
            if (cls.indexOf("android.database.") === 0) continue;
            if (cls.indexOf("java.lang.Thread") === 0) continue;
            return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

function safeStringArg(value: any): string {
    try { return String(value ?? ""); }
    catch (_) { return ""; }
}

function arrayLength(value: any): number {
    if (value === null || value === undefined) return 0;
    try {
        const n = Number(value.length);
        return Number.isFinite(n) && n >= 0 ? n : 0;
    } catch (_) { return 0; }
}

function emit(api: string, sql: any, argsCount: number): void {
    try {
        sendSqliteQueryExecuted({
            api,
            sql: safeStringArg(sql),
            args_count: argsCount,
            caller_class: callerClass(),
            stack: shortStack(),
        });
    } catch (e) {
        sendError(`sqlite.emit: ${String(e)}`);
    }
}

export function installSqliteHooks(): number {
    let installed = 0;

    let DB: any;
    try { DB = Java.use("android.database.sqlite.SQLiteDatabase"); }
    catch (_) { return 0; }

    // ---- rawQuery ----
    try {
        const overloads = DB.rawQuery ? DB.rawQuery.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    // Common shapes:
                    //   (String, String[])
                    //   (String, String[], CancellationSignal)
                    //   (String, String[], String editTable, CancellationSignal)
                    //   (SQLiteCursorDriver?, ...)
                    let sql = "";
                    let argsCount = 0;
                    for (let k = 0; k < args.length; k++) {
                        if (typeof args[k] === "string" && !sql) {
                            sql = args[k] as string;
                        } else if (args[k] && typeof args[k].length === "number"
                                   && !sql.length && k > 0) {
                            argsCount = arrayLength(args[k]);
                        } else if (args[k] && typeof args[k].length === "number"
                                   && sql) {
                            argsCount = arrayLength(args[k]);
                            break;
                        }
                    }
                    emit("rawQuery", sql, argsCount);
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- execSQL ----
    try {
        const overloads = DB.execSQL ? DB.execSQL.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    const sql = args[0];
                    const argsCount = args.length > 1
                        ? arrayLength(args[1]) : 0;
                    emit("execSQL", sql, argsCount);
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- query (standard 7-arg + variants) ----
    try {
        const overloads = DB.query ? DB.query.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    // The 7-arg builder shape is:
                    //   (String table, String[] columns, String selection,
                    //    String[] selectionArgs, String groupBy, ...)
                    // We treat selection as the SQL fragment.
                    let selection = "";
                    let selectionArgsCount = 0;
                    for (let k = 0; k < args.length; k++) {
                        if (typeof args[k] === "string"
                            && k > 1 && !selection) {
                            selection = args[k] as string;
                        } else if (args[k] && typeof args[k].length === "number"
                                   && selection) {
                            selectionArgsCount = arrayLength(args[k]);
                            break;
                        }
                    }
                    if (selection) {
                        emit("query", selection, selectionArgsCount);
                    }
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    return installed;
}
