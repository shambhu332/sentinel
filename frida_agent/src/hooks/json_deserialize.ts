/*
 * Unsafe JSON deserialization observation (D_031).
 *
 * Hooks:
 *   - java.lang.Class.forName (String) — feeds the D_031 sliding
 *     window the Python side uses to spot dynamic-type lookups.
 *   - com.google.gson.Gson.fromJson — every (String/Reader, Class/Type)
 *     overload.
 *   - com.squareup.moshi.JsonAdapter.fromJson — emits the adapter's
 *     declared type so the Python side can spot polymorphic factories.
 *   - com.fasterxml.jackson.databind.ObjectMapper.readValue — every
 *     overload, plus a flag if default typing is active.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendClassForname,
    sendJsonDeserializeCalled,
    sendError,
} from "../lib/send.js";

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

function callerClass(skipPrefixes: string[]): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            let skip = false;
            for (let p = 0; p < skipPrefixes.length; p++) {
                if (cls.indexOf(skipPrefixes[p]) === 0) {
                    skip = true; break;
                }
            }
            if (!skip) return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

function typeName(t: any): string {
    if (!t) return "";
    try {
        if (typeof t.getName === "function") return String(t.getName());
        if (typeof t.getTypeName === "function") return String(t.getTypeName());
        return String(t.toString());
    } catch (_) { return ""; }
}

function isPolymorphicFactory(adapter: any): string {
    if (!adapter) return "";
    try {
        const cls = String(adapter.getClass().getName());
        const probe = cls.toLowerCase();
        if (probe.indexOf("polymorphic") !== -1) return cls;
        if (probe.indexOf("runtimetypeadapter") !== -1) return cls;
        if (probe.indexOf("defaulttyping") !== -1) return cls;
        return "";
    } catch (_) { return ""; }
}

export function installJsonDeserializeHooks(): number {
    let installed = 0;

    // ---- Class.forName ----
    try {
        const Cls = Java.use("java.lang.Class");
        const ov = Cls.forName.overload("java.lang.String");
        ov.implementation = function (name: any) {
            try {
                sendClassForname({
                    name: name ? String(name) : "",
                    caller_class: callerClass(["java.lang.Class"]),
                    stack: shortStack(),
                });
            } catch (_) { /* swallow */ }
            return ov.call(this, name);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- Gson.fromJson ----
    try {
        const Gson = Java.use("com.google.gson.Gson");
        const overloads = Gson.fromJson ? Gson.fromJson.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    // The Type/Class is always the last argument.
                    const target = args[args.length - 1];
                    sendJsonDeserializeCalled({
                        library: "Gson",
                        target_type: typeName(target),
                        caller_class: callerClass(["com.google.gson"]),
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- Moshi JsonAdapter.fromJson ----
    try {
        const Adapter = Java.use("com.squareup.moshi.JsonAdapter");
        const overloads = Adapter.fromJson ? Adapter.fromJson.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    sendJsonDeserializeCalled({
                        library: "Moshi",
                        target_type: typeName(this.getClass()),
                        polymorphic_marker: isPolymorphicFactory(this),
                        caller_class: callerClass(["com.squareup.moshi"]),
                        stack: shortStack(),
                    });
                } catch (_) { /* swallow */ }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip */ }

    // ---- Jackson ObjectMapper.readValue ----
    try {
        const Mapper = Java.use(
            "com.fasterxml.jackson.databind.ObjectMapper",
        );
        const overloads = Mapper.readValue ? Mapper.readValue.overloads : [];
        for (let i = 0; i < overloads.length; i++) {
            const ov = overloads[i];
            ov.implementation = function (...args: any[]) {
                try {
                    const target = args[args.length - 1];
                    let marker = "";
                    try {
                        // ObjectMapper exposes default-typing state
                        // via getDeserializationConfig().getDefaultTyper().
                        const cfg = this.getDeserializationConfig();
                        if (cfg && cfg.getDefaultTyper) {
                            const typer = cfg.getDefaultTyper(null);
                            if (typer) marker = String(typer.getClass().getName());
                        }
                    } catch (_) { /* swallow */ }
                    sendJsonDeserializeCalled({
                        library: "Jackson",
                        target_type: typeName(target),
                        polymorphic_marker: marker,
                        caller_class: callerClass(["com.fasterxml.jackson"]),
                        stack: shortStack(),
                    });
                } catch (e) {
                    sendError(`jackson.report: ${String(e)}`);
                }
                return ov.apply(this, args);
            };
            installed++;
        }
    } catch (_) { /* skip — Jackson not bundled */ }

    return installed;
}
