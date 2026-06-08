/*
 * Reflection invocation observation (D_033).
 *
 * Hooks:
 *   - java.lang.reflect.Method.invoke
 *       -> emit reflection.method_invoked with the target class
 *          (the *runtime* type of the receiver, or declaringClass
 *          for static methods), the method name, and the caller.
 *   - java.lang.reflect.Constructor.newInstance
 *       -> emit reflection.constructor_invoked with the
 *          getDeclaringClass() name.
 *
 * Class.forName is already hooked by json_deserialize.ts (D_031) —
 * we re-use those reflection.class_forname events on the Python
 * side for the sliding-window correlation.
 *
 * Pure observer.
 */
import { Java } from "../lib/java_ready.js";
import {
    sendReflectionMethodInvoked,
    sendReflectionConstructorInvoked,
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

function callerClass(): string {
    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        for (let i = 3; i < frames.length; i++) {
            const cls = String(frames[i].getClassName());
            if (cls.indexOf("java.lang.reflect.") === 0) continue;
            if (cls.indexOf("java.lang.Thread") === 0) continue;
            return cls;
        }
    } catch (_) { /* swallow */ }
    return "";
}

function classNameOf(obj: any): string {
    if (!obj) return "";
    try { return String(obj.getClass().getName()); }
    catch (_) { return ""; }
}

export function installReflectionInvokeHooks(): number {
    let installed = 0;

    // ---- Method.invoke ----
    try {
        const Method = Java.use("java.lang.reflect.Method");
        const ov = Method.invoke.overload(
            "java.lang.Object", "[Ljava.lang.Object;",
        );
        ov.implementation = function (receiver: any, args: any[]) {
            try {
                // For instance methods, target = runtime type of
                // the receiver. For static methods, target =
                // declaring class on the Method itself.
                let target = "";
                if (receiver) {
                    target = classNameOf(receiver);
                } else {
                    try { target = String(this.getDeclaringClass().getName()); }
                    catch (_) { /* swallow */ }
                }
                let methodName = "";
                let declaring = "";
                try { methodName = String(this.getName()); } catch (_) {}
                try { declaring = String(this.getDeclaringClass().getName()); }
                catch (_) {}

                sendReflectionMethodInvoked({
                    target_class: target,
                    method_name: methodName,
                    declaring_class: declaring,
                    caller_class: callerClass(),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`reflection.invoke.emit: ${String(e)}`);
            }
            return ov.call(this, receiver, args);
        };
        installed++;
    } catch (_) { /* skip */ }

    // ---- Constructor.newInstance ----
    try {
        const Constructor = Java.use("java.lang.reflect.Constructor");
        const ov = Constructor.newInstance.overload("[Ljava.lang.Object;");
        ov.implementation = function (args: any[]) {
            try {
                let target = "";
                try { target = String(this.getDeclaringClass().getName()); }
                catch (_) { /* swallow */ }
                sendReflectionConstructorInvoked({
                    target_class: target,
                    caller_class: callerClass(),
                    stack: shortStack(),
                });
            } catch (e) {
                sendError(`reflection.newInstance.emit: ${String(e)}`);
            }
            return ov.call(this, args);
        };
        installed++;
    } catch (_) { /* skip */ }

    return installed;
}
