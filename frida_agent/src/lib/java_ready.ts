/*
 * Frida 17 removed the built-in Java bridge; this module imports
 * frida-java-bridge explicitly so it works on Frida 17. On Frida 16
 * the import still works (it just re-exposes the built-in module).
 *
 * The waitForJava helper polls Java.available with a 100ms tick and
 * 30-attempt ceiling (3s total), then runs the callback inside
 * Java.perform so all bytecode access is on the correct thread.
 */
import Java from "frida-java-bridge";
import { sendError } from "./send.js";

export { Java };

export type SetupFn = () => void;

export function waitForJava(label: string, setup: SetupFn): void {
    if (Java.available) {
        Java.perform(setup);
        return;
    }
    let attempts = 0;
    const interval = setInterval(() => {
        attempts++;
        if (Java.available) {
            clearInterval(interval);
            Java.perform(setup);
        } else if (attempts >= 30) {
            clearInterval(interval);
            sendError(`${label}: Java bridge unavailable after 3s`);
        }
    }, 100);
}
