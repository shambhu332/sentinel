/*
 * D_074 — Deep-link scheme-confusion probe.
 *
 * Hooks android.net.Uri.parse and records how Android interprets
 * confusion payloads such as:
 *
 *   scheme://evil.com@trusted.com/path
 *
 * For target Activity launches, the probe parses the curated payloads
 * emitted by the SAST half and reports host/userInfo/authority. It does
 * not rewrite arbitrary production URLs.
 */

import { Java } from "../lib/java_ready.js";
import { sendError } from "../lib/send.js";

interface SchemeProbePayload {
    type?: string;
    package?: string;
    activity: string;
    schemes: string[];
    hosts?: string[];
    confusion_payloads?: string[];
    safety_budget?: {
        max_actions_total?: number;
        max_actions_per_sec?: number;
        wall_clock_budget_s?: number;
        max_consecutive_crashes?: number;
    };
}

interface SchemeProbeResult {
    payload: string;
    scheme?: string;
    authority?: string;
    host?: string;
    user_info?: string;
    path?: string;
    confused: boolean;
    error?: string;
}

interface SchemeProbeSummary {
    fired: number;
    confused_count: number;
    results: SchemeProbeResult[];
    duration_ms: number;
    tripped: boolean;
    trip_reason?: string;
}

const HARD_CAP = 12;

export async function schemeConfuser(
    payload: SchemeProbePayload,
): Promise<SchemeProbeSummary> {
    const start = Date.now();
    const budget = payload.safety_budget ?? {};
    const maxTotal = Math.min(budget.max_actions_total ?? 12, HARD_CAP);
    const wallClockMs = (budget.wall_clock_budget_s ?? 30) * 1000;
    const probes = buildProbes(payload).slice(0, maxTotal);
    const results: SchemeProbeResult[] = [];
    let tripReason: string | undefined;
    let parseHookInstalled = false;

    return new Promise((resolve) => {
        Java.perform(() => {
            let Uri: any;
            let Activity: any;
            try {
                Uri = Java.use("android.net.Uri");
                Activity = Java.use("android.app.Activity");
            } catch (e: any) {
                sendError(`D_074: required class missing: ${e.message}`);
                resolve(summary());
                return;
            }

            try {
                const parse = Uri.parse.overload("java.lang.String");
                parse.implementation = function (input: any) {
                    const parsed = parse.call(this, input);
                    const raw = String(input);
                    if (raw.includes("evil.com@")) {
                        send({
                            kind: "scheme_confuser.uri_parse",
                            payload: {
                                agent_id: "D_074",
                                ...describeUri(raw, parsed),
                            },
                        });
                    }
                    return parsed;
                };
                parseHookInstalled = true;
            } catch (e: any) {
                sendError(`D_074: Uri.parse hook failed: ${e.message}`);
            }

            try {
                const onCreate = Activity.onCreate.overload("android.os.Bundle");
                onCreate.implementation = function (bundle: any) {
                    maybeProbeActivity(this, Uri, payload, probes, results, start);
                    return onCreate.call(this, bundle);
                };
            } catch (e: any) {
                sendError(`D_074: Activity.onCreate hook failed: ${e.message}`);
            }

            try {
                const onNewIntent = Activity.onNewIntent.overload(
                    "android.content.Intent",
                );
                onNewIntent.implementation = function (intent: any) {
                    maybeProbeActivity(this, Uri, payload, probes, results, start);
                    return onNewIntent.call(this, intent);
                };
            } catch (_) {
                // Some API levels expose this differently; onCreate is enough
                // for the common cold-start deep-link path.
            }

            send({
                kind: "scheme_confuser.probe_installed",
                payload: {
                    agent_id: "D_074",
                    activity: payload.activity,
                    parse_hook_installed: parseHookInstalled,
                    probe_count: probes.length,
                },
            });

            // Also parse immediately so headless Frida smoke runs produce a
            // deterministic result even if the target activity is not launched.
            fireProbes(Uri, probes, results, start);
            setTimeout(() => resolve(summary()), wallClockMs);
        });
    });

    function summary(): SchemeProbeSummary {
        const confused = results.filter((r) => r.confused).length;
        return {
            fired: results.length,
            confused_count: confused,
            results,
            duration_ms: Date.now() - start,
            tripped: tripReason !== undefined,
            trip_reason: tripReason,
        };
    }

    function buildProbes(input: SchemeProbePayload): string[] {
        if (input.confusion_payloads && input.confusion_payloads.length > 0) {
            return input.confusion_payloads;
        }
        const hosts = input.hosts && input.hosts.length > 0
            ? input.hosts
            : ["trusted.com"];
        const generated: string[] = [];
        input.schemes.forEach((scheme) => {
            hosts.slice(0, 3).forEach((host) => {
                generated.push(`${scheme}://evil.com@${host}/sentinel-probe`);
            });
        });
        return generated;
    }

    function fireProbes(
        UriCls: any,
        candidates: string[],
        out: SchemeProbeResult[],
        startedAt: number,
    ): void {
        for (const candidate of candidates) {
            if (out.length >= maxTotal) {
                tripReason = "max_actions_total exceeded";
                return;
            }
            if (Date.now() - startedAt > wallClockMs) {
                tripReason = "wall_clock_budget exceeded";
                return;
            }
            try {
                const parsed = UriCls.parse(candidate);
                const row = describeUri(candidate, parsed);
                out.push(row);
                send({
                    kind: "scheme_confuser.probe_result",
                    payload: {
                        agent_id: "D_074",
                        activity: payload.activity,
                        ...row,
                    },
                });
            } catch (e: any) {
                out.push({
                    payload: candidate,
                    confused: false,
                    error: e.message?.slice(0, 200) ?? String(e),
                });
            }
        }
    }
}

function maybeProbeActivity(
    activityObj: any,
    UriCls: any,
    payload: SchemeProbePayload,
    probes: string[],
    results: SchemeProbeResult[],
    start: number,
): void {
    try {
        const cls = String(activityObj.getClass().getName());
        if (!matchesActivity(cls, payload.activity)) return;
        if (results.length > 0) return;
        probes.forEach((probe) => {
            const parsed = UriCls.parse(probe);
            const row = describeUri(probe, parsed);
            results.push(row);
            send({
                kind: "scheme_confuser.activity_probe",
                payload: {
                    agent_id: "D_074",
                    activity: cls,
                    elapsed_ms: Date.now() - start,
                    ...row,
                },
            });
        });
    } catch (e: any) {
        sendError(`D_074 activity probe: ${e.message ?? String(e)}`);
    }
}

function matchesActivity(observed: string, expected: string): boolean {
    if (!expected) return false;
    return observed === expected || observed.endsWith(`.${expected}`);
}

function describeUri(raw: string, uri: any): SchemeProbeResult {
    const authority = nullableString(uri.getAuthority());
    const host = nullableString(uri.getHost());
    const userInfo = nullableString(uri.getUserInfo());
    return {
        payload: raw,
        scheme: nullableString(uri.getScheme()),
        authority,
        host,
        user_info: userInfo,
        path: nullableString(uri.getPath()),
        confused: raw.includes("@") && userInfo !== undefined
            && authority !== undefined && host !== undefined,
    };
}

function nullableString(value: any): string | undefined {
    if (value === null || value === undefined) return undefined;
    return String(value);
}

rpc.exports = {
    ...(rpc.exports as any),
    schemeconfuser: schemeConfuser,
};
