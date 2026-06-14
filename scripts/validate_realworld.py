#!/usr/bin/env python3
"""Real-world dynamic-agent validation harness.

This script validates SENTINEL's runtime stability against production
apps already installed on a rooted Android device. It is intentionally
health-oriented: the output is a tool-health report, not a vulnerability
verdict.

Safety defaults:
  * no active replay; the SENTINEL CLI defaults this off and this script
    never passes --active-replay;
  * one-minute dynamic and Frida windows by default;
  * no LLM triage/RAG calls;
  * cleanup always force-stops the app and clears global proxy settings.

Current repository note:
  The requested CLI flags --agents, --dynamic-timeout, and
  --no-active-replay do not exist in this checkout. The script records
  that in the report and uses supported equivalents:
      --dynamic-duration 60 --frida-duration 60
  Active replay remains disabled by omission.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TARGET_AGENTS = ("D_063", "D_065", "D_073", "D_074", "D_084", "D_087")
SUPPORTED_SAFE_EQUIVALENTS = {
    "--dynamic-timeout": "--dynamic-duration and --frida-duration",
    "--no-active-replay": "default behavior; --active-replay is not passed",
    "--agents": "not available in current CLI; full dynamic roster is used",
}

HOOK_KIND_HINTS = {
    "D_063": ("provider_sqli", "sqli", "sqlite.query_executed"),
    "D_065": ("file_provider", "file_provider.uri_minted"),
    "D_073": ("pending_intent", "pending_intent.probe_result"),
    "D_074": ("scheme_confuser", "scheme_confuser.probe_result"),
    "D_084": ("webview_xss", "webviewxss", "console"),
    "D_087": ("d087",),
}

RPC_RESULT_KEYS = {
    "D_063": ("fired", "succeeded", "distinct_row_counts"),
    "D_065": ("fired", "minted_count", "read_count"),
    "D_073": ("attempted", "injection_succeeded", "injection_failed"),
    "D_074": ("fired", "confused_count"),
    "D_084": ("probes_fired", "webviews_found", "console_hits"),
    "D_087": (),
}


@dataclass
class CommandResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass
class AgentHealth:
    agent_id: str
    hook_fired: bool | None = None
    hook_event_count: int = 0
    traffic_captured: bool | None = None
    app_crashed: bool = False
    notes: list[str] = field(default_factory=list)
    rpc_summary: dict[str, Any] = field(default_factory=dict)
    sast_findings: int = 0


def run_cmd(
    cmd: list[str],
    *,
    timeout: int = 30,
    check: bool = False,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command and return captured output."""
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    result = CommandResult(
        cmd=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout={proc.stdout[-1000:]}\nstderr={proc.stderr[-1000:]}",
        )
    return result


class RealWorldValidator:
    def __init__(self, args: argparse.Namespace) -> None:
        self.package = args.package_name
        self.adb = args.adb
        self.serial = args.serial
        self.sentinel_cmd = args.sentinel_cmd
        self.dynamic_duration = args.dynamic_duration
        self.frida_duration = args.frida_duration
        self.frida_spawn = args.frida_spawn
        self.workspace_root = args.workspace.expanduser().resolve()
        self.data_dir = args.data_dir.expanduser().resolve()
        self.report_path = args.report or Path(
            f"validation_report_{safe_name(self.package)}.json",
        )
        self.apk_path = args.apk_path.expanduser().resolve() if args.apk_path else None
        self.skip_scan = args.skip_scan
        self.force = args.force
        self.kill_frida_server = args.kill_frida_server
        self.command_prefix = self._adb_prefix()
        self.session_workspace: Path | None = None
        self.scan_output: Path | None = None
        self.scan_log: Path | None = None
        self.preflight: dict[str, Any] = {}
        self.cleanup_actions: list[dict[str, Any]] = []

    def _adb_prefix(self) -> list[str]:
        cmd = [self.adb]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def adb_cmd(self, *args: str, timeout: int = 30, check: bool = False) -> CommandResult:
        return run_cmd([*self.command_prefix, *args], timeout=timeout, check=check)

    def adb_shell(
        self,
        command: str,
        *,
        as_root: bool = False,
        timeout: int = 30,
        check: bool = False,
    ) -> CommandResult:
        if as_root:
            return self.adb_cmd("shell", "su", "-c", command, timeout=timeout, check=check)
        return self.adb_cmd("shell", command, timeout=timeout, check=check)

    def validate(self) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        scan_result: dict[str, Any] = {}
        scan_status = "skipped" if self.skip_scan else "not_started"
        scan_stdout = ""
        scan_stderr = ""
        app_pid_before = ""
        app_pid_after = ""
        app_crashed = False
        rasp_detected = False

        try:
            self.preflight = self.preflight_checks()
            if not self.preflight["overall_ok"] and not self.force:
                scan_status = "preflight_failed"
                return self.build_report(
                    started=started,
                    scan_status=scan_status,
                    scan_result=scan_result,
                    app_pid_before=app_pid_before,
                    app_pid_after=app_pid_after,
                    app_crashed=False,
                    rasp_detected=False,
                    scan_stdout=scan_stdout,
                    scan_stderr=scan_stderr,
                )

            app_pid_before = self.ensure_app_running()
            if not self.skip_scan:
                scan_status, scan_result, scan_stdout, scan_stderr = self.run_scan()
            app_pid_after = self.check_app_stability()
            app_crashed = bool(app_pid_before and not app_pid_after)
            rasp_detected = detect_rasp(scan_stdout, scan_stderr, scan_result, app_crashed)
        finally:
            self.cleanup()

        return self.build_report(
            started=started,
            scan_status=scan_status,
            scan_result=scan_result,
            app_pid_before=app_pid_before,
            app_pid_after=app_pid_after,
            app_crashed=app_crashed,
            rasp_detected=rasp_detected,
            scan_stdout=scan_stdout,
            scan_stderr=scan_stderr,
        )

    def preflight_checks(self) -> dict[str, Any]:
        checks: dict[str, Any] = {
            "adb_connected": False,
            "root_access": False,
            "package_installed": False,
            "frida_server_reachable": False,
            "frida_version_match": None,
            "package_paths": [],
            "apk_path": "",
            "notes": [],
            "unsupported_requested_flags": SUPPORTED_SAFE_EQUIVALENTS,
        }

        devices = self.adb_cmd("devices", "-l", timeout=15)
        device_lines = [
            line for line in devices.stdout.splitlines()[1:]
            if line.strip() and len(line.split()) >= 2 and line.split()[1] == "device"
        ]
        checks["adb_connected"] = devices.returncode == 0 and bool(device_lines)
        checks["adb_devices_output"] = devices.stdout.strip()

        whoami = self.adb_shell("whoami", timeout=10)
        su_whoami = self.adb_shell("whoami", as_root=True, timeout=10)
        checks["adb_whoami"] = whoami.stdout.strip()
        checks["adb_su_whoami"] = su_whoami.stdout.strip()
        checks["root_access"] = (
            whoami.stdout.strip() == "root"
            or su_whoami.stdout.strip() == "root"
        )

        pm_path = self.adb_shell(f"pm path {shell_quote(self.package)}", timeout=20)
        package_paths = parse_pm_paths(pm_path.stdout)
        checks["package_paths"] = package_paths
        checks["package_installed"] = pm_path.returncode == 0 and bool(package_paths)

        if checks["package_installed"]:
            if self.apk_path is None:
                self.apk_path = self.pull_base_apk(package_paths)
            checks["apk_path"] = str(self.apk_path)

        checks.update(self.check_frida_versions())
        checks["overall_ok"] = all([
            checks["adb_connected"],
            checks["root_access"],
            checks["package_installed"],
            bool(checks["apk_path"]),
            checks["frida_server_reachable"],
        ])
        if checks["frida_version_match"] is False:
            checks["notes"].append(
                "Frida client/server major versions differ; hook execution may be zero-event.",
            )
        return checks

    def pull_base_apk(self, package_paths: list[str]) -> Path:
        base = next((p for p in package_paths if p.endswith("/base.apk")), package_paths[0])
        out_dir = self.workspace_root / safe_name(self.package) / "pulled_apk"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "base.apk"
        pulled = self.adb_cmd("pull", base, str(out), timeout=120)
        if pulled.returncode != 0:
            remote_tmp = f"/data/local/tmp/sentinel_{safe_name(self.package)}_base.apk"
            copy = self.adb_shell(
                f"cp {shell_quote(base)} {shell_quote(remote_tmp)} && chmod 0644 {shell_quote(remote_tmp)}",
                as_root=True,
                timeout=60,
            )
            fallback_pull = self.adb_cmd("pull", remote_tmp, str(out), timeout=120)
            self.adb_shell(f"rm -f {shell_quote(remote_tmp)}", as_root=True, timeout=15)
            if copy.returncode != 0 or fallback_pull.returncode != 0:
                raise RuntimeError(
                    f"could not pull APK {base}: "
                    f"{pulled.stderr or copy.stderr or fallback_pull.stderr}",
                )
        return out

    def check_frida_versions(self) -> dict[str, Any]:
        local_version = ""
        try:
            import frida  # type: ignore
            local_version = getattr(frida, "__version__", "") or ""
        except Exception as exc:  # noqa: BLE001
            return {
                "frida_client_version": "",
                "frida_server_version": "",
                "frida_server_reachable": False,
                "frida_version_match": None,
                "frida_error": f"python frida import failed: {exc}",
            }

        frida_ps = run_cmd(["frida-ps", "-U"], timeout=15) if shutil.which("frida-ps") else None
        version_cmd = self.adb_shell(
            "/data/local/tmp/frida-server --version",
            as_root=True,
            timeout=10,
        )
        server_version = first_version(version_cmd.stdout + "\n" + version_cmd.stderr)
        reachable = bool(frida_ps and frida_ps.returncode == 0)
        if not server_version and reachable:
            server_version = "reachable-version-unknown"
        version_match = None
        if local_version and server_version and server_version != "reachable-version-unknown":
            version_match = major(local_version) == major(server_version)
        return {
            "frida_client_version": local_version,
            "frida_server_version": server_version,
            "frida_server_reachable": reachable or version_cmd.returncode == 0,
            "frida_version_match": version_match,
            "frida_ps_error": "" if frida_ps is None else frida_ps.stderr.strip()[:500],
        }

    def ensure_app_running(self) -> str:
        self.adb_shell(
            f"monkey -p {shell_quote(self.package)} "
            "-c android.intent.category.LAUNCHER 1",
            timeout=20,
        )
        time.sleep(3)
        return self.pidof()

    def pidof(self) -> str:
        result = self.adb_shell(f"pidof {shell_quote(self.package)}", timeout=10)
        return result.stdout.strip()

    def run_scan(self) -> tuple[str, dict[str, Any], str, str]:
        if self.apk_path is None:
            raise RuntimeError("APK path unavailable after preflight")
        run_root = self.workspace_root / safe_name(self.package)
        run_root.mkdir(parents=True, exist_ok=True)
        self.scan_output = run_root / f"scan_{int(time.time())}.json"
        self.scan_log = run_root / f"scan_{int(time.time())}.log"

        cmd = [
            *self.sentinel_cmd,
            "scan",
            str(self.apk_path),
            "--dynamic",
            "--frida",
            "--dynamic-duration",
            str(self.dynamic_duration),
            "--frida-duration",
            str(self.frida_duration),
            "--keep-workspace",
            "--workspace",
            str(run_root / "workspace"),
            "--data-dir",
            str(self.data_dir),
            "--output",
            str(self.scan_output),
            "--no-triage",
            "--no-rag",
            "--private",
        ]
        if self.frida_spawn:
            cmd.append("--frida-spawn")

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        timeout = self.dynamic_duration + self.frida_duration + 900
        result = run_cmd(cmd, timeout=timeout, env=env)
        if self.scan_log:
            self.scan_log.write_text(
                "COMMAND: " + " ".join(cmd) + "\n\n"
                "STDOUT:\n" + result.stdout + "\n\nSTDERR:\n" + result.stderr,
                encoding="utf-8",
            )
        scan_json: dict[str, Any] = {}
        if self.scan_output.exists():
            try:
                scan_json = json.loads(self.scan_output.read_text(errors="replace"))
            except json.JSONDecodeError as exc:
                scan_json = {"parse_error": str(exc)}
        session_id = scan_json.get("session_id")
        if session_id:
            self.session_workspace = run_root / "workspace" / session_id
        status = "completed" if result.returncode == 0 else "failed"
        return status, scan_json, result.stdout, result.stderr

    def check_app_stability(self) -> str:
        pid = self.pidof()
        if pid:
            return pid
        relaunch_pid = self.ensure_app_running()
        return relaunch_pid

    def cleanup(self) -> None:
        actions = [
            ("force_stop", lambda: self.adb_shell(
                f"am force-stop {shell_quote(self.package)}",
                timeout=15,
            )),
            ("clear_proxy_put", lambda: self.adb_shell(
                "settings put global http_proxy :0",
                timeout=15,
            )),
            ("clear_proxy_delete", lambda: self.adb_shell(
                "settings delete global http_proxy",
                timeout=15,
            )),
            ("clear_proxy_host", lambda: self.adb_shell(
                "settings delete global global_http_proxy_host",
                timeout=15,
            )),
            ("clear_proxy_port", lambda: self.adb_shell(
                "settings delete global global_http_proxy_port",
                timeout=15,
            )),
        ]
        if shutil.which("frida-kill"):
            actions.append(("frida_kill_package", lambda: run_cmd(
                ["frida-kill", "-U", self.package],
                timeout=10,
            )))
        if self.kill_frida_server:
            actions.append(("kill_frida_server", lambda: self.adb_shell(
                "pkill -f frida-server",
                as_root=True,
                timeout=10,
            )))

        for name, action in actions:
            try:
                result = action()
                self.cleanup_actions.append({
                    "action": name,
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip()[:300],
                    "stderr": result.stderr.strip()[:300],
                })
            except Exception as exc:  # noqa: BLE001
                self.cleanup_actions.append({
                    "action": name,
                    "error": str(exc),
                })

    def build_report(
        self,
        *,
        started: datetime,
        scan_status: str,
        scan_result: dict[str, Any],
        app_pid_before: str,
        app_pid_after: str,
        app_crashed: bool,
        rasp_detected: bool,
        scan_stdout: str,
        scan_stderr: str,
    ) -> dict[str, Any]:
        finished = datetime.now(timezone.utc)
        events, event_files = self.load_frida_events()
        flows_count, flow_files = self.count_mitm_flows()
        rpc_by_agent = extract_rpc_summaries(scan_result)
        finding_counts = Counter(
            f.get("agent_id", "")
            for f in scan_result.get("findings", [])
            if isinstance(f, dict)
        )

        agent_rows = [
            self.agent_health(
                agent_id=agent_id,
                events=events,
                flows_count=flows_count,
                app_crashed=app_crashed,
                rpc_summary=rpc_by_agent.get(agent_id, {}),
                sast_findings=finding_counts.get(agent_id, 0),
            )
            for agent_id in TARGET_AGENTS
        ]
        notes = []
        if not event_files:
            notes.append(
                "No frida_events.jsonl file found. Current SENTINEL keeps Frida "
                "events in memory; hook fire rate is inferred only from any "
                "persisted JSONL files or RPC summaries.",
            )
        if flows_count == 0:
            notes.append(
                "No mitmproxy flows captured. Causes: no app interaction, "
                "pinning/bypass failure, proxy refusal, or app blocked traffic.",
            )
        if rasp_detected:
            notes.append("RASP/frida detection suspected; treated as tool-health signal.")

        return {
            "package": self.package,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round((finished - started).total_seconds(), 2),
            "scan_status": scan_status,
            "preflight": self.preflight,
            "stability": {
                "pid_before": app_pid_before,
                "pid_after": app_pid_after,
                "app_crashed": app_crashed,
                "rasp_detected": rasp_detected,
            },
            "artifacts": {
                "apk_path": str(self.apk_path) if self.apk_path else "",
                "workspace_root": str(self.workspace_root),
                "session_workspace": str(self.session_workspace or ""),
                "scan_output": str(self.scan_output or ""),
                "scan_log": str(self.scan_log or ""),
                "frida_event_files": [str(p) for p in event_files],
                "mitm_flow_files": [str(p) for p in flow_files],
                "report_path": str(self.report_path),
            },
            "traffic": {
                "mitmproxy_flow_count": flows_count,
                "captured": flows_count > 0,
            },
            "hook_fire_rate": dict(Counter(e.get("kind", "unknown") for e in events)),
            "agent_health": [asdict(row) for row in agent_rows],
            "scan_warnings": scan_result.get("warnings", []),
            "notes": notes,
            "cleanup": self.cleanup_actions,
            "stdout_tail": scan_stdout[-4000:],
            "stderr_tail": scan_stderr[-4000:],
        }

    def agent_health(
        self,
        *,
        agent_id: str,
        events: list[dict[str, Any]],
        flows_count: int,
        app_crashed: bool,
        rpc_summary: dict[str, Any],
        sast_findings: int,
    ) -> AgentHealth:
        hints = HOOK_KIND_HINTS.get(agent_id, ())
        matched = [
            e for e in events
            if any(hint in str(e.get("kind", "")).lower() for hint in hints)
            or any(hint in json.dumps(e, default=str).lower() for hint in hints)
        ]
        hook_fired: bool | None = bool(matched)
        notes: list[str] = []
        if not events:
            hook_fired = None
            notes.append("No persisted Frida event file available.")
        if rpc_summary:
            hook_fired = True
            notes.append("RPC dispatch summary present.")
            for key in RPC_RESULT_KEYS.get(agent_id, ()):
                if key in rpc_summary:
                    notes.append(f"{key}={rpc_summary[key]}")
        if agent_id == "D_087":
            hook_fired = None
            notes.append("D_087 is not present in this repository checkout.")
        if sast_findings:
            notes.append(f"{sast_findings} SAST target finding(s) emitted.")
        if agent_id in {"D_063", "D_065", "D_073", "D_074", "D_084"} and not sast_findings:
            notes.append("No matching SAST target emitted in this run.")
        return AgentHealth(
            agent_id=agent_id,
            hook_fired=hook_fired,
            hook_event_count=len(matched),
            traffic_captured=(flows_count > 0) if agent_id in {"D_063", "D_084"} else None,
            app_crashed=app_crashed,
            notes=notes,
            rpc_summary=rpc_summary,
            sast_findings=sast_findings,
        )

    def load_frida_events(self) -> tuple[list[dict[str, Any]], list[Path]]:
        roots = [p for p in [self.session_workspace, self.workspace_root] if p]
        candidates: list[Path] = []
        for root in roots:
            if root.exists():
                candidates.extend(root.rglob("*frida*events*.jsonl"))
                candidates.extend(root.rglob("frida_events.jsonl"))
        events: list[dict[str, Any]] = []
        files = sorted(set(candidates))
        for path in files:
            events.extend(read_jsonl(path))
        return events, files

    def count_mitm_flows(self) -> tuple[int, list[Path]]:
        roots = [p for p in [self.session_workspace, self.workspace_root] if p]
        candidates: list[Path] = []
        for root in roots:
            if root.exists():
                candidates.extend(root.rglob("mitm_capture.jsonl"))
                candidates.extend(root.rglob("mitmproxy_flows.jsonl"))
        files = sorted(set(candidates))
        count = 0
        for path in files:
            for record in read_jsonl(path):
                if "error" not in record:
                    count += 1
        return count, files


def parse_pm_paths(stdout: str) -> list[str]:
    paths = []
    for line in stdout.splitlines():
        if line.startswith("package:"):
            paths.append(line.split("package:", 1)[1].strip())
    return paths


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                records.append({"kind": "parse_error", "raw": line[:300]})
                continue
            if isinstance(value, dict):
                records.append(value)
            else:
                records.append({"kind": "non_object", "value": value})
    except OSError:
        return []
    return records


def extract_rpc_summaries(scan_result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Best-effort extraction from future persisted dispatch evidence."""
    out: dict[str, dict[str, Any]] = {}
    for finding in scan_result.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        agent_id = finding.get("agent_id")
        evidence = finding.get("evidence") or {}
        if not isinstance(agent_id, str) or not isinstance(evidence, dict):
            continue
        for key in ("dispatch_result", "frida_result", "runtime_result"):
            value = evidence.get(key)
            if isinstance(value, dict):
                out[agent_id] = value
                break
    return out


def detect_rasp(
    stdout: str,
    stderr: str,
    scan_result: dict[str, Any],
    app_crashed: bool,
) -> bool:
    text = "\n".join([
        stdout[-8000:],
        stderr[-8000:],
        "\n".join(map(str, scan_result.get("warnings", []))),
        str(scan_result.get("error", "")),
    ]).lower()
    needles = (
        "frida detection",
        "rasp",
        "anti-frida",
        "ptrace",
        "processnotfound",
        "not running on device",
        "crashed",
        "sigabrt",
        "connection closed",
    )
    return app_crashed and any(needle in text for needle in needles)


def first_version(text: str) -> str:
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", text)
    return match.group(1) if match else ""


def major(version: str) -> str:
    return version.split(".", 1)[0]


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "package"


def print_table(report: dict[str, Any]) -> None:
    print("\nTool Health Report")
    print("| Agent ID | Hook Fired? | Traffic Captured? | App Crashed? | Notes |")
    print("| :--- | :--- | :--- | :--- | :--- |")
    for row in report["agent_health"]:
        hook = tri_state(row["hook_fired"])
        traffic = tri_state(row["traffic_captured"])
        crashed = "❌ No" if not row["app_crashed"] else "✅ Yes"
        notes = "; ".join(row["notes"]) or "-"
        print(f"| {row['agent_id']} | {hook} | {traffic} | {crashed} | {notes} |")


def tri_state(value: bool | None) -> str:
    if value is True:
        return "✅ Yes"
    if value is False:
        return "❌ No"
    return "N/A"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate SENTINEL dynamic-agent health against an installed Android package.",
    )
    parser.add_argument("package_name", help="Installed package name, e.g. com.coinhako.android")
    parser.add_argument("--adb", default="adb", help="adb binary path")
    parser.add_argument("--serial", default="", help="ADB serial to target")
    parser.add_argument(
        "--sentinel-cmd",
        nargs="+",
        default=["poetry", "run", "sentinel"],
        help="Command prefix for SENTINEL CLI, default: poetry run sentinel",
    )
    parser.add_argument("--workspace", type=Path, default=Path("./workspace/realworld-validation"))
    parser.add_argument("--data-dir", type=Path, default=Path("./data/realworld-validation"))
    parser.add_argument("--apk-path", type=Path, default=None, help="Use this APK instead of pulling base.apk")
    parser.add_argument("--dynamic-duration", type=int, default=60)
    parser.add_argument("--frida-duration", type=int, default=60)
    parser.add_argument("--frida-spawn", action="store_true", help="Use Frida spawn mode")
    parser.add_argument("--skip-scan", action="store_true", help="Only preflight and cleanup")
    parser.add_argument("--force", action="store_true", help="Run scan even if preflight is degraded")
    parser.add_argument(
        "--kill-frida-server",
        action="store_true",
        help="Also kill frida-server during cleanup. Default keeps server running.",
    )
    parser.add_argument("--report", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validator = RealWorldValidator(args)
    report = validator.validate()
    validator.report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print_table(report)
    print(f"\nReport saved: {validator.report_path}")
    if report["scan_status"] == "preflight_failed":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
