"""SENTINEL command-line interface.

Subcommands:
    serve         Launch the FastAPI gateway
    scan          Run a real scan against an APK
    scope parse   Parse a bug bounty scope (URL/file/text)
    agents        List available analysis agents
    status        Show configuration and connectivity
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

# ---------- Silence noisy third-party libraries ----------
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "True")
os.environ.setdefault("POSTHOG_DISABLED", "True")
os.environ.setdefault("DO_NOT_TRACK", "1")
warnings.filterwarnings("ignore", category=DeprecationWarning)

for noisy in (
    "androguard", "androguard.core", "androguard.core.apk",
    "androguard.core.axml", "androguard.core.api_specific_resources",
    "chromadb", "chromadb.telemetry", "chromadb.telemetry.product",
    "chromadb.telemetry.product.posthog",
    "posthog", "urllib3",
):
    logging.getLogger(noisy).setLevel(logging.CRITICAL)

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="WARNING")
except ImportError:
    pass

import click
from rich.console import Console
from rich.table import Table

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)
console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="sentinel")
def main() -> None:
    """SENTINEL — multi-agent mobile application security scanner."""


@main.command()
@click.option("--host", default="127.0.0.1", help="Bind host (default: localhost)")
@click.option("--port", default=8000, type=int, help="Bind port (default: 8000)")
@click.option("--reload", is_flag=True, help="Enable hot-reload (development)")
def serve(host: str, port: int, reload: bool) -> None:
    """Launch the FastAPI gateway."""
    import uvicorn
    console.print(f"[bold cyan]SENTINEL gateway starting on {host}:{port}[/]")
    console.print(f"[dim]API docs:  http://{host}:{port}/docs[/]")
    console.print(f"[dim]Health:    http://{host}:{port}/health[/]")
    uvicorn.run(
        "sentinel.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


@main.command()
@click.argument("apk_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--scope-url", type=str, default=None,
              help="Bug bounty scope from a URL")
@click.option("--scope-file", type=click.Path(exists=True, path_type=Path), default=None,
              help="Bug bounty scope from a JSON or text file")
@click.option("--scope-text", type=str, default=None,
              help="Bug bounty scope as inline text")
@click.option("--data-dir", type=click.Path(path_type=Path), default=Path("./data"),
              help="Directory for SENTINEL's persistent memory")
@click.option("--workspace", type=click.Path(path_type=Path), default=Path("./workspace"),
              help="Directory for per-scan working files")
@click.option("--output", "--json-output", "output",
              type=click.Path(path_type=Path), default=None,
              help="Optional path to write scan summary as JSON "
                   "(--json-output is an alias)")
@click.option("--static-only", "static_only", is_flag=True,
              help="Explicit static-only mode: refuse --dynamic / --frida. "
                   "Default mode is already static; this flag fails fast "
                   "when a caller accidentally combines the two intents.")
@click.option("--private", is_flag=True,
              help="Force local LLM only — no cloud API calls (forces Ollama)")
@click.option("--no-triage", is_flag=True,
              help="Disable LLM triage (faster, but more false positives)")
@click.option("--show-filtered", is_flag=True,
              help="Show findings the LLM filtered as false positives")
@click.option("--dynamic", is_flag=True,
              help="Enable Phase 4 dynamic analysis (requires a connected "
                   "Android device with mitmproxy CA cert trusted)")
@click.option("--dynamic-duration", type=int, default=30,
              help="Seconds to capture traffic during Phase 4 (default: 30)")
@click.option("--dynamic-port", type=int, default=8082,
              help="Local port for mitmproxy in Phase 4 (default: 8082)")
@click.option("--frida", is_flag=True,
              help="Enable Frida runtime hooks (requires --dynamic and "
                   "zygiskfrida on phone). Adds A_003 runtime crypto and "
                   "N_005 cert pinning bypass agents.")
@click.option("--frida-duration", type=int, default=20,
              help="Seconds to run Frida hooks during Phase 4 (default: 20). "
                   "Runs AFTER mitmproxy capture.")
@click.option("--frida-spawn", is_flag=True,
              help="Start the target app under Frida control instead of "
                   "attaching to a running instance. Use for apps that "
                   "detect Frida at startup and crash, or that you want "
                   "instrumented before any of their own code runs. "
                   "Implies --frida.")
@click.option("--no-proxy", is_flag=True,
              help="Skip mitmproxy and device proxy configuration during "
                   "Phase 4. Useful for apps with anti-MITM detection that "
                   "refuse to run when a proxy is set (Signal, banking apps, "
                   "secure messengers). Frida hooks still fire normally; "
                   "mitmproxy-based agents (N_003/N_004) produce no findings.")
@click.option("--keep-workspace", is_flag=True,
              help="Keep the per-scan workspace directory "
                   "(decompiled sources, mitmproxy capture, frida events) "
                   "after the scan finishes. Default is to delete it — "
                   "useful when debugging an agent or re-running triage.")
@click.option("--profile", "profile_name", type=str, default=None,
              help="App-category profile (banking, edu, ecommerce, or a path "
                   "to a custom .json). Reorders the agent roster so the "
                   "agents most relevant to the category run first; "
                   "coverage is unchanged.")
@click.option("--generate-patch", "generate_patch", is_flag=True,
              help="EXPERIMENTAL: ask the LLM to suggest a unified-diff "
                   "fix for each VERIFIED finding. Patches are "
                   "suggestions for human review — they are NEVER "
                   "auto-applied and are written against decompiled "
                   "code, so a literal `patch -p1` will not work. "
                   "See docs/REMEDIATION.md. Requires triage (cannot "
                   "be combined with --no-triage).")
@click.option("--patches-dir", "patches_dir",
              type=click.Path(path_type=Path),
              default=Path("./output/patches"),
              help="Directory to write suggested patches into when "
                   "--generate-patch is set. One .diff file per "
                   "VERIFIED finding.")
def scan(
    apk_path: Path,
    scope_url: str | None,
    scope_file: Path | None,
    scope_text: str | None,
    data_dir: Path,
    workspace: Path,
    output: Path | None,
    private: bool,
    no_triage: bool,
    show_filtered: bool,
    dynamic: bool,
    dynamic_duration: int,
    dynamic_port: int,
    frida: bool,
    frida_duration: int,
    frida_spawn: bool,
    no_proxy: bool,
    keep_workspace: bool,
    profile_name: str | None,
    static_only: bool,
    generate_patch: bool,
    patches_dir: Path,
) -> None:
    """Run a security scan against an APK file."""
    if static_only and (dynamic or frida or frida_spawn):
        raise click.UsageError(
            "--static-only cannot be combined with --dynamic / --frida / "
            "--frida-spawn",
        )
    if generate_patch and no_triage:
        raise click.UsageError(
            "--generate-patch requires LLM triage (it only patches "
            "VERIFIED findings). Drop --no-triage or drop "
            "--generate-patch.",
        )
    asyncio.run(_run_scan(
        apk_path=apk_path,
        scope_url=scope_url,
        scope_file=scope_file,
        scope_text=scope_text,
        data_dir=data_dir,
        workspace=workspace,
        output=output,
        private=private,
        no_triage=no_triage,
        show_filtered=show_filtered,
        dynamic=dynamic,
        dynamic_duration=dynamic_duration,
        dynamic_port=dynamic_port,
        frida=frida,
        frida_duration=frida_duration,
        frida_spawn=frida_spawn,
        no_proxy=no_proxy,
        keep_workspace=keep_workspace,
        profile_name=profile_name,
        generate_patch=generate_patch,
        patches_dir=patches_dir,
    ))


async def _run_scan(
    apk_path: Path,
    scope_url: str | None,
    scope_file: Path | None,
    scope_text: str | None,
    data_dir: Path,
    workspace: Path,
    output: Path | None,
    private: bool,
    no_triage: bool,
    show_filtered: bool,
    dynamic: bool,
    dynamic_duration: int,
    dynamic_port: int,
    frida: bool,
    frida_duration: int,
    frida_spawn: bool,
    no_proxy: bool,
    keep_workspace: bool,
    profile_name: str | None = None,
    generate_patch: bool = False,
    patches_dir: Path = Path("./output/patches"),
) -> None:
    """Async implementation of the scan command."""
    from sentinel.agents.auth import (
        BiometricBypassAgent,
        HardcodedSecretsAgent,
        TapJackingAgent,
    )
    from sentinel.agents.auth_storage import InsecureAuthStorageAgent
    from sentinel.agents.backup import InsecureBackupAgent
    from sentinel.agents.business import (
        IapBypassAgent,
        RaceConditionAgent,
        RestIdorAgent,
    )
    from sentinel.agents.cert_pinning import MissingCertPinningAgent
    from sentinel.agents.cloud import FirebaseMisconfigAgent
    from sentinel.agents.crossplatform import FlutterAgent, ReactNativeAgent
    from sentinel.agents.crypto import (
        EcbModeAgent,
        HardcodedCryptoKeysAgent,
        KeystoreMisuseAgent,
        SQLCipherKeyDerivationAgent,
        WeakCryptoAgent,
    )
    from sentinel.agents.data_storage import WorldReadableStorageAgent
    from sentinel.agents.dynamic import (
        CertPinningBypassAgent,
        DataInTransitAgent,
        ImproperTLSAgent,
        RuntimeCryptoAgent,
    )
    from sentinel.agents.logging import InsecureLoggingAgent
    from sentinel.agents.meta import ObfuscationDetectorAgent
    from sentinel.agents.native import NativeLibraryAgent
    from sentinel.agents.network import (
        ApiKeyLeakageAgent,
        CleartextTrafficAgent,
        GraphqlFuzzerAgent,
        GraphqlIntrospectionAgent,
        InsecureTrustManagerAgent,
        WebViewDebugFlagAgent,
    )
    from sentinel.agents.platform import (
        ContentProviderIDORAgent,
        DeepLinkHijackAgent,
        ExcessivePermissionsAgent,
        IntentRedirectAgent,
        IpcExposureAgent,
        MutablePendingIntentAgent,
        ReceiverChainHijackAgent,
    )
    from sentinel.agents.random_gen import InsecureRandomAgent
    from sentinel.agents.resilience import AntiTamperAgent
    from sentinel.agents.semgrep import SemgrepAgent
    from sentinel.agents.shared_prefs import (
        InsecureFileProviderAgent,
        InsecureSharedPrefsAgent,
    )
    from sentinel.agents.special import PipelineSmokeTestAgent
    from sentinel.agents.supply_chain import SCAAgent
    from sentinel.agents.taint import TaintAgent
    from sentinel.agents.webview import InsecureWebViewAgent
    from sentinel.core.finding import BountyScope
    from sentinel.core.orchestrator import Orchestrator
    from sentinel.core.scan_context import ScanContext, generate_session_id
    from sentinel.llm.router import FreeProviderRouter
    from sentinel.memory import LightweightMemory
    from sentinel.scope import parse_scope
    from sentinel.triage import LLMTriager

    console.rule("[bold cyan]SENTINEL Scan[/]")
    console.print(f"[bold]APK:[/]       {apk_path}")
    console.print(f"[bold]Workspace:[/] {workspace}")
    console.print(f"[bold]Memory:[/]    {data_dir}")
    if private:
        console.print("[bold yellow]Privacy mode:[/] local LLM only")
    if no_triage:
        console.print("[bold yellow]Triage disabled:[/] all findings unfiltered")
    # --frida-spawn implies --frida
    if frida_spawn and not frida:
        frida = True
    if frida and not dynamic:
        console.print(
            "[bold red]--frida requires --dynamic. Frida hooks attach to the "
            "running app after Phase 4 traffic capture.[/]",
        )
        return
    if dynamic:
        if no_proxy:
            console.print(
                "[bold yellow]Dynamic analysis enabled (--no-proxy mode):[/] "
                "mitmproxy + device proxy SKIPPED. N_003/N_004 will not fire. "
                "Useful for apps that refuse to run under MITM.",
            )
        else:
            console.print(
                f"[bold yellow]Dynamic analysis enabled:[/] "
                f"capture {dynamic_duration}s of traffic via mitmproxy on port "
                f"{dynamic_port}",
            )
        if frida:
            console.print(
                f"[bold yellow]Frida runtime hooks enabled:[/] "
                f"capture {frida_duration}s of runtime crypto/security events "
                f"(via zygiskfrida)",
            )
        console.print(
            "[dim]Connect a rooted Android device with mitmproxy CA cert "
            "trusted. Interact with the app during the capture window.[/]",
        )
    console.print()

    scope = BountyScope()
    if scope_url or scope_file or scope_text:
        try:
            scope = parse_scope(
                url=scope_url,
                file=scope_file,
                text=scope_text,
            )
            console.print(f"[bold green]Scope:[/] {scope.program_name or '(unnamed)'} "
                          f"on {scope.platform or '(unknown platform)'}")
            if scope.in_scope_packages:
                console.print(f"[dim]  In-scope packages: {len(scope.in_scope_packages)}[/]")
        except Exception as e:
            console.print(f"[bold red]Scope parse failed:[/] {e}")
            console.print("[dim]Continuing with empty scope.[/]")
    else:
        console.print("[dim]No scope provided — treating all findings as in-scope.[/]")

    console.print()

    memory = LightweightMemory(data_dir=data_dir)
    await memory.connect()

    # Build the LLM triager unless disabled
    router: FreeProviderRouter | None = None
    triager: LLMTriager | None = None
    if not no_triage:
        router = FreeProviderRouter(force_local=private)
        triager = LLMTriager(router=router)

    try:
        ctx = ScanContext(
            session_id=generate_session_id(),
            apk_path=apk_path,
            workspace=workspace,
            scope=scope,
        )

        console.print(f"[bold]Session:[/]   {ctx.session_id}")
        console.print()

        # Build the agent list. Dynamic agents only run when --dynamic is
        # passed (their is_applicable() also gates on ctx.sources['mitmproxy'],
        # so adding them when --dynamic is off would just be a no-op).
        agent_list: list = [
            # Meta — runs first, sets context for the rest
            ObfuscationDetectorAgent,         # META_001
            # Smoke test
            PipelineSmokeTestAgent,           # TEST_001
            # SAST agents (alphabetical by ID)
            InsecureAuthStorageAgent,         # A_001
            HardcodedSecretsAgent,            # A_004
            InsecureLoggingAgent,             # A_007
            BiometricBypassAgent,             # A_008
            TapJackingAgent,                  # A_009 (overlay touch-filter audit)
            RestIdorAgent,                    # B_001
            InsecureRandomAgent,              # B_002
            RaceConditionAgent,               # B_003
            IapBypassAgent,                   # B_004
            InsecureBackupAgent,              # C_001
            WorldReadableStorageAgent,        # C_002
            InsecureWebViewAgent,             # C_004
            HardcodedCryptoKeysAgent,         # C_005
            EcbModeAgent,                     # C_006
            WeakCryptoAgent,                  # C_007
            SQLCipherKeyDerivationAgent,      # C_010 (SQLCipher KDF audit)
            KeystoreMisuseAgent,              # C_011
            FirebaseMisconfigAgent,           # F_001
            MissingCertPinningAgent,          # N_001
            CleartextTrafficAgent,            # N_002
            ApiKeyLeakageAgent,               # N_006
            GraphqlIntrospectionAgent,        # N_007
            InsecureTrustManagerAgent,        # N_008 (TLS-bypass TrustManager / HostnameVerifier)
            WebViewDebugFlagAgent,            # N_009 (ungated WebView remote debug)
            GraphqlFuzzerAgent,               # N_011
            DeepLinkHijackAgent,              # P_001
            ExcessivePermissionsAgent,        # P_005 (manifest sensitive-perm audit)
            ContentProviderIDORAgent,         # P_004
            IntentRedirectAgent,              # P_010 (CWE-926 AST)
            ReceiverChainHijackAgent,         # P_011 (exported-receiver chain hijack)
            MutablePendingIntentAgent,        # P_012 (CVE-2021-0938 family)
            IpcExposureAgent,                 # IPC_001 (Phase B)
            NativeLibraryAgent,               # NL_001 (Phase B)
            AntiTamperAgent,                  # RES_001 (Phase B)
            SCAAgent,                         # SCA_001 (supply chain CVE scanner)
            TaintAgent,                       # TAINT_001 (data-flow taint analysis)
            ReactNativeAgent,                 # RN_001 (React Native bundle audit)
            FlutterAgent,                     # FL_001 (Flutter libapp.so string scan)
            SemgrepAgent,                     # SG_001 (AST pattern SAST)
            InsecureSharedPrefsAgent,         # STG_006 (renamed from C_006)
            InsecureFileProviderAgent,        # STG_007 (FileProvider path audit)
        ]
        if dynamic:
            agent_list.extend([
                ImproperTLSAgent,             # N_003 (Sprint 8.1 DAST)
                DataInTransitAgent,           # N_004 (Sprint 8.1 DAST)
            ])
        if dynamic and frida:
            agent_list.append(RuntimeCryptoAgent)        # A_003 (Sprint 8.2A DAST)
            agent_list.append(CertPinningBypassAgent)    # N_005 (Sprint 8.2B DAST)

        if profile_name:
            from sentinel.profiles import load_profile
            try:
                profile = load_profile(profile_name)
            except (FileNotFoundError, ValueError) as e:
                console.print(f"[bold red]Profile error:[/] {e}")
                return
            agent_list = profile.reorder(agent_list)
            missing = profile.missing_from(agent_list)
            console.print(f"[bold]Profile:[/]   {profile.label} "
                          f"({len(profile.priority_agents) - len(missing)} "
                          f"priority agents prioritized)")
            if missing:
                console.print(
                    f"[dim]  Profile lists {len(missing)} agent(s) not in "
                    f"roster: {', '.join(missing)}[/]",
                )

        orch = Orchestrator(
            context=ctx,
            memory=memory,
            agents=agent_list,
            triager=triager,
            dynamic_enabled=dynamic,
            dynamic_duration_seconds=dynamic_duration,
            dynamic_port=dynamic_port,
            frida_enabled=frida,
            frida_duration_seconds=frida_duration,
            frida_spawn=frida_spawn,
            proxy_enabled=not no_proxy,
        )

        # Status message reflects which optional phases are enabled
        if dynamic and frida and triager:
            status_msg = (
                "[bold cyan]Running scan with DAST + Frida + LLM triage "
                f"(at least {dynamic_duration + frida_duration}s + 1-3 min "
                "triage)...[/]"
            )
        elif dynamic and frida:
            status_msg = (
                f"[bold cyan]Running scan with DAST + Frida (at least "
                f"{dynamic_duration + frida_duration}s)...[/]"
            )
        elif dynamic and triager:
            status_msg = (
                "[bold cyan]Running scan with DAST capture + LLM triage "
                f"(at least {dynamic_duration}s + 1-3 min triage)...[/]"
            )
        elif dynamic:
            status_msg = (
                f"[bold cyan]Running scan with DAST capture (at least "
                f"{dynamic_duration}s)...[/]"
            )
        elif triager:
            status_msg = (
                "[bold cyan]Running scan with LLM triage "
                "(this may take 1-3 min)...[/]"
            )
        else:
            status_msg = "[bold cyan]Running scan...[/]"

        with console.status(status_msg, spinner="dots"):
            result = await orch.run()

        _print_summary(ctx, result)

        if result.findings:
            _print_findings(result.findings, show_filtered=show_filtered)
        else:
            console.print("[dim]No findings produced.[/]")

        if generate_patch and router is not None and result.findings:
            written = await _generate_and_write_patches(
                router=router,
                findings=result.findings,
                patches_dir=patches_dir,
            )
            console.print(
                f"\n[bold yellow]AI Suggested Patches:[/] "
                f"{written} written to {patches_dir} "
                f"(human review required — see docs/REMEDIATION.md)",
            )

        if output:
            _write_json_output(output, ctx, result)
            console.print(f"\n[bold green]Wrote summary to:[/] {output}")

    finally:
        if router is not None:
            await router.close()
        await memory.close()
        try:
            await orch.cleanup(keep_workspace=keep_workspace)
        except NameError:
            # Orchestrator never got constructed — nothing to clean
            pass
        except Exception:  # noqa: BLE001
            logger.exception("Workspace cleanup failed")


async def _generate_and_write_patches(
    router,
    findings,
    patches_dir: Path,
) -> int:
    """Generate suggested patches for VERIFIED findings and write each
    to ``patches_dir/<finding_id>.diff``. Returns the number of files
    written.

    Errors in patch generation are non-fatal — they downgrade to
    ``patch_status=UNAVAILABLE`` per-finding and we keep going.
    """
    from sentinel.llm.remediation import (
        PATCH_STATUS_SUGGESTED,
        RemediationGenerator,
        render_diff_file,
    )

    gen = RemediationGenerator(router=router)
    with console.status(
        "[bold yellow]Generating AI-suggested patches (review required)…[/]",
        spinner="dots",
    ):
        await gen.generate_patches(findings)

    patches_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for f in findings:
        ev = f.evidence or {}
        if ev.get("patch_status") != PATCH_STATUS_SUGGESTED:
            continue
        body = render_diff_file(f)
        if body is None:
            continue
        target = patches_dir / f"{f.finding_id}.diff"
        try:
            target.write_text(body)
            written += 1
        except OSError as e:
            logger.warning("[remediation] cannot write %s: %s", target, e)
    return written


def _print_summary(ctx, result) -> None:
    """Print a Rich table summarising the scan."""
    table = Table(title="Scan Summary", show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold")
    table.add_column("Value")

    status_colour = {
        "completed": "green",
        "failed": "red",
        "pending": "yellow",
    }.get(result.status, "white")

    table.add_row("Status", f"[{status_colour}]{result.status}[/]")
    table.add_row("Session ID", ctx.session_id)
    table.add_row("SHA-256", ctx.apk_sha256 or "(not computed)")
    table.add_row("Size", f"{ctx.apk_size_bytes:,} bytes" if ctx.apk_size_bytes else "(unknown)")

    if ctx.manifest:
        m = ctx.manifest
        table.add_row("Package", m.get("package", "(unknown)"))
        table.add_row("Version", m.get("version_name", "(unknown)"))
        table.add_row("Min SDK", str(m.get("min_sdk", 0)))
        table.add_row("Target SDK", str(m.get("target_sdk", 0)))
        table.add_row("Permissions", str(len(m.get("permissions", []))))
        table.add_row("Activities", str(len(m.get("activities", []))))
        table.add_row("Exported components", str(len(m.get("exported_components", []))))
        table.add_row("Deep links", str(len(m.get("deep_links", []))))

        risky = []
        if m.get("debuggable"):
            risky.append("debuggable=true")
        if m.get("allow_backup"):
            risky.append("allowBackup=true")
        if m.get("uses_cleartext_traffic"):
            risky.append("cleartext-traffic=true")
        if risky:
            table.add_row("Risky flags", "[yellow]" + ", ".join(risky) + "[/]")

    java_count = 0
    if ctx.decompiled_dir and ctx.decompiled_dir.exists():
        java_count = sum(1 for _ in ctx.decompiled_dir.rglob("*.java"))
    table.add_row("Java files", str(java_count))

    table.add_row("Findings", str(len(result.findings)))

    # Triage outcome breakdown if triage ran
    triage_breakdown = _count_triage_outcomes(result.findings)
    if triage_breakdown:
        verified = triage_breakdown.get("verified", 0)
        filtered = triage_breakdown.get("filtered", 0)
        uncertain = triage_breakdown.get("uncertain", 0)
        line = f"[green]{verified} verified[/]"
        if filtered:
            line += f", [dim]{filtered} filtered[/]"
        if uncertain:
            line += f", [yellow]{uncertain} uncertain[/]"
        table.add_row("  Triage", line)

    for phase, dur in result.phase_timings.items():
        table.add_row(f"  {phase}", f"{dur:.2f}s")

    if result.warnings:
        table.add_row(
            "[yellow]Warnings[/]",
            f"[yellow]{len(result.warnings)}[/]",
        )
        # Print warnings without truncation — Rich auto-wraps the cell to
        # terminal width. The previous w[:120] cap was hiding diagnostic
        # info (running-process lists, full error contexts).
        for i, w in enumerate(result.warnings[:10], 1):
            table.add_row(f"  [dim]warn {i}[/]", f"[dim]{w}[/]")

    if result.error:
        table.add_row("[red]Error[/]", f"[red]{result.error}[/]")

    console.print(table)


def _count_triage_outcomes(findings) -> dict[str, int]:
    """Count triage outcomes across findings. Returns empty dict if no triage."""
    counts: dict[str, int] = {}
    for f in findings:
        ev = getattr(f, "evidence", None) or {}
        triage_data = ev.get("_triage")
        if not triage_data or not isinstance(triage_data, dict):
            continue
        outcome = triage_data.get("outcome")
        if outcome:
            counts[outcome] = counts.get(outcome, 0) + 1
    return counts


def _print_findings(findings, show_filtered: bool = False) -> None:
    """Print findings as a Rich table with severity colouring + triage state."""
    # Filter the table rows. FILTERED findings are hidden unless --show-filtered.
    visible = []
    hidden_count = 0
    for f in findings:
        ev = getattr(f, "evidence", None) or {}
        triage_data = ev.get("_triage")
        outcome = (triage_data or {}).get("outcome") if isinstance(triage_data, dict) else None
        if outcome == "filtered" and not show_filtered:
            hidden_count += 1
            continue
        visible.append(f)

    if not visible:
        if hidden_count > 0:
            console.print(
                f"\n[dim]All {hidden_count} findings filtered as false positives "
                f"by LLM triage. Pass --show-filtered to view them.[/]"
            )
        return

    table = Table(title="\nFindings", show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Agent", width=10)
    table.add_column("Class", width=22)
    table.add_column("Triage", width=10)
    table.add_column("Conf.", width=6)
    # No fixed width on Recommendation — Rich auto-wraps the column to the
    # remaining terminal width. Previously this cell was clipped to 80
    # chars in code which dropped the most actionable text of every
    # finding; the clip is gone.
    table.add_column("Recommendation", overflow="fold")

    severity_colours = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Info": "dim",
    }

    triage_styles = {
        "verified": ("✓ verified", "green"),
        "filtered": ("✗ filtered", "dim red"),
        "uncertain": ("? uncertain", "yellow"),
        "skipped": ("- skipped", "dim"),
    }

    for f in visible:
        sev = f.severity.value
        colour = severity_colours.get(sev, "white")

        ev = getattr(f, "evidence", None) or {}
        triage_data = ev.get("_triage") if isinstance(ev, dict) else None
        outcome = (triage_data or {}).get("outcome") if isinstance(triage_data, dict) else None
        if outcome and outcome in triage_styles:
            triage_label, triage_colour = triage_styles[outcome]
            triage_cell = f"[{triage_colour}]{triage_label}[/]"
        else:
            triage_cell = "[dim]—[/]"

        table.add_row(
            f"[{colour}]{sev}[/]",
            f.agent_id,
            f.vuln_class[:22],
            triage_cell,
            f"{f.confidence:.2f}",
            f.recommendation,
        )

    console.print(table)

    if hidden_count > 0 and not show_filtered:
        console.print(
            f"\n[dim]({hidden_count} additional finding(s) filtered as false "
            f"positives — pass --show-filtered to view)[/]"
        )


def _write_json_output(output: Path, ctx, result) -> None:
    """Write scan summary as JSON for downstream consumption."""
    import json

    summary = {
        "session_id": ctx.session_id,
        "status": result.status,
        "apk_path": str(ctx.apk_path),
        "apk_sha256": ctx.apk_sha256,
        "apk_size_bytes": ctx.apk_size_bytes,
        "manifest": ctx.manifest,
        "phase_timings": result.phase_timings,
        "started_at": result.started_at.isoformat() if result.started_at else None,
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "error": result.error,
        "triage_breakdown": _count_triage_outcomes(result.findings),
        "findings": [
            {
                "finding_id": f.finding_id,
                "agent_id": f.agent_id,
                "vuln_class": f.vuln_class,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "recommendation": f.recommendation,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, default=str))


@main.group()
def scope() -> None:
    """Bug bounty scope utilities."""


@scope.command("parse")
@click.option("--url", type=str, default=None, help="Scope URL")
@click.option("--file", "file_path", type=click.Path(exists=True, path_type=Path),
              default=None, help="Scope file (JSON or text)")
@click.option("--text", type=str, default=None, help="Inline scope text")
@click.option("--json", "as_json", is_flag=True, help="Output JSON instead of table")
def scope_parse(
    url: str | None,
    file_path: Path | None,
    text: str | None,
    as_json: bool,
) -> None:
    """Parse a bug bounty scope from URL, file, or text."""
    from sentinel.scope import parse_scope

    if not any([url, file_path, text]):
        raise click.UsageError("Provide --url, --file, or --text")

    try:
        scope_obj = parse_scope(url=url, file=file_path, text=text)
    except Exception as e:
        console.print(f"[bold red]Scope parse failed:[/] {e}")
        raise click.Abort() from e

    if as_json:
        import json
        click.echo(json.dumps(scope_obj.model_dump(), indent=2, default=str))
        return

    table = Table(title="Parsed Scope", show_header=False, box=None)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Program", scope_obj.program_name or "(unknown)")
    table.add_row("Platform", scope_obj.platform or "(unknown)")
    table.add_row("In-scope packages", str(len(scope_obj.in_scope_packages)))
    table.add_row("In-scope domains", str(len(scope_obj.in_scope_domains)))
    table.add_row("Out-of-scope packages", str(len(scope_obj.out_of_scope_packages)))
    table.add_row("Forbidden techniques", ", ".join(sorted(scope_obj.forbidden_techniques)) or "(none)")
    if scope_obj.reward_ranges:
        for sev, (lo, hi) in scope_obj.reward_ranges.items():
            table.add_row(f"  Reward ({sev})", f"${lo:,} – ${hi:,}")
    console.print(table)


@main.command("agents")
@click.option("--category", type=str, default=None,
              help="Filter by category")
def list_agents(category: str | None) -> None:
    """List available agents (queries the local gateway)."""
    import httpx

    url = "http://127.0.0.1:8000/agents"
    params = {"category": category} if category else {}

    try:
        resp = httpx.get(url, params=params, timeout=5.0)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        console.print(f"[bold red]Cannot reach gateway:[/] {e}")
        console.print("[dim]Start it first with:  poetry run sentinel serve[/]")
        return
    except Exception as e:
        console.print(f"[bold red]Cannot reach gateway:[/] {e}")
        console.print("[dim]Start it first with:  poetry run sentinel serve[/]")
        return

    agents = resp.json()
    if not agents:
        console.print("[dim]No agents found.[/]")
        return

    table = Table(title=f"Agents ({len(agents)})", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="bold", width=10)
    table.add_column("Category", width=18)
    table.add_column("Phase", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Description")

    for a in agents:
        table.add_row(
            a["id"],
            a["category"],
            a["phase"],
            a["severity"],
            a["description"][:80],
        )
    console.print(table)


@main.command()
def status() -> None:
    """Show configuration and connectivity status."""
    settings = get_settings()
    table = Table(title="SENTINEL Status", show_header=False, box=None)
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    table.add_row("Cerebras API", "configured" if settings.cerebras_api_key.get_secret_value() else "[yellow]not set[/]")
    table.add_row("Ollama host", settings.ollama_host)
    table.add_row("Workspace", str(settings.workspace))
    table.add_row("Max APK size (MB)", str(settings.max_apk_size_mb))
    table.add_row("Scan timeout (s)", str(settings.scan_timeout_seconds))
    table.add_row("Log level", settings.log_level)

    console.print(table)


@main.command()
@click.option("--base", "base_apk", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Baseline APK (the older / known-good build).")
@click.option("--head", "head_apk", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Candidate APK (the newer build under review).")
@click.option("--fail-on", "fail_on", type=str, default="critical,high",
              show_default=True,
              help="Comma-separated severities that should fail the gate. "
                   "Exit code 1 if any NEW finding matches; 0 otherwise.")
@click.option("--format", "fmt",
              type=click.Choice(["json", "markdown"]),
              default="markdown", show_default=True,
              help="Output format. JSON for tooling, markdown for PR comments.")
@click.option("--data-dir", type=click.Path(path_type=Path),
              default=Path("./data"),
              help="Directory for SENTINEL's persistent memory.")
@click.option("--workspace", type=click.Path(path_type=Path),
              default=Path("./workspace"),
              help="Directory for per-scan working files.")
@click.option("--output", "output", type=click.Path(path_type=Path),
              default=None,
              help="Optional path to write the rendered diff. "
                   "Default is stdout.")
@click.option("--no-baseline", is_flag=True,
              help="Skip writing to data/baselines.sqlite. The diff is "
                   "still computed and rendered.")
@click.option("--baseline-db", type=click.Path(path_type=Path),
              default=Path("./data/baselines.sqlite"),
              help="Path to the baseline SQLite store.")
def diff(
    base_apk: Path,
    head_apk: Path,
    fail_on: str,
    fmt: str,
    data_dir: Path,
    workspace: Path,
    output: Path | None,
    no_baseline: bool,
    baseline_db: Path,
) -> None:
    """Diff the static SAST findings of two APK versions.

    Runs the full static pipeline against each APK, fingerprints the
    findings on stable (agent, vuln_class, normalised path, normalised
    snippet) tuples, and reports new / fixed / unchanged sets. Designed
    to be wired into CI as a regression gate — exits non-zero when a
    new finding of the configured severity appears.
    """
    from sentinel.core.diff import (
        compute_delta,
        gate_exit_code,
        parse_severity_list,
        render_json,
        render_markdown,
    )

    try:
        fail_set = parse_severity_list(fail_on)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--fail-on") from None

    console.rule("[bold cyan]SENTINEL Diff[/]")
    console.print(f"[bold]Base:[/] {base_apk}")
    console.print(f"[bold]Head:[/] {head_apk}")
    console.print(f"[bold]Fail-on:[/] {', '.join(s.value for s in fail_set) or '(none)'}")
    console.print()

    base_findings, base_hash = asyncio.run(
        _run_static_scan(base_apk, data_dir, workspace, label="base"),
    )
    head_findings, head_hash = asyncio.run(
        _run_static_scan(head_apk, data_dir, workspace, label="head"),
    )

    summary = compute_delta(base_findings, head_findings)

    if not no_baseline:
        try:
            from sentinel.core.baseline_store import BaselineStore
            with BaselineStore(baseline_db) as store:
                store.record(base_hash, base_findings)
                store.record(head_hash, head_findings)
        except Exception as e:  # noqa: BLE001 — non-fatal
            console.print(
                f"[yellow]Baseline persistence skipped:[/] {e}",
            )

    if fmt == "json":
        import json
        payload = render_json(
            summary, base_label=str(base_apk), head_label=str(head_apk),
        )
        rendered = json.dumps(payload, indent=2)
    else:
        rendered = render_markdown(
            summary, base_label=str(base_apk), head_label=str(head_apk),
        )

    if output:
        output.write_text(rendered)
        console.print(f"[bold green]Wrote diff to:[/] {output}")
    else:
        click.echo(rendered)

    code = gate_exit_code(summary, fail_set)
    if code:
        console.print(
            f"\n[bold red]Gate FAILED:[/] {len(summary.new)} new finding(s); "
            f"{sum(1 for f in summary.new if f.severity in fail_set)} match "
            f"--fail-on severity set.",
        )
    else:
        console.print(
            "\n[bold green]Gate PASSED:[/] no new findings at the "
            "configured severity threshold.",
        )
    sys.exit(code)


async def _run_static_scan(
    apk_path: Path,
    data_dir: Path,
    workspace: Path,
    label: str,
) -> tuple[list, str]:
    """Static-only scan helper used by `sentinel diff`.

    Returns ``(findings, apk_sha256)``. No LLM triage, no dynamic
    analysis — just the static SAST agents identical to the default
    static path of `sentinel scan`. The same agent list is built here
    that ``_run_scan`` uses, so coverage is identical.
    """
    from sentinel.agents.auth import (
        BiometricBypassAgent,
        HardcodedSecretsAgent,
        TapJackingAgent,
    )
    from sentinel.agents.auth_storage import InsecureAuthStorageAgent
    from sentinel.agents.backup import InsecureBackupAgent
    from sentinel.agents.business import (
        IapBypassAgent,
        RaceConditionAgent,
        RestIdorAgent,
    )
    from sentinel.agents.cert_pinning import MissingCertPinningAgent
    from sentinel.agents.cloud import FirebaseMisconfigAgent
    from sentinel.agents.crossplatform import FlutterAgent, ReactNativeAgent
    from sentinel.agents.crypto import (
        EcbModeAgent,
        HardcodedCryptoKeysAgent,
        KeystoreMisuseAgent,
        SQLCipherKeyDerivationAgent,
        WeakCryptoAgent,
    )
    from sentinel.agents.data_storage import WorldReadableStorageAgent
    from sentinel.agents.logging import InsecureLoggingAgent
    from sentinel.agents.meta import ObfuscationDetectorAgent
    from sentinel.agents.native import NativeLibraryAgent
    from sentinel.agents.network import (
        ApiKeyLeakageAgent,
        CleartextTrafficAgent,
        GraphqlFuzzerAgent,
        GraphqlIntrospectionAgent,
        InsecureTrustManagerAgent,
        WebViewDebugFlagAgent,
    )
    from sentinel.agents.platform import (
        ContentProviderIDORAgent,
        DeepLinkHijackAgent,
        ExcessivePermissionsAgent,
        IntentRedirectAgent,
        IpcExposureAgent,
        MutablePendingIntentAgent,
        ReceiverChainHijackAgent,
    )
    from sentinel.agents.random_gen import InsecureRandomAgent
    from sentinel.agents.resilience import AntiTamperAgent
    from sentinel.agents.semgrep import SemgrepAgent
    from sentinel.agents.shared_prefs import (
        InsecureFileProviderAgent,
        InsecureSharedPrefsAgent,
    )
    from sentinel.agents.supply_chain import SCAAgent
    from sentinel.agents.taint import TaintAgent
    from sentinel.agents.webview import InsecureWebViewAgent
    from sentinel.core.finding import BountyScope
    from sentinel.core.orchestrator import Orchestrator
    from sentinel.core.scan_context import ScanContext, generate_session_id
    from sentinel.memory import LightweightMemory

    console.print(f"[dim]Running static scan on {label}: {apk_path}[/]")

    memory = LightweightMemory(data_dir=data_dir)
    await memory.connect()

    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk_path,
        workspace=workspace,
        scope=BountyScope(),
    )

    agent_list: list = [
        ObfuscationDetectorAgent,
        InsecureAuthStorageAgent, HardcodedSecretsAgent, InsecureLoggingAgent,
        BiometricBypassAgent, TapJackingAgent, RestIdorAgent, InsecureRandomAgent,
        RaceConditionAgent, IapBypassAgent, InsecureBackupAgent,
        WorldReadableStorageAgent, InsecureWebViewAgent,
        HardcodedCryptoKeysAgent, EcbModeAgent, WeakCryptoAgent,
        SQLCipherKeyDerivationAgent, KeystoreMisuseAgent,
        FirebaseMisconfigAgent, MissingCertPinningAgent,
        CleartextTrafficAgent, ApiKeyLeakageAgent, GraphqlIntrospectionAgent,
        InsecureTrustManagerAgent, WebViewDebugFlagAgent, GraphqlFuzzerAgent,
        DeepLinkHijackAgent, ContentProviderIDORAgent,
        IntentRedirectAgent, ReceiverChainHijackAgent,
        MutablePendingIntentAgent, ExcessivePermissionsAgent, IpcExposureAgent,
        NativeLibraryAgent, AntiTamperAgent,
        SCAAgent, TaintAgent, ReactNativeAgent, FlutterAgent,
        SemgrepAgent, InsecureSharedPrefsAgent, InsecureFileProviderAgent,
    ]

    orch = Orchestrator(
        context=ctx, memory=memory, agents=agent_list,
        triager=None, dynamic_enabled=False, proxy_enabled=False,
        frida_enabled=False,
    )
    try:
        result = await orch.run()
    finally:
        try:
            await orch.cleanup(keep_workspace=False)
        except Exception:  # noqa: BLE001
            logger.exception("Workspace cleanup failed for %s scan", label)
        await memory.close()

    return result.findings, ctx.apk_sha256 or ""


if __name__ == "__main__":
    main()
