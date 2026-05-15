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
@click.option("--output", type=click.Path(path_type=Path), default=None,
              help="Optional path to write scan summary as JSON")
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
                   "zygiskfrida on phone). Adds A_003 runtime crypto agent.")
@click.option("--frida-duration", type=int, default=20,
              help="Seconds to run Frida hooks during Phase 4 (default: 20). "
                   "Runs AFTER mitmproxy capture.")
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
) -> None:
    """Run a security scan against an APK file."""
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
) -> None:
    """Async implementation of the scan command."""
    from sentinel.agents.auth import HardcodedSecretsAgent
    from sentinel.agents.auth_storage import InsecureAuthStorageAgent
    from sentinel.agents.backup import InsecureBackupAgent
    from sentinel.agents.cert_pinning import MissingCertPinningAgent
    from sentinel.agents.cloud import FirebaseMisconfigAgent
    from sentinel.agents.crypto import WeakCryptoAgent
    from sentinel.agents.data_storage import WorldReadableStorageAgent
    from sentinel.agents.deep_links import DeepLinkHijackAgent
    from sentinel.agents.dynamic import (
        DataInTransitAgent,
        ImproperTLSAgent,
        RuntimeCryptoAgent,
    )
    from sentinel.agents.logging import InsecureLoggingAgent
    from sentinel.agents.meta import ObfuscationDetectorAgent
    from sentinel.agents.network import CleartextTrafficAgent
    from sentinel.agents.platform import ContentProviderIDORAgent
    from sentinel.agents.random_gen import InsecureRandomAgent
    from sentinel.agents.shared_prefs import InsecureSharedPrefsAgent
    from sentinel.agents.special import PipelineSmokeTestAgent
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
    if frida and not dynamic:
        console.print(
            "[bold red]--frida requires --dynamic. Frida hooks attach to the "
            "running app after Phase 4 traffic capture.[/]",
        )
        return
    if dynamic:
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
            InsecureRandomAgent,              # B_002
            InsecureBackupAgent,              # C_001
            WorldReadableStorageAgent,        # C_002
            InsecureWebViewAgent,             # C_004
            InsecureSharedPrefsAgent,         # C_006
            WeakCryptoAgent,                  # C_007
            FirebaseMisconfigAgent,           # F_001
            MissingCertPinningAgent,          # N_001
            CleartextTrafficAgent,            # N_002
            DeepLinkHijackAgent,              # P_001
            ContentProviderIDORAgent,         # P_004
        ]
        if dynamic:
            agent_list.extend([
                ImproperTLSAgent,             # N_003 (Sprint 8.1 DAST)
                DataInTransitAgent,           # N_004 (Sprint 8.1 DAST)
            ])
        if dynamic and frida:
            agent_list.append(RuntimeCryptoAgent)  # A_003 (Sprint 8.2 DAST)

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

        if output:
            _write_json_output(output, ctx, result)
            console.print(f"\n[bold green]Wrote summary to:[/] {output}")

    finally:
        if router is not None:
            await router.close()
        await memory.close()


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
    table.add_column("Recommendation")

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

        rec = (f.recommendation[:80] + "...") if len(f.recommendation) > 80 else f.recommendation
        table.add_row(
            f"[{colour}]{sev}[/]",
            f.agent_id,
            f.vuln_class[:22],
            triage_cell,
            f"{f.confidence:.2f}",
            rec,
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


if __name__ == "__main__":
    main()
