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
# Must happen BEFORE importing anything that triggers their loggers.
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "True")
os.environ.setdefault("POSTHOG_DISABLED", "True")
os.environ.setdefault("DO_NOT_TRACK", "1")
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Silence noisy third-party loggers package-wide
for noisy in (
    "androguard", "androguard.core", "androguard.core.apk",
    "androguard.core.axml", "androguard.core.api_specific_resources",
    "chromadb", "chromadb.telemetry", "chromadb.telemetry.product",
    "chromadb.telemetry.product.posthog",
    "posthog", "urllib3",
):
    logging.getLogger(noisy).setLevel(logging.CRITICAL)

# Loguru is what androguard actually uses; silence it specifically
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


# ---------- Root group ----------

@click.group()
@click.version_option(version="0.1.0", prog_name="sentinel")
def main() -> None:
    """SENTINEL — multi-agent mobile application security scanner."""


# ---------- serve ----------

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


# ---------- scan ----------

@main.command()
@click.argument("apk_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--scope-url", type=str, default=None,
              help="Bug bounty scope from a URL (HackerOne, Bugcrowd, etc.)")
@click.option("--scope-file", type=click.Path(exists=True, path_type=Path), default=None,
              help="Bug bounty scope from a JSON or text file")
@click.option("--scope-text", type=str, default=None,
              help="Bug bounty scope as inline text")
@click.option("--data-dir", type=click.Path(path_type=Path), default=Path("./data"),
              help="Directory for SENTINEL's persistent memory (default: ./data)")
@click.option("--workspace", type=click.Path(path_type=Path), default=Path("./workspace"),
              help="Directory for per-scan working files (default: ./workspace)")
@click.option("--output", type=click.Path(path_type=Path), default=None,
              help="Optional path to write scan summary as JSON")
@click.option("--private", is_flag=True,
              help="Force local LLM only — no cloud API calls")
def scan(
    apk_path: Path,
    scope_url: str | None,
    scope_file: Path | None,
    scope_text: str | None,
    data_dir: Path,
    workspace: Path,
    output: Path | None,
    private: bool,
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
) -> None:
    """Async implementation of the scan command."""
    from sentinel.agents.auth import HardcodedSecretsAgent
    from sentinel.agents.cloud import FirebaseMisconfigAgent
    from sentinel.agents.data_storage import WorldReadableStorageAgent
    from sentinel.agents.network import CleartextTrafficAgent
    from sentinel.agents.platform import ContentProviderIDORAgent
    from sentinel.agents.special import PipelineSmokeTestAgent
    from sentinel.core.finding import BountyScope
    from sentinel.core.orchestrator import Orchestrator
    from sentinel.core.scan_context import ScanContext, generate_session_id
    from sentinel.memory import LightweightMemory
    from sentinel.scope import parse_scope

    console.rule("[bold cyan]SENTINEL Scan[/]")
    console.print(f"[bold]APK:[/]       {apk_path}")
    console.print(f"[bold]Workspace:[/] {workspace}")
    console.print(f"[bold]Memory:[/]    {data_dir}")
    if private:
        console.print("[bold yellow]Privacy mode:[/] local LLM only")
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
            console.print("[dim]Continuing with empty scope (everything is in-scope).[/]")
    else:
        console.print("[dim]No scope provided — treating all findings as in-scope.[/]")

    console.print()

    memory = LightweightMemory(data_dir=data_dir)
    await memory.connect()

    try:
        ctx = ScanContext(
            session_id=generate_session_id(),
            apk_path=apk_path,
            workspace=workspace,
            scope=scope,
        )

        console.print(f"[bold]Session:[/]   {ctx.session_id}")
        console.print()

        orch = Orchestrator(
            context=ctx,
            memory=memory,
            agents=[
                PipelineSmokeTestAgent,
                FirebaseMisconfigAgent,
                ContentProviderIDORAgent,
                CleartextTrafficAgent,
                HardcodedSecretsAgent,
                WorldReadableStorageAgent,
            ],
        )

        with console.status("[bold cyan]Running scan...[/]", spinner="dots"):
            result = await orch.run()

        _print_summary(ctx, result)

        if result.findings:
            _print_findings(result.findings)
        else:
            console.print("[dim]No findings produced.[/]")

        if output:
            _write_json_output(output, ctx, result)
            console.print(f"\n[bold green]Wrote summary to:[/] {output}")

    finally:
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

    for phase, dur in result.phase_timings.items():
        table.add_row(f"  {phase}", f"{dur:.2f}s")

    if result.error:
        table.add_row("[red]Error[/]", f"[red]{result.error}[/]")

    console.print(table)


def _print_findings(findings) -> None:
    """Print findings as a Rich table with severity colouring."""
    table = Table(title="\nFindings", show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Agent", width=12)
    table.add_column("Class", width=24)
    table.add_column("Confidence", width=10)
    table.add_column("Recommendation")

    severity_colours = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Info": "dim",
    }

    for f in findings:
        sev = f.severity.value
        colour = severity_colours.get(sev, "white")
        rec = (f.recommendation[:80] + "...") if len(f.recommendation) > 80 else f.recommendation
        table.add_row(
            f"[{colour}]{sev}[/]",
            f.agent_id,
            f.vuln_class[:24],
            f"{f.confidence:.2f}",
            rec,
        )

    console.print(table)


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


# ---------- scope ----------

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


# ---------- agents ----------

@main.command("agents")
@click.option("--category", type=str, default=None,
              help="Filter by category (e.g. 'Firebase', 'Network')")
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


# ---------- status ----------

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
