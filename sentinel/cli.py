"""SENTINEL command-line interface.

Three commands:
    sentinel serve              — start the FastAPI gateway
    sentinel scope parse        — test scope parsing from URL/file/text
    sentinel agents             — list all 88 agents

Legal: use only against targets you have explicit written permission to test.
"""
from __future__ import annotations

import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from sentinel.core.config import get_settings
from sentinel.scope.scope_parser import ScopeParser, ScopeSourceError

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%H:%M:%S",
)


@click.group()
@click.version_option(version="0.1.0", prog_name="sentinel")
def main() -> None:
    """SENTINEL — multi-agent mobile application security scanner.

    \b
    Use only against targets you have explicit written permission to test.
    Always respect bug bounty program scope.
    """


# ---------- serve ----------

@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", type=int, default=8000, show_default=True)
@click.option("--reload", is_flag=True, help="Enable auto-reload (dev only)")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the FastAPI gateway.

    Once running, open http://localhost:8000/docs in a browser for Swagger UI.
    """
    import uvicorn

    console.print(f"[bold cyan]SENTINEL[/] gateway starting on http://{host}:{port}")
    console.print(f"[dim]Swagger UI:  http://{host}:{port}/docs[/]")
    console.print(f"[dim]ReDoc:       http://{host}:{port}/redoc[/]")
    console.print()

    uvicorn.run(
        "sentinel.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=get_settings().log_level.lower(),
    )


# ---------- scope ----------

@main.group()
def scope() -> None:
    """Bug bounty scope operations."""


@scope.command(name="parse")
@click.option("--url", type=str, default=None, help="Bounty program URL")
@click.option("--file", "file_path", type=click.Path(exists=True, path_type=Path),
              default=None, help="Local scope file (JSON or text)")
@click.option("--text", type=str, default=None, help="Inline scope text")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON instead of table")
def scope_parse(url: str | None, file_path: Path | None, text: str | None, as_json: bool) -> None:
    """Parse scope from URL, file, or pasted text."""
    if not any([url, file_path, text]):
        console.print("[red]error:[/] provide one of --url, --file, or --text")
        raise SystemExit(2)

    parser = ScopeParser()
    try:
        if url:
            scope_obj = parser.from_url(url)
        elif file_path:
            scope_obj = parser.from_file(file_path)
        else:
            scope_obj = parser.from_text(text or "")
    except ScopeSourceError as e:
        console.print(f"[red]scope parse failed:[/] {e}")
        raise SystemExit(1) from e

    if as_json:
        console.print_json(scope_obj.model_dump_json())
        return

    # Rich table output
    console.print(f"[bold cyan]Program:[/]  {scope_obj.program_name}")
    console.print(f"[bold cyan]Platform:[/] {scope_obj.platform}")
    console.print()

    if scope_obj.in_scope_packages:
        t = Table(title="In-Scope Packages", title_style="bold green")
        t.add_column("Package")
        for p in scope_obj.in_scope_packages:
            t.add_row(p)
        console.print(t)

    if scope_obj.out_of_scope_packages:
        t = Table(title="Out-of-Scope Packages", title_style="bold red")
        t.add_column("Package")
        for p in scope_obj.out_of_scope_packages:
            t.add_row(p)
        console.print(t)

    if scope_obj.in_scope_domains:
        t = Table(title="In-Scope Domains", title_style="bold green")
        t.add_column("Domain")
        for d in scope_obj.in_scope_domains:
            t.add_row(d)
        console.print(t)

    if scope_obj.forbidden_techniques:
        t = Table(title="Forbidden Techniques", title_style="bold yellow")
        t.add_column("Technique")
        for tech in sorted(scope_obj.forbidden_techniques):
            t.add_row(tech)
        console.print(t)

    if scope_obj.reward_ranges:
        t = Table(title="Reward Ranges", title_style="bold magenta")
        t.add_column("Severity")
        t.add_column("Min ($)", justify="right")
        t.add_column("Max ($)", justify="right")
        for sev, (lo, hi) in scope_obj.reward_ranges.items():
            t.add_row(sev.capitalize(), f"{lo:,}", f"{hi:,}")
        console.print(t)


# ---------- agents ----------

@main.command(name="agents")
@click.option("--category", default=None, help="Filter by category")
def list_agents_cmd(category: str | None) -> None:
    """List all SENTINEL agents (requires gateway running)."""
    import httpx

    base = "http://127.0.0.1:8000"
    params = {"category": category} if category else {}
    try:
        resp = httpx.get(f"{base}/agents", params=params, timeout=5.0)
        resp.raise_for_status()
    except httpx.ConnectError:
        console.print("[red]error:[/] gateway not running. Start with: sentinel serve")
        raise SystemExit(1) from None

    agents_list = resp.json()
    t = Table(title=f"SENTINEL Agents ({len(agents_list)} shown)")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("Name")
    t.add_column("Category", style="magenta")
    t.add_column("Severity", style="yellow")
    for a in agents_list:
        t.add_row(a["id"], a["name"], a["category"], a["severity"])
    console.print(t)


# ---------- status ----------

@main.command()
def status() -> None:
    """Show SENTINEL runtime status."""
    s = get_settings()
    t = Table(title="SENTINEL Status")
    t.add_column("Setting", style="cyan")
    t.add_column("Value")
    t.add_row("Version", "0.1.0")
    t.add_row("Workspace", str(s.workspace))
    t.add_row("Log Level", s.log_level)
    t.add_row("Cerebras Configured", "yes" if s.has_cerebras_key() else "no")
    t.add_row("Ollama Host", s.ollama_host)
    console.print(t)


if __name__ == "__main__":
    main()
