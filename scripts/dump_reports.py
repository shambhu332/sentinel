"""Run a real scan and generate HackerOne reports for every finding.

Usage:
    poetry run python scripts/dump_reports.py corpus/InsecureBankv2.apk
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from rich.console import Console

from sentinel.agents.auth import HardcodedSecretsAgent
from sentinel.agents.cloud import FirebaseMisconfigAgent
from sentinel.agents.crypto import WeakCryptoAgent
from sentinel.agents.data_storage import WorldReadableStorageAgent
from sentinel.agents.logging import InsecureLoggingAgent
from sentinel.agents.meta import ObfuscationDetectorAgent
from sentinel.agents.network import CleartextTrafficAgent
from sentinel.agents.platform import ContentProviderIDORAgent
from sentinel.agents.random_gen import InsecureRandomAgent
from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.agents.webview import InsecureWebViewAgent
from sentinel.core.finding import BountyScope
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.reports import generate_hackerone_report

console = Console()


async def main(apk_path: Path) -> None:
    console.rule("[bold cyan]SENTINEL — Scan + Report Generation[/]")

    memory = LightweightMemory(data_dir=Path("./data"))
    await memory.connect()

    try:
        ctx = ScanContext(
            session_id=generate_session_id(),
            apk_path=apk_path,
            workspace=Path("./workspace"),
            scope=BountyScope(),
        )

        orch = Orchestrator(
            context=ctx,
            memory=memory,
            agents=[
                ObfuscationDetectorAgent,
                PipelineSmokeTestAgent,
                HardcodedSecretsAgent,
                InsecureLoggingAgent,
                InsecureRandomAgent,
                WorldReadableStorageAgent,
                InsecureWebViewAgent,
                WeakCryptoAgent,
                FirebaseMisconfigAgent,
                CleartextTrafficAgent,
                ContentProviderIDORAgent,
            ],
        )

        with console.status("[bold cyan]Scanning..."):
            result = await orch.run()

        console.print(f"[green]✓[/] Scan complete: {len(result.findings)} finding(s)")
        console.print()

        if not result.findings:
            console.print("[dim]No findings to report.[/]")
            return

        package = (ctx.manifest or {}).get("package", "unknown")
        version = (ctx.manifest or {}).get("version_name", "0.0.0")

        report_dir = Path("./reports")
        report_dir.mkdir(exist_ok=True)

        # Skip Info-only findings (smoke test, obfuscation analysis) — they're
        # not bug bounty submissions, they're scanner self-information.
        real_findings = [
            f for f in result.findings
            if f.agent_id not in ("TEST_001", "META_001")
        ]

        if not real_findings:
            console.print("[dim]Only informational findings produced — nothing to report.[/]")
            return

        for f in real_findings:
            report_path = generate_hackerone_report(
                finding=f,
                apk_package=package,
                apk_version=version,
                output_dir=report_dir,
                program_name="(your bounty program here)",
            )
            console.print(
                f"[bold green]✓[/] {f.agent_id} ({f.severity.value}) → "
                f"[cyan]{report_path}[/]"
            )

        console.print()
        console.print("[bold]Reports written to:[/] ./reports/")
        console.print("[dim]Open them with:  cat reports/*.md  |  less[/]")

    finally:
        await memory.close()


if __name__ == "__main__":
    apk = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("corpus/InsecureBankv2.apk")
    if not apk.exists():
        console.print(f"[bold red]APK not found:[/] {apk}")
        sys.exit(1)
    asyncio.run(main(apk))