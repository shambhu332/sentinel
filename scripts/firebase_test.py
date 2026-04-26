"""Firebase test fixture — proves F_001 fires correctly end-to-end.

This script creates a synthetic decompiled APK directory with a planted
Firebase URL, runs F_001 with a mock HTTP probe, and generates a real
HackerOne-format .md report you can read.

No external network calls. No real APK needed. Fully deterministic.

Run with:  poetry run python scripts/firebase_test.py
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from sentinel.agents.cloud import FirebaseMisconfigAgent
from sentinel.core.finding import BountyScope
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory
from sentinel.reports import generate_hackerone_report

console = Console()


async def main() -> None:
    """Run the synthetic Firebase test end-to-end."""
    console.rule("[bold cyan]F_001 Firebase Test — Synthetic Fixture[/]")
    console.print()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # ---------- Step 1: create a fake "decompiled" directory ----------
        ws = tmp_path / "ws"
        decompiled = ws / "decompiled"
        decompiled.mkdir(parents=True)
        resources = ws / "resources"
        resources.mkdir(parents=True)

        # Plant a Firebase URL in a fake decompiled Java file (mimics what JADX
        # would produce when decompiling a real app that uses Firebase)
        firebase_helper = decompiled / "FirebaseHelper.java"
        firebase_helper.write_text("""
package com.example.vulnerable.app;

import com.google.firebase.database.FirebaseDatabase;

public class FirebaseHelper {
    // The bug: this database URL is hardcoded and the production database
    // has no authentication rules configured.
    private static final String DATABASE_URL =
        "https://my-leaky-bank-prod.firebaseio.com";

    public void connect() {
        FirebaseDatabase db = FirebaseDatabase.getInstance(DATABASE_URL);
        // ... rest of implementation
    }
}
""")
        console.print(f"[green]✓[/] Created fake decompiled file: {firebase_helper.name}")

        # Plant a google-services.json (the gold-standard signal)
        google_services = resources / "google-services.json"
        google_services.write_text(json.dumps({
            "project_info": {
                "project_id": "my-leaky-bank-prod",
                "firebase_url": "https://my-leaky-bank-prod.firebaseio.com",
                "project_number": "123456789012",
                "storage_bucket": "my-leaky-bank-prod.appspot.com",
            },
        }))
        console.print(f"[green]✓[/] Created fake google-services.json")

        # ---------- Step 2: build a ScanContext ----------
        apk = tmp_path / "fake-bank.apk"
        apk.write_bytes(b"PK\x03\x04fake-apk-bytes")  # Minimal valid zip header

        ctx = ScanContext(
            session_id=generate_session_id(),
            apk_path=apk,
            workspace=ws,
            scope=BountyScope(),
        )
        ctx.decompiled_dir = decompiled
        ctx.resources_dir = resources

        console.print(f"[green]✓[/] Created scan context: session={ctx.session_id}")
        console.print()

        # ---------- Step 3: connect memory ----------
        memory = LightweightMemory(data_dir=tmp_path / "data")
        await memory.connect()

        try:
            # ---------- Step 4: run F_001 with a mock HTTP probe ----------
            console.print("[bold cyan]Running F_001 with mocked HTTP probe...[/]")
            console.print()

            # Mock the Firebase database response — a realistic leak
            leaked_data = {
                "users": {
                    "u_001": {
                        "email": "alice@victim-corp.com",
                        "phone": "+1-555-0100",
                        "balance_usd": 14523.50,
                        "ssn_last4": "1234",
                    },
                    "u_002": {
                        "email": "bob@victim-corp.com",
                        "phone": "+1-555-0101",
                        "balance_usd": 89221.00,
                        "ssn_last4": "5678",
                    },
                },
                "config": {
                    "stripe_secret_key": "sk_live_REDACTED_REDACTED_REDACTED",
                    "smtp_password": "p@ssw0rd123",
                },
            }

            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__.return_value = mock_client
                mock_client.__aexit__.return_value = None
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = json.dumps(leaked_data)
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client

                agent = FirebaseMisconfigAgent(context=ctx, memory=memory)
                findings = await agent.analyze()

            console.print(f"[green]✓[/] F_001 produced {len(findings)} finding(s)")
            console.print()

            if not findings:
                console.print("[bold red]No findings produced — something is wrong.[/]")
                return

            # ---------- Step 5: display the finding ----------
            for i, f in enumerate(findings, start=1):
                console.print(Panel(
                    f"[bold red]Severity:[/] {f.severity.value}\n"
                    f"[bold]Agent:[/] {f.agent_id}\n"
                    f"[bold]Class:[/] {f.vuln_class}\n"
                    f"[bold]Confidence:[/] {f.confidence:.2f}\n"
                    f"[bold]Project ID:[/] {f.evidence.get('project_id')}\n"
                    f"[bold]URL:[/] {f.evidence.get('url')}\n"
                    f"[bold]Probe endpoint:[/] {f.evidence.get('probe_endpoint')}\n"
                    f"[bold]HTTP status:[/] {f.evidence.get('http_status')}\n"
                    f"[bold]Files:[/] {', '.join(f.evidence.get('discovered_in_files', [])[:3])}",
                    title=f"[bold cyan]Finding #{i}[/]",
                    border_style="red",
                ))
                console.print()

                console.print("[bold]Sample of leaked data:[/]")
                sample_str = f.evidence.get("data_sample", "")[:400]
                console.print(Syntax(sample_str, "json", theme="monokai", line_numbers=False))
                console.print()

                # ---------- Step 6: generate a real HackerOne report ----------
                report_dir = Path("./reports")
                report_dir.mkdir(exist_ok=True)
                report_path = generate_hackerone_report(
                    finding=f,
                    apk_package="com.example.vulnerable.app",
                    apk_version="1.0.0",
                    output_dir=report_dir,
                    program_name="(synthetic test program)",
                )
                console.print(f"[bold green]✓ HackerOne report written to:[/] [cyan]{report_path}[/]")
                console.print()

                # Show the report contents
                console.print("[bold]Report contents (first 60 lines):[/]")
                lines = report_path.read_text().splitlines()
                preview = "\n".join(lines[:60])
                console.print(Syntax(preview, "markdown", theme="monokai", line_numbers=True))
                console.print()
                console.print(f"[dim](Report has {len(lines)} lines total — see {report_path} for the full thing)[/]")

        finally:
            await memory.close()

        console.rule("[bold green]Test complete — F_001 works end-to-end[/]")


if __name__ == "__main__":
    asyncio.run(main())
