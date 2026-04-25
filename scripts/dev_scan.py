"""Manual development scan — run a full Phase 0+1+2 pipeline on a real APK.

Usage:
    poetry run python scripts/dev_scan.py [apk_path]

Defaults to corpus/InsecureBankv2.apk if no path given.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.core.finding import BountyScope
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


async def main(apk_path: Path) -> None:
    if not apk_path.exists():
        print(f"ERROR: APK not found: {apk_path}")
        sys.exit(1)

    print(f"Scanning: {apk_path}")
    print("Backend: LightweightMemory (SQLite + ChromaDB + NetworkX)")
    print("Agents:  TEST_001 (Pipeline Smoke Test)")
    print("---")

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
            agents=[PipelineSmokeTestAgent],
        )
        result = await orch.run()

        print()
        print("=== Scan complete ===")
        print(f"Session ID:  {ctx.session_id}")
        print(f"Status:      {result.status}")
        print(f"SHA-256:     {ctx.apk_sha256}")
        print(f"Size:        {ctx.apk_size_bytes:,} bytes")
        print()

        if ctx.manifest:
            m = ctx.manifest
            print("--- Manifest ---")
            print(f"Package:     {m.get('package', '(unknown)')}")
            print(f"Version:     {m.get('version_name', '(unknown)')}")
            print(f"Min SDK:     {m.get('min_sdk', 0)}")
            print(f"Target SDK:  {m.get('target_sdk', 0)}")
            print(f"Permissions: {len(m.get('permissions', []))}")
            print(f"Activities:  {len(m.get('activities', []))}")
            print(f"Services:    {len(m.get('services', []))}")
            print(f"Receivers:   {len(m.get('receivers', []))}")
            print(f"Providers:   {len(m.get('providers', []))}")
            print(f"Exported:    {len(m.get('exported_components', []))}")
            print(f"Deep links:  {len(m.get('deep_links', []))}")
            print(f"Cleartext:   {m.get('uses_cleartext_traffic', False)}")
            print(f"Backup:      {m.get('allow_backup', False)}")
            print(f"Debuggable:  {m.get('debuggable', False)}")
            print()

        print("--- Decompilation ---")
        if ctx.decompiled_dir:
            java_count = sum(1 for _ in ctx.decompiled_dir.rglob("*.java"))
            print(f"JADX:        OK — {java_count} Java files")
            print(f"  output:    {ctx.decompiled_dir}")
        else:
            print("JADX:        FAILED")

        if ctx.resources_dir:
            manifest_xml = ctx.resources_dir / "AndroidManifest.xml"
            print(f"apktool:     {'OK' if manifest_xml.exists() else 'PARTIAL'}")
            print(f"  output:    {ctx.resources_dir}")
        else:
            print("apktool:     FAILED")

        print()
        print("--- Findings ---")
        for f in result.findings:
            print(f"  [{f.severity.value}] {f.agent_id}: {f.vuln_class}")
        if not result.findings:
            print("  (none)")

        print()
        print("--- Timings ---")
        for phase, dur in result.phase_timings.items():
            print(f"  {phase}: {dur:.2f}s")

        if result.error:
            print()
            print(f"--- Error ---")
            print(f"  {result.error}")

    finally:
        await memory.close()


if __name__ == "__main__":
    apk = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./corpus/InsecureBankv2.apk")
    asyncio.run(main(apk))
