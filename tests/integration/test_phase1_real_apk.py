"""Integration test — runs Phase 0 + Phase 1 on a real APK.

Requires: jadx, apktool, androguard installed and corpus/InsecureBankv2.apk present.
Skips automatically if tools or APK missing.

Realistic expectations: real-world APKs sometimes cause one decompiler to fail.
The pipeline is robust — manifest parsing via androguard is reliable, and
either JADX or apktool succeeding gives us enough source to analyse.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sentinel.agents.special import PipelineSmokeTestAgent
from sentinel.core.finding import BountyScope
from sentinel.core.orchestrator import Orchestrator
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory

REPO_ROOT = Path(__file__).resolve().parents[2]
APK_PATH = REPO_ROOT / "corpus" / "InsecureBankv2.apk"

jadx_available = shutil.which("jadx") is not None
apktool_available = shutil.which("apktool") is not None
apk_available = APK_PATH.exists()

pytestmark = pytest.mark.skipif(
    not (jadx_available and apktool_available and apk_available),
    reason=(
        f"Integration test requires jadx, apktool, and {APK_PATH}. "
        f"jadx={jadx_available} apktool={apktool_available} apk={apk_available}"
    ),
)


@pytest.mark.asyncio
async def test_full_phase0_phase1_on_insecurebank(tmp_path):
    """Run a real scan through Phase 0-2 on InsecureBankv2.apk."""
    memory = LightweightMemory(data_dir=tmp_path / "data")
    await memory.connect()

    try:
        ctx = ScanContext(
            session_id=generate_session_id(),
            apk_path=APK_PATH,
            workspace=tmp_path / "ws",
            scope=BountyScope(),
        )

        orch = Orchestrator(
            context=ctx,
            memory=memory,
            agents=[PipelineSmokeTestAgent],
        )
        result = await orch.run()

        # Phase 0 must always succeed — it just hashes the file
        assert ctx.apk_sha256 != ""
        assert len(ctx.apk_sha256) == 64
        assert ctx.apk_size_bytes > 0

        # Phase 1 manifest parsing always works (androguard is reliable)
        assert ctx.manifest is not None
        assert ctx.manifest.get("package", "") != ""
        assert "insecurebankv2" in ctx.manifest["package"].lower()
        assert len(ctx.manifest.get("permissions", [])) > 0
        assert len(ctx.manifest.get("activities", [])) > 0

        # Phase 2 must run TEST_001 successfully
        assert len(result.findings) == 1
        assert result.findings[0].agent_id == "TEST_001"
        assert result.status == "completed"

        # At least apktool should give us the manifest XML
        # (JADX can be flaky on certain APKs — that's an open issue
        # tracked in sprint 2c follow-up)
        assert ctx.resources_dir is not None
        assert (ctx.resources_dir / "AndroidManifest.xml").exists()

    finally:
        await memory.close()
