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
    """Run a real scan through Phase 0-2 on InsecureBankv2.apk.

    The pipeline must produce useful output via at least ONE decompilation
    path. Manifest parsing via androguard is independent and must always work.
    """
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
        assert ctx.apk_sha256 != "", "Phase 0 SHA-256 hash missing"
        assert len(ctx.apk_sha256) == 64, "Phase 0 SHA-256 wrong length"
        assert ctx.apk_size_bytes > 0, "Phase 0 file size not recorded"

        # Phase 1 manifest parsing always works (androguard is reliable)
        assert ctx.manifest is not None, "Phase 1 manifest is None"
        assert ctx.manifest.get("package", "") != "", "Phase 1 package empty"
        assert "insecurebankv2" in ctx.manifest["package"].lower(), \
            f"Wrong package: {ctx.manifest.get('package')}"
        assert len(ctx.manifest.get("permissions", [])) > 0, "Phase 1 no permissions"
        assert len(ctx.manifest.get("activities", [])) > 0, "Phase 1 no activities"

        # Phase 2 must run TEST_001 successfully
        test_findings = [f for f in result.findings if f.agent_id == "TEST_001"]
        assert len(test_findings) == 1, (
            f"Expected exactly 1 TEST_001 finding, got {len(test_findings)} "
            f"(total findings: {len(result.findings)})"
        )
        assert result.status == "completed", f"Scan status: {result.status} ({result.error})"

        # At least one decompilation path must produce useful output.
        # JADX produces .java files; apktool produces a directory tree
        # containing AndroidManifest.xml somewhere inside.
        jadx_worked = (
            ctx.decompiled_dir is not None
            and ctx.decompiled_dir.exists()
            and any(ctx.decompiled_dir.rglob("*.java"))
        )

        apktool_worked = False
        if ctx.resources_dir is not None and ctx.resources_dir.exists():
            # apktool may put AndroidManifest.xml at the root or in a subdir
            manifest_files = list(ctx.resources_dir.rglob("AndroidManifest.xml"))
            apktool_worked = len(manifest_files) > 0

        assert jadx_worked or apktool_worked, (
            f"Both decompilers failed. "
            f"jadx_worked={jadx_worked} apktool_worked={apktool_worked} "
            f"decompiled_dir={ctx.decompiled_dir} "
            f"resources_dir={ctx.resources_dir}"
        )

    finally:
        await memory.close()
