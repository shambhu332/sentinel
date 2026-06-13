"""Tests for D_078 biometric unwrapper + D_081 backup extractor."""
from __future__ import annotations

import io
import tarfile
import zlib
from pathlib import Path

import pytest

from sentinel.agents.dynamic.d078_biometric_unwrapper import (
    BiometricCryptoUnwrapperAgent,
)
from sentinel.agents.dynamic.d081_backup_extractor import BackupDataExtractorAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.tools.backup_tool import extract_and_scan_backup, run_adb_backup


class _Memory:
    async def save_finding(self, finding):
        return None

    async def publish_event(self, session_id, event_type, payload):
        return None


def _apk(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return path


def _ctx(tmp_path: Path) -> tuple[ScanContext, Path]:
    apk = _apk(tmp_path / "t.apk")
    decompiled = tmp_path / "decompiled"
    decompiled.mkdir()
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=tmp_path / "ws",
        scope=BountyScope(),
    )
    ctx.decompiled_dir = decompiled
    return ctx, decompiled


@pytest.mark.asyncio
async def test_d078_flags_biometric_cryptoobject_cipher(tmp_path):
    ctx, root = _ctx(tmp_path)
    (root / "VaultUnlocker.java").write_text(
        "package com.x;\n"
        "import androidx.biometric.BiometricPrompt;\n"
        "import javax.crypto.Cipher;\n"
        "import javax.crypto.SecretKey;\n"
        "class VaultUnlocker {\n"
        "  void unlock(BiometricPrompt prompt, Cipher cipher, SecretKey key) {\n"
        "    BiometricPrompt.CryptoObject cryptoObject =\n"
        "      new BiometricPrompt.CryptoObject(cipher);\n"
        "    prompt.authenticate(new PromptInfo.Builder().build(), cryptoObject);\n"
        "  }\n"
        "}\n"
    )
    findings = await BiometricCryptoUnwrapperAgent(
        context=ctx,
        memory=_Memory(),
    ).analyze()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.agent_id == "D_078"
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["class_name"] == "com.x.VaultUnlocker"
    assert finding.evidence["dynamic_target"] is True
    payload = finding.evidence["frida_payload"]
    assert payload["type"] == "biometric_unwrap_probe"
    assert payload["class_name"] == "com.x.VaultUnlocker"


@pytest.mark.asyncio
async def test_d078_skips_biometric_prompt_without_crypto(tmp_path):
    ctx, root = _ctx(tmp_path)
    (root / "Login.java").write_text(
        "import androidx.biometric.BiometricPrompt;\n"
        "class Login {\n"
        "  void login(BiometricPrompt prompt) {\n"
        "    prompt.authenticate(new PromptInfo.Builder().build());\n"
        "  }\n"
        "}\n"
    )
    findings = await BiometricCryptoUnwrapperAgent(
        context=ctx,
        memory=_Memory(),
    ).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d081_emits_backup_payload_when_active_replay_enabled(tmp_path):
    ctx, _ = _ctx(tmp_path)
    ctx.active_replay = True
    ctx.manifest = {
        "package": "com.x",
        "allow_backup": True,
        "target_sdk": 30,
    }
    findings = await BackupDataExtractorAgent(context=ctx, memory=_Memory()).analyze()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.agent_id == "D_081"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["requires_active_replay"] is True
    assert finding.evidence["dynamic_target"] is True
    payload = finding.evidence["dast_payload"]
    assert payload["type"] == "backup_extract"
    assert payload["package"] == "com.x"


@pytest.mark.asyncio
async def test_d081_skips_when_active_replay_disabled(tmp_path):
    ctx, _ = _ctx(tmp_path)
    ctx.active_replay = False
    ctx.manifest = {"package": "com.x", "allow_backup": True}
    findings = await BackupDataExtractorAgent(context=ctx, memory=_Memory()).analyze()
    assert findings == []


@pytest.mark.asyncio
async def test_d081_treats_missing_allow_backup_as_default_enabled(tmp_path):
    ctx, _ = _ctx(tmp_path)
    ctx.active_replay = True
    ctx.target_sdk = 28
    ctx.manifest = {"package": "com.x", "target_sdk": 28}
    findings = await BackupDataExtractorAgent(context=ctx, memory=_Memory()).analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["allow_backup_source"] == "default_missing"


def test_backup_tool_unpacks_ab_and_finds_shared_pref_secret(tmp_path):
    backup_path = _android_backup(
        tmp_path / "backup.ab",
        {
            "apps/com.x/shared_prefs/auth.xml": (
                b"<?xml version='1.0' encoding='utf-8'?>"
                b"<map><string name='auth_token'>"
                b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                b"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                b"</string></map>"
            ),
        },
    )
    result = extract_and_scan_backup(backup_path, tmp_path / "out")
    assert result.files_extracted == 1
    assert len(result.secrets) == 1
    assert result.secrets[0].key == "auth_token"
    assert result.secrets[0].reason == "jwt"


def test_run_adb_backup_requires_active_replay(tmp_path):
    with pytest.raises(PermissionError):
        run_adb_backup("com.x", tmp_path / "backup.ab", active_replay=False)


def _android_backup(path: Path, files: dict[str, bytes]) -> Path:
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    payload = zlib.compress(tar_buf.getvalue())
    path.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + payload)
    return path
