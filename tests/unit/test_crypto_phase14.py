"""Unit tests for Phase 1.4: at-rest encryption and janitor."""
from __future__ import annotations

import asyncio
import base64
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.core.crypto import (
    decode_master_key,
    decrypt_file,
    derive_tenant_key,
    encrypt_file,
    generate_master_key,
    is_encrypted,
)
from sentinel.core.janitor import _prune_old_workspaces


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

class TestGenerateAndDecodeMasterKey:
    def test_generate_returns_valid_b64(self):
        key_str = generate_master_key()
        raw = base64.b64decode(key_str)
        assert len(raw) == 32

    def test_decode_roundtrip(self):
        key_str = generate_master_key()
        raw = decode_master_key(key_str)
        assert len(raw) == 32

    def test_decode_rejects_wrong_length(self):
        bad = base64.b64encode(b"short").decode()
        with pytest.raises(ValueError, match="32 bytes"):
            decode_master_key(bad)

    def test_decode_rejects_invalid_b64(self):
        with pytest.raises(ValueError, match="valid base64"):
            decode_master_key("not@@base64!!")


class TestDeriveTenantKey:
    def test_different_tenants_yield_different_keys(self):
        master = os.urandom(32)
        k1 = derive_tenant_key(master, "tenant-aaa")
        k2 = derive_tenant_key(master, "tenant-bbb")
        assert k1 != k2

    def test_same_tenant_is_deterministic(self):
        master = os.urandom(32)
        k1 = derive_tenant_key(master, "tenant-xyz")
        k2 = derive_tenant_key(master, "tenant-xyz")
        assert k1 == k2

    def test_key_is_32_bytes(self):
        master = os.urandom(32)
        key = derive_tenant_key(master, "t1")
        assert len(key) == 32

    def test_different_masters_yield_different_keys(self):
        m1, m2 = os.urandom(32), os.urandom(32)
        assert derive_tenant_key(m1, "same") != derive_tenant_key(m2, "same")


class TestEncryptDecryptFile:
    def _key(self) -> bytes:
        return os.urandom(32)

    def test_roundtrip_small_file(self, tmp_path: Path):
        src = tmp_path / "test.apk"
        src.write_bytes(b"APK binary content")
        key = self._key()
        enc = encrypt_file(src, key)
        assert not src.exists(), "plaintext should be deleted after encryption"
        assert enc.suffix == ".enc"
        dec = decrypt_file(enc, key)
        assert dec.read_bytes() == b"APK binary content"

    def test_roundtrip_large_file(self, tmp_path: Path):
        data = os.urandom(1024 * 1024)  # 1 MB
        src = tmp_path / "big.apk"
        src.write_bytes(data)
        key = self._key()
        enc = encrypt_file(src, key)
        dec = decrypt_file(enc, key)
        assert dec.read_bytes() == data

    def test_wrong_key_raises(self, tmp_path: Path):
        src = tmp_path / "secret.apk"
        src.write_bytes(b"secret data")
        key = self._key()
        enc = encrypt_file(src, key)
        with pytest.raises(Exception):  # InvalidTag from AESGCM
            decrypt_file(enc, self._key())

    def test_decrypt_to_custom_dst(self, tmp_path: Path):
        src = tmp_path / "app.apk"
        src.write_bytes(b"data")
        key = self._key()
        enc = encrypt_file(src, key)
        dst = tmp_path / "decoded.apk"
        result = decrypt_file(enc, key, dst=dst)
        assert result == dst
        assert dst.read_bytes() == b"data"

    def test_truncated_file_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.apk.enc"
        bad.write_bytes(b"short")
        with pytest.raises(ValueError, match="too short"):
            decrypt_file(bad, self._key())

    def test_is_encrypted_detection(self, tmp_path: Path):
        enc = tmp_path / "app.apk.enc"
        enc.write_bytes(b"x")
        plain = tmp_path / "app.apk"
        plain.write_bytes(b"x")
        assert is_encrypted(enc) is True
        assert is_encrypted(plain) is False

    def test_nonces_are_unique_across_encryptions(self, tmp_path: Path):
        key = self._key()
        enc_paths = []
        for i in range(5):
            src = tmp_path / f"f{i}.apk"
            src.write_bytes(b"same plaintext")
            enc_paths.append(encrypt_file(src, key))
        nonces = [p.read_bytes()[:12] for p in enc_paths]
        assert len(set(nonces)) == 5, "each encryption should use a unique nonce"


# ---------------------------------------------------------------------------
# Janitor
# ---------------------------------------------------------------------------

class TestPruneOldWorkspaces:
    def _make_session_dir(self, base: Path, name: str, age_days: float) -> Path:
        d = base / "tenant1" / name
        d.mkdir(parents=True)
        mtime = (datetime.now(timezone.utc) - timedelta(days=age_days)).timestamp()
        os.utime(d, (mtime, mtime))
        return d

    def test_prunes_old_dirs(self, tmp_path: Path):
        old = self._make_session_dir(tmp_path, "old-scan", 31)
        recent = self._make_session_dir(tmp_path, "new-scan", 1)
        removed = asyncio.get_event_loop().run_until_complete(
            _prune_old_workspaces(tmp_path, retention_days=30)
        )
        assert removed == 1
        assert not old.exists()
        assert recent.exists()

    def test_respects_retention_boundary(self, tmp_path: Path):
        boundary = self._make_session_dir(tmp_path, "boundary-scan", 29)
        removed = asyncio.get_event_loop().run_until_complete(
            _prune_old_workspaces(tmp_path, retention_days=30)
        )
        assert removed == 0
        assert boundary.exists()

    def test_nonexistent_workspace_returns_zero(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist"
        removed = asyncio.get_event_loop().run_until_complete(
            _prune_old_workspaces(missing, retention_days=30)
        )
        assert removed == 0

    def test_ignores_files_at_root_level(self, tmp_path: Path):
        (tmp_path / "stray_file.txt").write_text("hi")
        removed = asyncio.get_event_loop().run_until_complete(
            _prune_old_workspaces(tmp_path, retention_days=0)
        )
        assert removed == 0

    def test_multi_tenant_pruning(self, tmp_path: Path):
        for tenant in ("t1", "t2", "t3"):
            d = tmp_path / tenant / "old-session"
            d.mkdir(parents=True)
            mtime = (datetime.now(timezone.utc) - timedelta(days=35)).timestamp()
            os.utime(d, (mtime, mtime))
        removed = asyncio.get_event_loop().run_until_complete(
            _prune_old_workspaces(tmp_path, retention_days=30)
        )
        assert removed == 3


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------

class TestConfigEncryption:
    def test_encryption_disabled_by_default(self):
        from sentinel.core.config import reset_settings, get_settings
        reset_settings()
        s = get_settings()
        assert s.encryption_enabled() is False
        reset_settings()

    def test_encryption_enabled_with_key(self, monkeypatch):
        from sentinel.core.config import reset_settings, get_settings
        key = generate_master_key()
        monkeypatch.setenv("SENTINEL_MASTER_KEY", key)
        reset_settings()
        s = get_settings()
        assert s.encryption_enabled() is True
        reset_settings()
