"""AES-256-GCM at-rest encryption for APK uploads (Phase 1.4).

Key hierarchy
-------------
Master key  (SENTINEL_MASTER_KEY, 32 raw bytes, base64-encoded in env)
    └─ per-tenant DEK  (HKDF-SHA256, 32 bytes, derived on the fly)
           └─ per-file nonce  (12 random bytes prepended to ciphertext)

Wire format for .enc files:  <12-byte nonce><AES-GCM ciphertext+16-byte tag>

Customer-managed keys (CMK) are tracked in the tenant_encryption_keys table
(migration 0004) but key material never enters the DB — only key references.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_LEN = 12
_KEY_LEN = 32
ENC_SUFFIX = ".enc"


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def decode_master_key(b64_key: str) -> bytes:
    """Decode a base64-encoded 32-byte master key from the environment."""
    try:
        raw = base64.b64decode(b64_key)
    except Exception as exc:
        raise ValueError("SENTINEL_MASTER_KEY must be valid base64") from exc
    if len(raw) != _KEY_LEN:
        raise ValueError(
            f"SENTINEL_MASTER_KEY must decode to exactly 32 bytes, got {len(raw)}"
        )
    return raw


def generate_master_key() -> str:
    """Return a fresh base64-encoded 32-byte key suitable for SENTINEL_MASTER_KEY."""
    return base64.b64encode(os.urandom(_KEY_LEN)).decode()


def derive_tenant_key(master_key: bytes, tenant_id: str) -> bytes:
    """Derive a 32-byte per-tenant DEK using HKDF-SHA256.

    The info string binds the key to this specific tenant so that
    compromising one tenant's DEK does not expose another's.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=None,
        info=f"sentinel-apk-key:{tenant_id}".encode(),
    )
    return hkdf.derive(master_key)


# ---------------------------------------------------------------------------
# File-level encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt_file(src: Path, key: bytes) -> Path:
    """Encrypt *src* in-place with AES-256-GCM.

    Writes ``<src>.enc``, deletes the plaintext, and returns the enc path.
    The original file is only deleted after the encrypted copy is fully
    written so a crash mid-write leaves the plaintext intact.
    """
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, src.read_bytes(), None)
    enc_path = src.with_suffix(src.suffix + ENC_SUFFIX)
    enc_path.write_bytes(nonce + ciphertext)
    src.unlink()
    return enc_path


def decrypt_file(enc_path: Path, key: bytes, dst: Path | None = None) -> Path:
    """Decrypt an ``.enc`` file produced by :func:`encrypt_file`.

    Returns the path of the plaintext file (``dst`` if given, otherwise the
    enc path with the ``.enc`` suffix stripped).  The caller is responsible
    for deleting the plaintext when it is no longer needed.
    """
    data = enc_path.read_bytes()
    if len(data) < _NONCE_LEN:
        raise ValueError(f"Encrypted file too short: {enc_path}")
    nonce, ciphertext = data[:_NONCE_LEN], data[_NONCE_LEN:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    out_path = dst or enc_path.with_suffix("")
    out_path.write_bytes(plaintext)
    return out_path


def is_encrypted(path: Path) -> bool:
    return path.suffix == ENC_SUFFIX


__all__ = [
    "ENC_SUFFIX",
    "decode_master_key",
    "decrypt_file",
    "derive_tenant_key",
    "encrypt_file",
    "generate_master_key",
    "is_encrypted",
]
