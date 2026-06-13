"""Android backup extraction helpers for D_081.

The functions in this module are intentionally inert unless callers pass
``active_replay=True`` to ``run_adb_backup``. Unpacking and scanning an
existing ``.ab`` file is local-only and safe for unit tests.
"""
from __future__ import annotations

import io
import math
import re
import subprocess
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_KEY_NAME_RE = re.compile(r"(token|secret|key|auth|session|jwt|bearer)", re.I)
_MAX_VALUE_PREVIEW = 120


@dataclass(frozen=True)
class BackupSecret:
    """High-entropy value found in extracted backup data."""

    path: str
    key: str
    value_preview: str
    entropy: float
    reason: str


@dataclass(frozen=True)
class BackupExtractionResult:
    """Result returned by ``extract_and_scan_backup``."""

    backup_path: Path
    extract_dir: Path
    files_extracted: int
    secrets: list[BackupSecret]


def run_adb_backup(
    package: str,
    backup_path: Path,
    *,
    adb_path: str = "adb",
    active_replay: bool = False,
    timeout_s: int = 120,
) -> Path:
    """Run ``adb backup`` for one package.

    This touches a connected device and can prompt the user on-device, so
    callers must opt in with ``active_replay=True``.
    """

    if not active_replay:
        raise PermissionError("D_081 backup extraction requires active_replay=True")
    if not package:
        raise ValueError("package is required")

    backup_path = backup_path.expanduser().resolve()
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            adb_path,
            "backup",
            "-noapk",
            "-f",
            str(backup_path),
            package,
        ],
        check=True,
        timeout=timeout_s,
    )
    return backup_path


def extract_and_scan_backup(
    backup_path: Path,
    extract_dir: Path,
) -> BackupExtractionResult:
    """Unpack an Android ``.ab`` backup and scan extracted shared prefs."""

    files = unpack_android_backup(backup_path, extract_dir)
    return BackupExtractionResult(
        backup_path=backup_path,
        extract_dir=extract_dir,
        files_extracted=files,
        secrets=scan_shared_prefs(extract_dir),
    )


def unpack_android_backup(backup_path: Path, extract_dir: Path) -> int:
    """Unpack an unencrypted Android backup archive into ``extract_dir``.

    The Android backup format starts with four newline-terminated header
    fields, followed by either a raw tar stream or a zlib-compressed tar
    stream. Encrypted backups are intentionally rejected.
    """

    backup_path = backup_path.expanduser().resolve()
    extract_dir = extract_dir.expanduser().resolve()
    raw = backup_path.read_bytes()
    payload, compressed, encrypted = _split_android_backup(raw)
    if encrypted:
        raise ValueError("encrypted Android backups are not supported")
    tar_bytes = zlib.decompress(payload) if compressed else payload
    extract_dir.mkdir(parents=True, exist_ok=True)
    return _safe_extract_tar(tar_bytes, extract_dir)


def scan_shared_prefs(root: Path) -> list[BackupSecret]:
    """Scan extracted ``shared_prefs`` XML files for likely secrets."""

    root = root.expanduser().resolve()
    secrets: list[BackupSecret] = []
    for path in root.rglob("*.xml"):
        if "shared_prefs" not in path.parts:
            continue
        for key, value in _read_pref_values(path):
            reason = _secret_reason(key, value)
            if reason is None:
                continue
            secrets.append(BackupSecret(
                path=str(path.relative_to(root)),
                key=key,
                value_preview=_preview(value),
                entropy=round(_shannon_entropy(value), 3),
                reason=reason,
            ))
    return secrets


def _split_android_backup(raw: bytes) -> tuple[bytes, bool, bool]:
    lines: list[bytes] = []
    cursor = 0
    for _ in range(4):
        end = raw.find(b"\n", cursor)
        if end < 0:
            raise ValueError("invalid Android backup header")
        lines.append(raw[cursor:end])
        cursor = end + 1
    if lines[0] != b"ANDROID BACKUP":
        raise ValueError("not an Android backup archive")
    compressed = lines[2] == b"1"
    encrypted = lines[3] != b"none"
    return raw[cursor:], compressed, encrypted


def _safe_extract_tar(tar_bytes: bytes, extract_dir: Path) -> int:
    count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as archive:
        for member in archive.getmembers():
            target = (extract_dir / member.name).resolve()
            if not _is_relative_to(target, extract_dir):
                raise ValueError(f"backup archive contains unsafe path: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            target.write_bytes(source.read())
            count += 1
    return count


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _read_pref_values(path: Path) -> Iterable[tuple[str, str]]:
    try:
        root = ElementTree.parse(path).getroot()
    except (ElementTree.ParseError, OSError):
        return []
    values: list[tuple[str, str]] = []
    for child in root:
        key = child.attrib.get("name", "")
        if child.tag == "string":
            values.append((key, child.text or ""))
        elif child.tag in {"int", "long", "float", "boolean"}:
            values.append((key, child.attrib.get("value", "")))
        elif child.tag == "set":
            values.extend((key, item.text or "") for item in child)
    return values


def _secret_reason(key: str, value: str) -> str | None:
    if len(value) < 16:
        return None
    if _JWT_RE.search(value):
        return "jwt"
    if _KEY_NAME_RE.search(key) and _shannon_entropy(value) >= 3.5:
        return "sensitive_key_high_entropy_value"
    if _HEX_RE.search(value) and _shannon_entropy(value) >= 3.2:
        return "hex_high_entropy"
    if _B64_RE.search(value) and _shannon_entropy(value) >= 4.0:
        return "base64_high_entropy"
    if len(value) >= 24 and _shannon_entropy(value) >= 4.25:
        return "high_entropy"
    return None


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _preview(value: str) -> str:
    value = value.replace("\n", "\\n")
    if len(value) <= _MAX_VALUE_PREVIEW:
        return value
    return f"{value[:_MAX_VALUE_PREVIEW]}..."


__all__ = [
    "BackupExtractionResult",
    "BackupSecret",
    "extract_and_scan_backup",
    "run_adb_backup",
    "scan_shared_prefs",
    "unpack_android_backup",
]
