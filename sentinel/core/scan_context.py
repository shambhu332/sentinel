"""ScanContext — shared state every agent reads from during a scan."""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.finding import BountyScope


def generate_session_id() -> str:
    """Cryptographically random URL-safe session ID."""
    return secrets.token_urlsafe(12)[:16]


@dataclass
class ScanContext:
    session_id: str
    apk_path: Path
    workspace: Path
    scope: BountyScope = field(default_factory=BountyScope)
    data_sensitivity: str = "public"
    apk_sha256: str = ""
    apk_size_bytes: int = 0
    decompiled_dir: Path | None = None
    resources_dir: Path | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    native_libs: list[Path] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        # Path resolution prevents traversal via ../ in user input
        self.workspace = self.workspace.expanduser().resolve()
        self.apk_path = self.apk_path.expanduser().resolve()

        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")
        if not self.apk_path.is_file():
            raise ValueError(f"APK path is not a file: {self.apk_path}")
        if self.data_sensitivity not in {"public", "private"}:
            raise ValueError("data_sensitivity must be 'public' or 'private'")

    @property
    def is_private(self) -> bool:
        return self.data_sensitivity == "private"
