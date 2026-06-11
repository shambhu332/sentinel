"""ScanContext — shared state every agent reads from during a scan."""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sentinel.core.ast_cache import AstCache

from sentinel.core.finding import BountyScope


def generate_session_id() -> str:
    """Cryptographically random URL-safe session ID."""
    return secrets.token_urlsafe(12)[:16]


@dataclass
class ScanContext:
    """State shared across every phase of a scan.

    Sprint 7.6.3 added the `sources` dict to support multiple parallel
    decompilation/analysis tools. Agents that need decompiled source
    can consult `sources['jadx']` (Java) or `sources['androguard']`
    (bytecode-level analysis) and pick whichever is available.

    Backwards compatibility:
    - `decompiled_dir` is still set when JADX succeeds — existing agents
      that read it continue to work unchanged.
    - `manifest` and `permissions` are still populated.
    """
    session_id: str
    apk_path: Path
    workspace: Path
    scope: BountyScope = field(default_factory=BountyScope)
    data_sensitivity: str = "public"
    apk_sha256: str = ""
    apk_size_bytes: int = 0

    # Single-source fields (kept for backwards compatibility).
    # Agents continue to use these. Sprint 7.6.5 will migrate them to `sources`.
    decompiled_dir: Path | None = None
    resources_dir: Path | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    native_libs: list[Path] = field(default_factory=list)

    # Multi-source field (Sprint 7.6.3).
    # Keys: 'jadx', 'androguard', 'apktool'.
    # Values: tool-specific result objects, or None if that tool failed.
    # Use sources.get('androguard') etc — never assume a key is present.
    sources: dict[str, Any] = field(default_factory=dict)

    # App profile populated by META_005 Profiler Agent in Phase 1.5.
    # Keys: 'frameworks', 'native_libs_info', 'obfuscation_level',
    #        'api_types', 'recommended_agents'.
    app_profile: dict[str, Any] = field(default_factory=dict)

    # Global AST cache shared across all agents. Populated by the
    # orchestrator before Phase 2. Agents use
    # `await ctx.ast_cache.get_or_parse(path)` to get cached trees.
    ast_cache: AstCache | None = None

    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    # Opt-in: when True, verifiers are allowed to issue active HTTP
    # replays against the live backend (race-condition parallel-fire,
    # IDOR perturbation, third-party token redaction). Off by default
    # — verifiers without this flag set return UNSUPPORTED rather than
    # touch a live system.
    active_replay: bool = False

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

    # ---------- Source helpers ----------

    def has_jadx(self) -> bool:
        """True if JADX decompilation succeeded for this scan."""
        return self.sources.get("jadx") is not None

    def has_androguard(self) -> bool:
        """True if Androguard bytecode analysis succeeded for this scan."""
        return self.sources.get("androguard") is not None

    def has_apktool(self) -> bool:
        """True if apktool decoding succeeded for this scan."""
        return self.sources.get("apktool") is not None

    # ---------- Profile helpers ----------

    def has_profile(self) -> bool:
        """True if the Profiler Agent has populated the app profile."""
        return bool(self.app_profile)

    def detected_frameworks(self) -> list[str]:
        """Return list of detected frameworks (e.g. ['Flutter', 'React Native'])."""
        return self.app_profile.get("frameworks", [])

    def obfuscation_level(self) -> str:
        """Return obfuscation tier string, e.g. 'Tier 1 (ProGuard/R8)'."""
        return self.app_profile.get("obfuscation_level", "unknown")

    def has_native_libs(self) -> bool:
        """True if the profiler found .so libraries."""
        return bool(self.app_profile.get("native_libs_info", {}).get("count", 0))

    def detected_api_types(self) -> list[str]:
        """Return list of detected API types (e.g. ['REST', 'GraphQL', 'gRPC'])."""
        return self.app_profile.get("api_types", [])
