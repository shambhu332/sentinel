"""ToolResult — uniform return type for all tool wrappers.

Every tool wrapper (JADX, apktool, manifest parser, Androguard) returns a
ToolResult instead of raising exceptions. This makes the orchestrator
crash-proof: it can pattern-match on result.success and continue gracefully
when any tool fails.

Design principle: tool wrappers MAY raise exceptions internally for control
flow, but MUST catch them at the boundary and return a ToolResult.

Usage:
    result = await jadx.decompile(apk, output_dir)
    if result.success:
        # Use result.data
        java_count = result.data.java_file_count
    else:
        logger.warning("JADX failed: %s", result.error)
        # Continue with whatever we have
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


@dataclass
class ToolResult(Generic[T]):
    """Uniform return type for tool wrappers.

    Attributes:
        success: True if the tool completed without unrecoverable errors.
                 Note: success can still be True with warnings.
        data: The successful output (e.g., JadxResult, ManifestData).
              None when success=False.
        error: Short error description when success=False.
               Format: "{error_class}: {message}" — e.g., "JadxError: timeout after 729s".
        duration_seconds: Wall-clock time spent in this tool call.
        warnings: Non-fatal issues encountered during execution
                  (e.g., "found 3 corrupt class files but continued").
    """

    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    duration_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def ok(cls, data: T, duration: float = 0.0,
           warnings: Optional[list[str]] = None) -> "ToolResult[T]":
        """Construct a successful result."""
        return cls(
            success=True,
            data=data,
            duration_seconds=duration,
            warnings=warnings or [],
        )

    @classmethod
    def fail(cls, error: str, duration: float = 0.0,
             warnings: Optional[list[str]] = None) -> "ToolResult[T]":
        """Construct a failed result."""
        return cls(
            success=False,
            error=error,
            duration_seconds=duration,
            warnings=warnings or [],
        )

    @classmethod
    def from_exception(cls, exc: BaseException,
                       duration: float = 0.0) -> "ToolResult[T]":
        """Construct a failed result from an exception."""
        error = f"{type(exc).__name__}: {exc}"
        return cls(success=False, error=error, duration_seconds=duration)

    def __bool__(self) -> bool:
        """Truthy if successful — enables `if result:` pattern."""
        return self.success
