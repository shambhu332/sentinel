"""FL_002 — Flutter MethodChannel tracker.

Flutter's bridge is `MethodChannel("com.example/myChannel")` on the
Dart side, `setMethodCallHandler` on the Android side. The two halves
are linked by the channel name *string*, which is brittle: a rename
on one side that doesn't propagate breaks the bridge silently; an
attacker who replicates the channel name can spoof the Dart caller.

This agent enumerates both halves from decompiled output and reports:

  * **Channels declared on the Android side without a matching Dart
    constructor.** Either Dart has been compiled to libapp.so (the
    common Flutter release shape — we degrade to "unconfirmed pair")
    or the channel is dead code an attacker can take over.
  * **Channels whose name pattern is "open"** (no app-package prefix
    on the channel string). Generic names like `"my_channel"` or
    `"native"` can be re-registered by another app's plugin and
    intercept the bridge in some embedding setups.
  * **Channel handlers that don't validate `call.method`.** The
    handler receives `MethodCall call`; an attacker who reaches the
    bridge can invoke ANY method name. Handlers should switch on
    expected names and reject unknown ones explicitly.
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Android-side MethodChannel construction
_ANDROID_CHANNEL_RE = re.compile(
    r"new\s+MethodChannel\s*\([^,]+,\s*\"([^\"]+)\"\s*\)"
)
# `setMethodCallHandler(handler)` — captures the handler expression
_SET_HANDLER_RE = re.compile(r"\.\s*setMethodCallHandler\s*\(")
# Dart-side constructor — looks the same shape when decompiled libapp
# can't be read, but for hybrid apps Dart files might be in assets.
_DART_CHANNEL_RE = re.compile(
    r"MethodChannel\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
)
# Validation: a switch / if-chain on `call.method`
_VALIDATION_RE = re.compile(r"call\s*\.\s*method")
# Open-name patterns considered too generic
_OPEN_NAME_RE = re.compile(r"^[a-z_]+$")

_MAX_FILES = 2500


class FlutterMethodChannelAgent(BaseAgent):
    """FL_002: enumerate + audit Flutter platform channels."""

    AGENT_ID = "FL_002"
    VULN_CLASS = "Flutter MethodChannel Surface"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if "Flutter" in ctx.detected_frameworks():
            return True
        # Heuristic fallback: flutter_assets / libapp.so / libflutter.so
        if ctx.resources_dir:
            if (ctx.resources_dir / "assets" / "flutter_assets").is_dir():
                return True
        return False

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        if root is None or not root.exists():
            return []

        android_channels: dict[str, str] = {}    # name -> file
        dart_channels: set[str] = set()
        handler_validations: dict[str, bool] = {}  # name -> validates?

        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(root))

            for m in _ANDROID_CHANNEL_RE.finditer(text):
                name = m.group(1)
                android_channels.setdefault(name, rel)
                # Validation check: same file references call.method?
                handler_validations[name] = bool(_VALIDATION_RE.search(text))

        # Look for Dart-side channel declarations in flutter_assets/ or
        # any .dart file the apk shipped (some hybrid setups ship Dart
        # sources for hot-reload).
        if ctx.resources_dir:
            assets = ctx.resources_dir / "assets" / "flutter_assets"
            if assets.is_dir():
                for p in assets.rglob("*.dart"):
                    try:
                        text = p.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    for m in _DART_CHANNEL_RE.finditer(text):
                        dart_channels.add(m.group(1))

        findings: list[Finding] = []
        for name, src in android_channels.items():
            # 1) Open name
            if _OPEN_NAME_RE.match(name) and len(name) < 30:
                findings.append(self._make_finding(
                    vuln_class="Flutter Channel — Open Name",
                    severity=Severity.LOW,
                    confidence=0.55,
                    recommendation=(
                        f"Channel name `{name}` lacks a package-style "
                        "prefix (e.g. com.example.app/feature). Open "
                        "names can collide with third-party plugins "
                        "and create bridge-hijack opportunities. "
                        "Rename to a package-prefixed form."
                    ),
                    evidence={"channel": name, "file": src},
                ))

            # 2) No matching Dart side. Inconclusive when libapp.so
            # is the only Dart artifact (release builds) — emit at INFO.
            if dart_channels and name not in dart_channels:
                findings.append(self._make_finding(
                    vuln_class="Flutter Channel — No Matching Dart Caller",
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    recommendation=(
                        f"Channel `{name}` is registered on the Android "
                        "side but no Dart caller references it. Either "
                        "the Dart caller is in compiled libapp.so "
                        "(verify dynamically) or the handler is dead "
                        "code an attacker could squat on."
                    ),
                    evidence={
                        "channel": name,
                        "file": src,
                        "dart_channels_found": sorted(dart_channels),
                    },
                ))

            # 3) Handler missing method-name validation
            if handler_validations.get(name) is False:
                findings.append(self._make_finding(
                    vuln_class="Flutter Channel Handler Without Method Check",
                    severity=Severity.HIGH,
                    confidence=0.70,
                    recommendation=(
                        f"The handler for channel `{name}` does not "
                        "appear to switch on `call.method`. Attacker "
                        "code reaching the bridge can invoke any "
                        "method name. Add explicit `if/switch` on "
                        "`call.method` and reject unknown methods."
                    ),
                    evidence={"channel": name, "file": src},
                ))

        # 4) Inventory finding — always emit when we found channels
        if android_channels:
            findings.append(self._make_finding(
                vuln_class="Flutter MethodChannel Inventory",
                severity=Severity.INFO,
                confidence=0.85,
                recommendation=(
                    "Inventory of Flutter MethodChannels for the "
                    "dynamic phase — the Frida agent can hook these "
                    "for runtime auditing."
                ),
                evidence={
                    "android_channels": sorted(android_channels.keys()),
                    "dart_channels": sorted(dart_channels),
                    "channel_count": len(android_channels),
                },
            ))

        return findings


__all__ = ["FlutterMethodChannelAgent"]
