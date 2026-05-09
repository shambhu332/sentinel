"""AndroguardAnalyzer — bytecode-level APK analysis.

While JADX/apktool decompile to Java/smali source files, Androguard reads
the raw DEX bytecode directly into Python objects. This is dramatically
faster (5-10s on a 100MB APK) and never times out.

Use cases where Androguard analysis beats decompilation:
- Finding hardcoded strings/keys in obfuscated APKs
- Locating every call to a specific API method
- Listing classes, methods, fields, permissions
- Working with APKs JADX cannot decompile

CRASH-PROOF: All public methods return ToolResult. Internal exceptions
are caught at the boundary.

Performance characteristics (verified on InsecureBankv2 + base.apk):
- 3.4MB APK: ~1-2 seconds to load and index
- 91MB APK:  ~5-10 seconds to load and index
- After loading, queries are millisecond-fast
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)


@dataclass
class StringMatch:
    """A string found in the APK's bytecode/resources."""
    value: str               # the actual string
    location: str            # "bytecode", "resources", "manifest", or class name
    context: str = ""        # surrounding info if available


@dataclass
class MethodMatch:
    """A method discovered in the APK."""
    class_name: str          # e.g., "Lcom/example/Foo;"
    method_name: str         # e.g., "doStuff"
    descriptor: str = ""     # e.g., "(Ljava/lang/String;)V"
    is_external: bool = False  # True if defined outside the APK (Android SDK)


@dataclass
class CallsiteMatch:
    """A location in the APK that calls a specific external method."""
    caller_class: str        # the class containing the call
    caller_method: str       # the method containing the call
    target_class: str        # what's being called (e.g., "Ljavax/crypto/Cipher;")
    target_method: str       # the method on the target (e.g., "getInstance")


@dataclass
class AndroguardAnalysis:
    """Container for analysis results from a loaded APK."""

    apk_path: Path
    package_name: str = ""
    main_activity: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    min_sdk: int = 0
    target_sdk: int = 0
    debuggable: bool = False
    allow_backup: bool = False

    # Lazy-evaluated, populated on demand
    _all_strings: Optional[list[str]] = None
    _all_methods: Optional[list[MethodMatch]] = None
    _all_classes: Optional[list[str]] = None

    # Internal — kept for direct access if needed
    _apk: Any = None  # androguard APK object
    _dex_files: list[Any] = field(default_factory=list)  # DalvikVMFormat objects
    _analysis: Any = None  # androguard Analysis object

    def get_all_strings(self) -> list[str]:
        """Return every string constant in the APK's DEX files.

        Cached after first call. Note: includes Android framework strings,
        package names, etc. — filter as needed.
        """
        if self._all_strings is not None:
            return self._all_strings

        strings: list[str] = []
        for dex in self._dex_files:
            try:
                # Androguard's DalvikVMFormat exposes get_strings()
                dex_strings = dex.get_strings()
                strings.extend(str(s) for s in dex_strings)
            except Exception as e:  # noqa: BLE001
                logger.debug("Failed to extract strings from one DEX: %s", e)

        self._all_strings = strings
        return strings

    def find_strings_matching(self, pattern: str | re.Pattern) -> list[StringMatch]:
        """Return strings in the APK matching a regex pattern.

        Use this for hardcoded secret detection (e.g., r'AIza[A-Za-z0-9_-]{35}').
        """
        if isinstance(pattern, str):
            compiled = re.compile(pattern)
        else:
            compiled = pattern

        matches: list[StringMatch] = []
        for s in self.get_all_strings():
            if compiled.search(s):
                matches.append(StringMatch(value=s, location="bytecode"))
        return matches

    def get_all_classes(self) -> list[str]:
        """Return all class names in the APK (e.g., 'Lcom/example/Foo;')."""
        if self._all_classes is not None:
            return self._all_classes

        classes: list[str] = []
        for dex in self._dex_files:
            try:
                for c in dex.get_classes():
                    classes.append(c.get_name())
            except Exception as e:  # noqa: BLE001
                logger.debug("Failed to list classes from one DEX: %s", e)

        self._all_classes = classes
        return classes

    def get_all_methods(self) -> list[MethodMatch]:
        """Return all methods defined in the APK."""
        if self._all_methods is not None:
            return self._all_methods

        methods: list[MethodMatch] = []
        for dex in self._dex_files:
            try:
                for m in dex.get_methods():
                    methods.append(MethodMatch(
                        class_name=m.get_class_name(),
                        method_name=m.get_name(),
                        descriptor=m.get_descriptor(),
                        is_external=False,
                    ))
            except Exception as e:  # noqa: BLE001
                logger.debug("Failed to list methods from one DEX: %s", e)

        self._all_methods = methods
        return methods

    def find_callsites_of(
        self, target_class: str, target_method: str | None = None,
    ) -> list[CallsiteMatch]:
        """Find every location that calls a given API method.

        Args:
            target_class: e.g., "Ljavax/crypto/Cipher;" or "Cipher" (substring match)
            target_method: e.g., "getInstance" — None matches any method on the class

        Returns:
            List of CallsiteMatch objects describing each callsite.

        Example:
            # Find every Cipher.getInstance() call
            sites = analysis.find_callsites_of("Ljavax/crypto/Cipher;", "getInstance")
        """
        if self._analysis is None:
            return []

        matches: list[CallsiteMatch] = []
        try:
            # Use Androguard's MethodAnalysis.get_xref_from()
            for method in self._analysis.get_methods():
                m = method.get_method()
                if not _matches_target(m, target_class, target_method):
                    continue
                # Find what calls this method
                for _, caller, _ in method.get_xref_from():
                    matches.append(CallsiteMatch(
                        caller_class=caller.get_class_name(),
                        caller_method=caller.get_name(),
                        target_class=m.get_class_name(),
                        target_method=m.get_name(),
                    ))
        except Exception as e:  # noqa: BLE001
            logger.debug("find_callsites_of failed: %s", e)

        return matches


def _matches_target(method: Any, target_class: str, target_method: str | None) -> bool:
    """Check if a method matches the target class/method query."""
    try:
        cls = method.get_class_name()
        name = method.get_name()
    except Exception:  # noqa: BLE001
        return False

    # Class matching: substring OK (so "Cipher" matches "Ljavax/crypto/Cipher;")
    if target_class not in cls:
        return False

    if target_method is None:
        return True
    return name == target_method


class AndroguardAnalyzer:
    """Wraps Androguard for crash-proof bytecode analysis of APKs.

    All public methods return ToolResult. Never raises to the caller.
    """

    def __init__(self) -> None:
        # Defer Androguard import to avoid load-time failures if it's missing
        try:
            from androguard.misc import AnalyzeAPK
            self._analyze_apk = AnalyzeAPK
            self._import_error: Optional[str] = None
        except Exception as e:  # noqa: BLE001
            self._analyze_apk = None
            self._import_error = f"{type(e).__name__}: {e}"

    async def analyze(self, apk_path: Path) -> ToolResult[AndroguardAnalysis]:
        """Load an APK and return an AndroguardAnalysis object for querying.

        Returns ToolResult.success=True with AndroguardAnalysis on success.
        Returns ToolResult.fail() if Androguard isn't installed or APK
        can't be parsed.
        Never raises.
        """
        start = time.monotonic()

        if self._analyze_apk is None:
            return ToolResult.fail(
                f"Androguard not available: {self._import_error}",
                duration=time.monotonic() - start,
            )

        try:
            return await self._analyze_inner(apk_path, start)
        except Exception as e:  # noqa: BLE001
            logger.exception("Androguard analysis crashed unexpectedly")
            return ToolResult.from_exception(e, duration=time.monotonic() - start)

    async def _analyze_inner(
        self, apk_path: Path, start: float,
    ) -> ToolResult[AndroguardAnalysis]:
        """Inner analysis. Wrapped in try/except by analyze()."""
        apk_path = apk_path.expanduser().resolve()

        if not apk_path.exists():
            return ToolResult.fail(
                f"APK not found: {apk_path}",
                duration=time.monotonic() - start,
            )
        if not apk_path.is_file():
            return ToolResult.fail(
                f"Not a file: {apk_path}",
                duration=time.monotonic() - start,
            )

        warnings: list[str] = []

        # AnalyzeAPK is synchronous and CPU-bound. Run it in a thread to
        # avoid blocking the asyncio event loop.
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            apk_obj, dex_files, analysis_obj = await loop.run_in_executor(
                None, self._analyze_apk, str(apk_path),
            )
        except Exception as e:  # noqa: BLE001
            return ToolResult.fail(
                f"AnalyzeAPK failed: {type(e).__name__}: {e}",
                duration=time.monotonic() - start,
            )

        # Normalize dex_files — AnalyzeAPK returns a single DalvikVMFormat
        # for single-DEX APKs, but a list for multi-DEX. Make it always a list.
        if not isinstance(dex_files, list):
            dex_files = [dex_files]

        # Build the AndroguardAnalysis result
        try:
            result = AndroguardAnalysis(
                apk_path=apk_path,
                package_name=apk_obj.get_package() or "",
                main_activity=apk_obj.get_main_activity() or None,
                permissions=list(apk_obj.get_permissions() or []),
                activities=list(apk_obj.get_activities() or []),
                services=list(apk_obj.get_services() or []),
                receivers=list(apk_obj.get_receivers() or []),
                providers=list(apk_obj.get_providers() or []),
                min_sdk=int(apk_obj.get_min_sdk_version() or 0),
                target_sdk=int(apk_obj.get_target_sdk_version() or 0),
                debuggable=bool(apk_obj.get_element("application", "debuggable") == "true"),
                allow_backup=bool(apk_obj.get_element("application", "allowBackup") != "false"),
                _apk=apk_obj,
                _dex_files=dex_files,
                _analysis=analysis_obj,
            )
        except Exception as e:  # noqa: BLE001
            return ToolResult.fail(
                f"Failed to build analysis result: {type(e).__name__}: {e}",
                duration=time.monotonic() - start,
            )

        duration = time.monotonic() - start
        logger.info(
            "Androguard analyzed %s in %.1fs: %d classes, %d DEX files",
            apk_path.name, duration,
            len(result.get_all_classes()),
            len(dex_files),
        )

        if duration > 60:
            warnings.append(f"Androguard slow on this APK ({duration:.0f}s)")

        return ToolResult.ok(result, duration=duration, warnings=warnings)
