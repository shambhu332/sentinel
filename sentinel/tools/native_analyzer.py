"""native_analyzer — ELF binary analysis via pyelftools.

Provides structured analysis of Android native shared objects (.so)
beyond raw string extraction (which NL_001 already does). This tool
parses ELF headers and symbol tables to extract:

1. Exported function symbols (dynsym with STT_FUNC + STB_GLOBAL)
2. Security-relevant symbol families (SSL_*, Java_com_*, ptrace, dlopen)
3. High-entropy printable strings (candidate secrets / obfuscated data)
4. Binary metadata (architecture, linking, RELRO status)

Graceful degradation: if pyelftools is not installed, all methods return
empty results with a logged warning. Agents calling this tool should
always check the ToolResult.success flag.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)

# Minimum string length to extract from binaries
_MIN_STRING_LEN = 6

# Maximum bytes to scan per binary (16 MiB)
_MAX_BYTES_PER_BINARY = 16 * 1024 * 1024

# Printable ASCII extraction pattern
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,}")

# Security-relevant symbol prefixes / names
_SECURITY_SYMBOLS: dict[str, list[str]] = {
    "ssl_tls": ["SSL_", "TLS_", "ssl_", "tls_", "OPENSSL_"],
    "jni_bridge": ["Java_com_", "Java_org_", "Java_io_", "Java_net_"],
    "anti_debug": ["ptrace", "PT_DENY_ATTACH", "TracerPid"],
    "dynamic_loading": ["dlopen", "dlsym", "dlclose", "dlerror"],
    "root_detection": ["su", "magisk", "frida", "xposed"],
    "crypto": ["AES_", "EVP_", "RSA_", "HMAC_", "SHA256_", "MD5_"],
}

# Tokens in extracted strings that indicate root/tamper detection
_TAMPER_TOKENS = [
    b"su", b"magisk", b"frida", b"frida-server",
    b"xposed", b"substrate", b"cydia",
    b"/system/xbin/su", b"/system/bin/su",
    b"/sbin/.magisk", b"magiskpolicy",
    b"gum-js-loop", b"re.frida.server",
]


@dataclass
class ElfAnalysis:
    """Structured analysis result for a single .so file."""

    path: str
    arch: str = ""
    bits: int = 0
    is_stripped: bool = True
    has_relro: bool = False

    # Exported symbols
    exported_symbols: list[str] = field(default_factory=list)

    # Categorized security-relevant symbols
    security_symbols: dict[str, list[str]] = field(default_factory=dict)

    # High-entropy strings (potential secrets)
    high_entropy_strings: list[dict[str, Any]] = field(default_factory=list)

    # Tamper-detection related strings found
    tamper_detection_strings: list[str] = field(default_factory=list)


@dataclass
class NativeAnalysisResult:
    """Aggregated results across all .so files."""

    total_libs: int = 0
    analyzed_libs: int = 0
    architectures: list[str] = field(default_factory=list)
    analyses: list[ElfAnalysis] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class NativeAnalyzer:
    """ELF binary analyzer for Android native libraries.

    Uses pyelftools when available; degrades gracefully otherwise.

    Usage::

        analyzer = NativeAnalyzer()
        result = await analyzer.analyze_directory(lib_dir)
        if result.success:
            for analysis in result.data.analyses:
                print(f"{analysis.path}: {len(analysis.exported_symbols)} exports")
    """

    def __init__(
        self,
        min_entropy: float = 4.0,
        max_strings: int = 100,
        max_symbols: int = 500,
    ) -> None:
        self._min_entropy = min_entropy
        self._max_strings = max_strings
        self._max_symbols = max_symbols
        self._pyelftools_available = self._check_pyelftools()

    @staticmethod
    def _check_pyelftools() -> bool:
        """Check if pyelftools is installed."""
        try:
            import elftools  # noqa: F401
            return True
        except ImportError:
            logger.warning(
                "pyelftools not installed — native ELF analysis disabled. "
                "Install with: pip install pyelftools"
            )
            return False

    async def analyze_directory(
        self, lib_dir: Path,
    ) -> ToolResult[NativeAnalysisResult]:
        """Analyze all .so files under a directory.

        Args:
            lib_dir: Path to the lib/ directory (typically resources_dir/lib/)

        Returns:
            ToolResult containing NativeAnalysisResult.
        """
        if not lib_dir.exists():
            return ToolResult.fail(f"Directory not found: {lib_dir}")

        so_files = sorted(p for p in lib_dir.rglob("*.so") if p.is_file())
        if not so_files:
            return ToolResult.ok(NativeAnalysisResult(total_libs=0))

        result = NativeAnalysisResult(total_libs=len(so_files))
        architectures: set[str] = set()

        for so_path in so_files:
            try:
                analysis = self._analyze_single(so_path, lib_dir)
                result.analyses.append(analysis)
                result.analyzed_libs += 1
                if analysis.arch:
                    architectures.add(analysis.arch)
            except Exception as e:  # noqa: BLE001
                error_msg = f"{so_path.name}: {type(e).__name__}: {e}"
                result.errors.append(error_msg)
                logger.warning("[NativeAnalyzer] %s", error_msg)

        result.architectures = sorted(architectures)
        return ToolResult.ok(result)

    def _analyze_single(self, so_path: Path, lib_root: Path) -> ElfAnalysis:
        """Analyze a single .so file."""
        rel_path = str(so_path.relative_to(lib_root))
        analysis = ElfAnalysis(path=rel_path)

        # Read raw bytes for string extraction (always works)
        try:
            raw = so_path.read_bytes()
            if len(raw) > _MAX_BYTES_PER_BINARY:
                raw = raw[:_MAX_BYTES_PER_BINARY]
        except OSError:
            return analysis

        # Extract high-entropy strings and tamper tokens
        self._extract_strings(raw, analysis)

        # ELF-specific analysis (requires pyelftools)
        if self._pyelftools_available:
            self._analyze_elf(so_path, analysis)

        return analysis

    def _analyze_elf(self, so_path: Path, analysis: ElfAnalysis) -> None:
        """Parse ELF headers and symbol tables using pyelftools."""
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.sections import SymbolTableSection
        except ImportError:
            return

        try:
            with open(so_path, "rb") as f:
                elf = ELFFile(f)

                # Architecture info
                analysis.arch = elf.header.get("e_machine", "")
                analysis.bits = elf.elfclass

                # Check for RELRO
                for segment in elf.iter_segments():
                    if segment.header.get("p_type") == "PT_GNU_RELRO":
                        analysis.has_relro = True
                        break

                # Extract exported symbols from .dynsym
                for section in elf.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue

                    for symbol in section.iter_symbols():
                        name = symbol.name
                        if not name:
                            continue

                        # Check if the symbol is exported (GLOBAL or WEAK, FUNC type)
                        bind = symbol.entry.st_info.get("bind", "")
                        stype = symbol.entry.st_info.get("type", "")

                        if bind in ("STB_GLOBAL", "STB_WEAK") and stype == "STT_FUNC":
                            if len(analysis.exported_symbols) < self._max_symbols:
                                analysis.exported_symbols.append(name)

                            # Categorize security-relevant symbols
                            for category, prefixes in _SECURITY_SYMBOLS.items():
                                if any(name.startswith(p) or name == p for p in prefixes):
                                    analysis.security_symbols.setdefault(
                                        category, [],
                                    ).append(name)

                # Check if binary is stripped (no .symtab section)
                analysis.is_stripped = elf.get_section_by_name(".symtab") is None

        except Exception as e:  # noqa: BLE001
            logger.debug("ELF parse failed for %s: %s", so_path.name, e)

    def _extract_strings(self, raw: bytes, analysis: ElfAnalysis) -> None:
        """Extract high-entropy and security-relevant strings."""
        strings_found = 0

        for match in _PRINTABLE_RE.finditer(raw):
            s = match.group(0)

            # Check for tamper-detection tokens
            s_lower = s.lower()
            for token in _TAMPER_TOKENS:
                if token in s_lower:
                    decoded = s.decode("ascii", errors="replace")
                    if decoded not in analysis.tamper_detection_strings:
                        analysis.tamper_detection_strings.append(decoded)

            # High-entropy string extraction
            if len(s) >= 16:  # Only check longer strings for entropy
                decoded = s.decode("ascii", errors="replace")
                entropy = shannon_entropy(decoded)

                if entropy >= self._min_entropy:
                    if strings_found < self._max_strings:
                        analysis.high_entropy_strings.append({
                            "value": _redact_string(decoded),
                            "length": len(decoded),
                            "entropy": round(entropy, 2),
                            "offset": match.start(),
                        })
                        strings_found += 1


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns a value between 0.0 (uniform) and ~log2(charset_size).
    Typical thresholds:
    - < 3.0: likely natural language or code
    - 3.0–4.0: could be either
    - > 4.0: likely encoded/encrypted data or random strings
    - > 5.0: almost certainly high-entropy (keys, tokens, etc.)
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _redact_string(s: str) -> str:
    """Show first 8 / last 4 chars, mask the middle."""
    if len(s) <= 16:
        return s[:4] + "***" + s[-4:]
    return s[:8] + "..." + s[-4:]


__all__ = ["NativeAnalyzer", "NativeAnalysisResult", "ElfAnalysis", "shannon_entropy"]
