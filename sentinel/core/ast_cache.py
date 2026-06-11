"""AstCache — Global Tree-sitter AST cache shared across all agents.

Problem: agents like TAINT_001, P_010, B_007, and others independently
parse the same Java files into Tree-sitter CSTs. On a 91MB APK with
5,000+ source files, this redundant work adds 15–30 seconds of CPU
time per duplicated parse.

Solution: a process-wide LRU-bounded cache keyed by (file_path, mtime).
The first agent to parse a file stores the tree; subsequent agents get
an O(1) dict lookup instead of an O(n) parse.

Thread/task safety: Tree-sitter trees are immutable once parsed, so
concurrent async reads are safe. The cache itself uses a simple dict
with an asyncio.Lock around writes to prevent double-parse races.

Memory management: the cache enforces a configurable max_entries limit.
When exceeded, oldest entries (by insertion order) are evicted. Default
is 5000 files ≈ ~500MB peak for large APKs.
"""
from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default maximum number of cached AST trees
_DEFAULT_MAX_ENTRIES = 5000


@dataclass
class CachedTree:
    """A cached Tree-sitter parse result."""

    tree: Any  # tree_sitter.Tree
    language: str  # "java", "xml", "kotlin"
    file_path: str
    mtime: float
    byte_size: int


class AstCache:
    """Process-wide Tree-sitter AST cache with LRU eviction.

    Usage from any agent::

        cache = ctx.ast_cache  # populated by orchestrator
        tree = await cache.get_or_parse(path, "java")
        if tree is not None:
            root = tree.tree.root_node
            # ... walk the CST
    """

    def __init__(self, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
        self._max_entries = max_entries
        self._cache: OrderedDict[str, CachedTree] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
        self._parser_cache: dict[str, Any] = {}  # language -> ts.Parser

    @property
    def size(self) -> int:
        """Number of entries currently cached."""
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """Cache hit ratio (0.0–1.0)."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict[str, Any]:
        """Cache statistics for diagnostic reporting."""
        return {
            "entries": len(self._cache),
            "max_entries": self._max_entries,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 3),
        }

    async def get_or_parse(
        self,
        file_path: Path,
        language: str = "java",
    ) -> CachedTree | None:
        """Return a cached tree or parse the file and cache it.

        Returns None if:
        - The file does not exist or is unreadable
        - tree_sitter is not installed
        - The language binding is unavailable
        """
        path_str = str(file_path.resolve())

        try:
            mtime = file_path.stat().st_mtime
        except OSError:
            return None

        # Fast path: cache hit (no lock needed for reads of immutable trees)
        cached = self._cache.get(path_str)
        if cached is not None and cached.mtime == mtime:
            self._hits += 1
            # Move to end for LRU ordering
            self._cache.move_to_end(path_str)
            return cached

        # Slow path: parse and cache
        async with self._lock:
            # Double-check after acquiring lock
            cached = self._cache.get(path_str)
            if cached is not None and cached.mtime == mtime:
                self._hits += 1
                self._cache.move_to_end(path_str)
                return cached

            self._misses += 1
            tree = await self._parse_file(file_path, language)
            if tree is None:
                return None

            # Read file size for memory tracking
            try:
                byte_size = file_path.stat().st_size
            except OSError:
                byte_size = 0

            entry = CachedTree(
                tree=tree,
                language=language,
                file_path=path_str,
                mtime=mtime,
                byte_size=byte_size,
            )

            # Evict oldest if at capacity
            while len(self._cache) >= self._max_entries:
                evicted_key, _ = self._cache.popitem(last=False)
                logger.debug("AST cache evicted: %s", evicted_key)

            self._cache[path_str] = entry
            return entry

    async def _parse_file(
        self,
        file_path: Path,
        language: str,
    ) -> Any | None:
        """Parse a source file using Tree-sitter.

        Returns the tree_sitter.Tree object, or None on failure.
        Runs the actual parse in an executor to avoid blocking the event loop.
        """
        try:
            import tree_sitter  # noqa: F811
        except ImportError:
            logger.debug("tree_sitter not installed — AST cache disabled")
            return None

        parser = self._get_parser(language)
        if parser is None:
            return None

        try:
            source = file_path.read_bytes()
        except OSError as e:
            logger.debug("Cannot read %s: %s", file_path, e)
            return None

        loop = asyncio.get_event_loop()
        try:
            tree = await loop.run_in_executor(None, parser.parse, source)
            return tree
        except Exception as e:  # noqa: BLE001
            logger.debug("Tree-sitter parse failed for %s: %s", file_path, e)
            return None

    def _get_parser(self, language: str) -> Any | None:
        """Get or create a Tree-sitter parser for the given language."""
        if language in self._parser_cache:
            return self._parser_cache[language]

        try:
            import tree_sitter  # noqa: F811

            parser = tree_sitter.Parser()

            # Try to load the language binding
            lang_module = self._load_language(language)
            if lang_module is None:
                return None

            parser.language = lang_module
            self._parser_cache[language] = parser
            return parser

        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to create parser for %s: %s", language, e)
            return None

    @staticmethod
    def _load_language(language: str) -> Any | None:
        """Load a Tree-sitter language binding.

        Supports the modern tree-sitter-languages package format
        (tree_sitter_java, tree_sitter_xml, etc.) and falls back
        gracefully if the language pack is missing.
        """
        module_name = f"tree_sitter_{language}"
        try:
            import importlib
            lang_mod = importlib.import_module(module_name)
            # Modern tree-sitter-language packages expose a Language class
            if hasattr(lang_mod, "language"):
                return lang_mod.language()
            if hasattr(lang_mod, "Language"):
                return lang_mod.Language
            logger.debug("Language module %s has no 'language()' callable", module_name)
            return None
        except ImportError:
            logger.debug("Language pack %s not installed", module_name)
            return None

    def invalidate(self, file_path: Path) -> bool:
        """Remove a specific file from the cache. Returns True if evicted."""
        path_str = str(file_path.resolve())
        if path_str in self._cache:
            del self._cache[path_str]
            return True
        return False

    def clear(self) -> None:
        """Flush all cached trees."""
        count = len(self._cache)
        self._cache.clear()
        self._hits = 0
        self._misses = 0
        logger.info("AST cache cleared (%d entries evicted)", count)


__all__ = ["AstCache", "CachedTree"]
