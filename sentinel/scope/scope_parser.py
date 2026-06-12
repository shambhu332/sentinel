"""S_001 Scope Ingestion — parse bug bounty program scope from any platform.

Supports three input modes (Option C):
    1. --scope-url https://hackerone.com/program
    2. --scope-file ./scope.json or ./scope.txt
    3. --scope-text "inline pasted scope text"

Platforms detected from URL:
    - HackerOne (hackerone.com)
    - Bugcrowd (bugcrowd.com)
    - YesWeHack (yeswehack.com)
    - Intigriti (intigriti.com)
    - Immunefi (immunefi.com)

When a URL is given, SENTINEL tries to fetch it. If fetch fails (auth wall,
rate limit, HTML changed), it falls back to asking the user to paste the
scope text. The paste approach works 100% of the time as a last resort.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from sentinel.core.finding import BountyScope

logger = logging.getLogger(__name__)

FETCH_TIMEOUT = 15.0
MAX_SCOPE_SIZE = 500_000  # 500KB — legitimate scope pages are <200KB
USER_AGENT = "SENTINEL-security-scanner/0.1 (+https://github.com/sentinel)"

# Package name pattern: com.example.app
PACKAGE_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,6})\b")
# Domain pattern (supports *.example.com wildcards)
DOMAIN_RE = re.compile(r"\b(?:\*\.)?(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}\b", re.IGNORECASE)
# Reward extraction: $500 - $5,000 or $1000-$10000
REWARD_RE = re.compile(r"\$\s*([\d,]+)\s*[-–—to]+\s*\$?\s*([\d,]+)", re.IGNORECASE)

# Techniques universally forbidden by most bounty programs
COMMON_FORBIDDEN = [
    ("dos", r"\b(denial[\s-]of[\s-]service|dos|ddos|volumetric)\b"),
    ("social-engineering", r"\bsocial[\s-]engineer"),
    ("physical", r"\bphysical[\s-]attack"),
    ("brute-force", r"\bbrute[\s-]forc"),
    ("automated-scanning", r"\bautomated[\s-]scan|aggressive[\s-]scan"),
    ("spam", r"\bspam\b"),
]


class ScopeSourceError(Exception):
    """All scope sources failed."""


class ScopeParser:
    """Detects platform from URL, fetches, parses into BountyScope."""

    # TLDs that appear as the FIRST segment in Android/iOS package names
    PACKAGE_PREFIXES = {
        "com", "org", "net", "io", "co", "me", "app", "dev",
        "edu", "gov", "info", "xyz", "uk", "us", "ca", "de",
        "jp", "fr", "eu", "au", "in",
    }

    VALID_DOMAIN_TLDS = {
        "com", "org", "net", "io", "co", "app", "dev", "info",
        "xyz", "uk", "us", "ca", "de", "jp", "fr", "eu", "au", "in",
    }

    PLATFORM_HOSTS = {
        "hackerone.com": "hackerone",
        "bugcrowd.com": "bugcrowd",
        "yeswehack.com": "yeswehack",
        "intigriti.com": "intigriti",
        "immunefi.com": "immunefi",
    }

    def __init__(self, timeout: float = FETCH_TIMEOUT) -> None:
        self._timeout = timeout

    # ---------- Entry points ----------

    def from_url(self, url: str) -> BountyScope:
        """Fetch URL and parse. Raises ScopeSourceError on any fetch failure."""
        if not self._is_safe_url(url):
            raise ScopeSourceError(f"URL not allowed: {url}")

        platform = self._detect_platform(url)
        try:
            text = self._fetch(url)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError) as e:
            raise ScopeSourceError(f"Fetch failed for {url}: {e}") from e

        return self._parse_text(text, platform=platform, source_url=url)

    def from_file(self, path: Path, allowed_root: Path | None = None) -> BountyScope:
        """Parse scope from a local file. Auto-detects JSON vs plain text."""
        path = path.expanduser().resolve()
        if allowed_root is not None:
            root = allowed_root.expanduser().resolve()
            if not path.is_relative_to(root):
                raise ScopeSourceError(f"Scope file outside allowed root: {path}")
        if not path.exists():
            raise ScopeSourceError(f"Scope file not found: {path}")
        if not path.is_file():
            raise ScopeSourceError(f"Not a file: {path}")
        if path.stat().st_size > MAX_SCOPE_SIZE:
            raise ScopeSourceError(f"Scope file too large: {path.stat().st_size} bytes")

        content = path.read_text(encoding="utf-8", errors="replace")

        # Try JSON first (structured scope file)
        if path.suffix.lower() == ".json" or content.lstrip().startswith("{"):
            try:
                return self._parse_json(json.loads(content))
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning("JSON parse failed, falling back to text: %s", e)

        return self._parse_text(content, platform="file", source_url=str(path))

    def from_text(self, text: str, platform: str = "manual") -> BountyScope:
        """Parse pasted scope text directly."""
        if len(text) > MAX_SCOPE_SIZE:
            raise ScopeSourceError(f"Scope text too large: {len(text)} bytes")
        return self._parse_text(text, platform=platform, source_url="")

    # ---------- Platform detection ----------

    def _detect_platform(self, url: str) -> str:
        host = (urlparse(url).hostname or "").lower()
        for platform_host, name in self.PLATFORM_HOSTS.items():
            if platform_host in host:
                return name
        return "unknown"

    def _is_safe_url(self, url: str) -> bool:
        """Block non-HTTP(S), localhost, private IPs — basic SSRF guard."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        if parsed.scheme not in {"http", "https"}:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host == "localhost":
            return False
        try:
            return self._is_public_ip(ipaddress.ip_address(host))
        except ValueError:
            return self._hostname_resolves_public(host)

    @staticmethod
    def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    def _hostname_resolves_public(self, host: str) -> bool:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False
        addresses = {info[4][0] for info in infos if info and info[4]}
        if not addresses:
            return False
        for address in addresses:
            try:
                if not self._is_public_ip(ipaddress.ip_address(address)):
                    return False
            except ValueError:
                return False
        return True

    # ---------- Fetch ----------

    def _fetch(self, url: str) -> str:
        """Fetch URL content with size limit and proper user agent."""
        with httpx.Client(
            timeout=self._timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = client.get(url)
            if resp.is_redirect:
                location = resp.headers.get("location", "")
                redirected = str(resp.url.join(location)) if location else ""
                if not redirected or not self._is_safe_url(redirected):
                    raise httpx.HTTPError("unsafe redirect blocked")
                resp = client.get(redirected)
            resp.raise_for_status()
            text = resp.text
            if len(text) > MAX_SCOPE_SIZE:
                logger.warning("Truncating scope page (%d bytes)", len(text))
                text = text[:MAX_SCOPE_SIZE]
            return text

    # ---------- Parsing ----------

    def _parse_json(self, data: dict[str, Any]) -> BountyScope:
        """Parse structured JSON scope file."""
        return BountyScope(
            program_name=str(data.get("program_name", ""))[:200],
            platform=str(data.get("platform", "file"))[:50],
            in_scope_packages=[str(x)[:200] for x in data.get("in_scope_packages", [])],
            in_scope_domains=[str(x)[:200] for x in data.get("in_scope_domains", [])],
            out_of_scope_packages=[str(x)[:200] for x in data.get("out_of_scope_packages", [])],
            out_of_scope_domains=[str(x)[:200] for x in data.get("out_of_scope_domains", [])],
            excluded_vuln_classes=set(str(x)[:100] for x in data.get("excluded_vuln_classes", [])),
            forbidden_techniques=set(str(x)[:100] for x in data.get("forbidden_techniques", [])),
            reward_ranges={
                str(k)[:50]: (int(v[0]), int(v[1]))
                for k, v in data.get("reward_ranges", {}).items()
                if isinstance(v, (list, tuple)) and len(v) == 2
            },
        )

    def _parse_text(self, text: str, platform: str, source_url: str) -> BountyScope:
        """Heuristic text parser that works across platforms."""
        # Extract program name from ORIGINAL text (preserves casing) BEFORE lowercasing
        program_name = self._extract_program_name(text, source_url)

        # Strip HTML tags if present
        if "<" in text and ">" in text:
            text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"&nbsp;", " ", text)
            text = re.sub(r"&amp;", "&", text)
            text = re.sub(r"&lt;", "<", text)
            text = re.sub(r"&gt;", ">", text)

        # Keep original for reward extraction (preserves $ formatting)
        original_text = text
        text_lower = text.lower()

        in_scope_section, out_scope_section = self._split_sections(text_lower)

        in_pkgs = self._extract_packages(in_scope_section) if in_scope_section else []
        out_pkgs = self._extract_packages(out_scope_section) if out_scope_section else []
        in_domains = self._extract_domains(in_scope_section) if in_scope_section else []
        out_domains = self._extract_domains(out_scope_section) if out_scope_section else []

        if not in_pkgs and not in_domains:
            in_pkgs = self._extract_packages(text_lower)
            in_domains = self._extract_domains(text_lower)

        forbidden = self._extract_forbidden_techniques(text_lower)
        rewards = self._extract_rewards(original_text)

        return BountyScope(
            program_name=program_name,
            platform=platform,
            in_scope_packages=sorted(set(in_pkgs))[:100],
            in_scope_domains=sorted(set(in_domains))[:100],
            out_of_scope_packages=sorted(set(out_pkgs))[:100],
            out_of_scope_domains=sorted(set(out_domains))[:100],
            excluded_vuln_classes=set(),
            forbidden_techniques=forbidden,
            reward_ranges=rewards,
        )

    def _split_sections(self, text: str) -> tuple[str, str]:
        """Roughly split into in-scope and out-of-scope sections."""
        in_markers = ["in scope", "in-scope", "targets", "assets in scope", "scope"]
        out_markers = ["out of scope", "out-of-scope", "exclusions", "not in scope",
                       "excluded assets", "explicitly excluded"]

        in_start = -1
        out_start = -1
        for m in in_markers:
            idx = text.find(m)
            if idx != -1 and (in_start == -1 or idx < in_start):
                in_start = idx
        for m in out_markers:
            idx = text.find(m)
            if idx != -1 and (out_start == -1 or idx < out_start):
                out_start = idx

        if in_start == -1 and out_start == -1:
            return "", ""
        if out_start == -1:
            return text[in_start:], ""
        if in_start == -1:
            return "", text[out_start:]
        if in_start < out_start:
            return text[in_start:out_start], text[out_start:]
        return text[in_start:], text[out_start:in_start]

    def _extract_packages(self, text: str) -> list[str]:
        """Find Android/iOS package names (reverse-DNS: com.example.app)."""
        results = []
        for m in PACKAGE_RE.finditer(text):
            pkg = m.group(1)
            if pkg.count(".") < 1 or len(pkg) > 200:
                continue
            first_segment = pkg.split(".")[0]
            # Packages start with a reverse-DNS prefix
            if first_segment not in self.PACKAGE_PREFIXES:
                continue
            results.append(pkg)
        return results

    def _extract_domains(self, text: str) -> list[str]:
        """Find domain names (forward notation ending in real TLD)."""
        results = []
        for m in DOMAIN_RE.finditer(text):
            domain = m.group(0).lower()
            if len(domain) > 200:
                continue
            # Skip the bounty platforms themselves
            if domain in {"hackerone.com", "bugcrowd.com", "yeswehack.com",
                         "intigriti.com", "immunefi.com"}:
                continue
            parts = domain.split(".")
            if len(parts) < 2:
                continue
            first = parts[0].lstrip("*")
            last = parts[-1]
            if last not in self.VALID_DOMAIN_TLDS:
                continue
            # Reject reverse-DNS patterns
            if first in self.PACKAGE_PREFIXES:
                continue
            results.append(domain)
        return results

    def _extract_forbidden_techniques(self, text: str) -> set[str]:
        """Detect commonly forbidden techniques mentioned in the scope."""
        forbidden = set()
        for name, pattern in COMMON_FORBIDDEN:
            if re.search(pattern, text, re.IGNORECASE):
                forbidden.add(name)
        return forbidden

    def _extract_rewards(self, text: str) -> dict[str, tuple[int, int]]:
        """Extract severity → reward range mappings."""
        result: dict[str, tuple[int, int]] = {}
        severities = ["critical", "high", "medium", "low"]
        for sev in severities:
            pattern = re.compile(
                rf"\b{sev}\b[^$]{{0,200}}\$\s*([\d,]+)\s*[-–—to]+\s*\$?\s*([\d,]+)",
                re.IGNORECASE | re.DOTALL,
            )
            m = pattern.search(text)
            if m:
                try:
                    lo = int(m.group(1).replace(",", ""))
                    hi = int(m.group(2).replace(",", ""))
                    if 0 < lo <= hi <= 10_000_000:
                        result[sev] = (lo, hi)
                except ValueError:
                    pass
        return result

    def _extract_program_name(self, text: str, source_url: str) -> str:
        """Best-effort program name extraction. Uses ORIGINAL text (not lowercased)."""
        m = re.search(r"<title>([^<]{1,200})</title>", text, re.IGNORECASE)
        if m:
            title = m.group(1).strip()
            for suffix in [" | HackerOne", " · Bugcrowd", " - YesWeHack",
                          " | Intigriti", " - Immunefi"]:
                if title.endswith(suffix):
                    title = title[:-len(suffix)]
            return title[:200]
        if source_url:
            path = urlparse(source_url).path.strip("/")
            if path:
                return path.split("/")[-1][:200]
        return "unknown"


# ---------- Convenience function ----------

def parse_scope(
    url: str | None = None,
    file: Path | None = None,
    text: str | None = None,
) -> BountyScope:
    """Parse scope from any source. Tries URL first, then file, then text."""
    parser = ScopeParser()
    errors = []

    if url:
        try:
            return parser.from_url(url)
        except ScopeSourceError as e:
            errors.append(f"url: {e}")
            logger.warning("URL fetch failed, trying next source: %s", e)

    if file:
        try:
            return parser.from_file(file)
        except ScopeSourceError as e:
            errors.append(f"file: {e}")

    if text:
        return parser.from_text(text)

    if errors:
        raise ScopeSourceError("All scope sources failed: " + "; ".join(errors))
    raise ScopeSourceError("No scope source provided")
