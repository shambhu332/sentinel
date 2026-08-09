"""OST_001 — Passive APK Recon Agent.

Performs passive OSINT against domains and subdomains extracted from
an APK without making any requests to the target app itself.

Three data sources:
  1. crt.sh certificate transparency log (JSON API)
  2. Wayback Machine CDX API (historical URLs)
  3. APK manifest + string extraction (local only)

All network calls go to crt.sh and web.archive.org — never to the
target. This makes the module safe to run against in-scope production
apps without triggering WAF alerts or rate-limit bans.

Scope guardrails
----------------
Only domains that share a registered suffix with the APK package name
(or with explicitly in-scope domains from BountyScope) are queried.
Everything else is classified INFO-only and logged rather than queried.

Output
------
Findings are all Severity.INFO — this agent surfaces recon context,
not exploitable vulnerabilities. Consumers (triage LLM, report builder)
use the evidence to prioritise deeper testing against discovered endpoints.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Maximum certificates to pull from crt.sh per domain.
_CRT_MAX = 200
# Maximum Wayback CDX rows per domain.
_CDX_MAX = 300
# Request timeout for all OSINT HTTP calls (seconds).
_HTTP_TIMEOUT = 10
# Maximum unique domains to actively query (prevents runaway scans).
_MAX_ACTIVE_DOMAINS = 15


@dataclass
class _DomainBucket:
    """Aggregated recon data for one discovered domain."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    wayback_urls: list[str] = field(default_factory=list)
    source: str = "manifest"  # manifest | strings | crt_sh | wayback


class ApkReconAgent(BaseAgent):
    """OST_001: passive OSINT recon — crt.sh + Wayback CDX."""

    AGENT_ID = "OST_001"
    VULN_CLASS = "RECON_SURFACE"
    PHASE = "Phase 0"
    CATEGORY = "OSINT"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.apk_path is None or not Path(ctx.apk_path).exists():
            self._log.info("[OST_001] no APK path — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        manifest = ctx.manifest or {}

        # --- Step 1: extract seed domains from manifest + strings ---
        seed_domains = self._extract_seed_domains(manifest, ctx)
        if not seed_domains:
            self._log.info("[OST_001] no seed domains extracted")
            return []

        self._log.info(
            "[OST_001] %d seed domain(s): %s",
            len(seed_domains), seed_domains,
        )

        # --- Step 2: scope guard — only query domains in-scope ---
        active, passive = self._partition_scope(seed_domains, ctx)
        self._log.info(
            "[OST_001] active query: %d, passive (out-of-scope): %d",
            len(active), len(passive),
        )
        active = active[:_MAX_ACTIVE_DOMAINS]

        # --- Step 3: run crt.sh + Wayback concurrently per domain ---
        buckets = await self._recon_all(active)

        # --- Step 4: emit findings ---
        findings: list[Finding] = []
        for bucket in buckets:
            if bucket.subdomains or bucket.wayback_urls:
                findings.append(self._bucket_to_finding(bucket))

        if passive:
            findings.append(self._oos_finding(passive))

        self._log.info("[OST_001] emitted %d recon findings", len(findings))
        return findings

    # ---------- Domain extraction ----------

    @staticmethod
    def _extract_seed_domains(
        manifest: dict, ctx: Any,
    ) -> list[str]:
        domains: set[str] = set()

        # Package name → com.example.app → example.com heuristic
        package = manifest.get("package", "")
        if package:
            parts = package.split(".")
            if len(parts) >= 2:
                # Reverse the first two parts: com.example → example.com
                domains.add(f"{parts[1]}.{parts[0]}")

        # Network security config / intent-filter hosts
        for host in manifest.get("hosts", []):
            clean = host.lstrip("*.")
            if clean and "." in clean:
                domains.add(clean)

        # BountyScope explicit domains
        scope = ctx.scope
        for d in getattr(scope, "in_scope_domains", []) or []:
            clean = d.lstrip("*.")
            if clean and "." in clean:
                domains.add(clean)

        # Decompiled strings scan (cheap: look for http/https URLs)
        decompiled = ctx.decompiled_dir
        if decompiled and decompiled.exists():
            domains.update(ApkReconAgent._scan_strings_for_domains(decompiled))

        return sorted(domains)

    @staticmethod
    def _scan_strings_for_domains(root: Path) -> list[str]:
        """Grep decompiled sources for embedded domain strings."""
        url_re = re.compile(
            r'https?://([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)',
        )
        found: set[str] = set()
        try:
            for path in root.rglob("*.java"):
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                for m in url_re.finditer(text):
                    host = m.group(1).lower()
                    # Skip localhost / loopback / obvious non-targets
                    if host in {"localhost", "127.0.0.1"} or host.endswith(".local"):
                        continue
                    # Strip www prefix
                    if host.startswith("www."):
                        host = host[4:]
                    found.add(host)
                if len(found) > 50:
                    break
        except Exception as e:  # noqa: BLE001
            logger.debug("[OST_001] string scan error: %s", e)
        return list(found)

    @staticmethod
    def _partition_scope(
        domains: list[str], ctx: Any,
    ) -> tuple[list[str], list[str]]:
        """Split domains into (active-query, out-of-scope) lists."""
        scope = ctx.scope
        if scope.is_unrestricted():
            return list(domains), []
        active, passive = [], []
        for d in domains:
            if scope.domain_in_scope(d):
                active.append(d)
            else:
                passive.append(d)
        return active, passive

    # ---------- OSINT queries ----------

    async def _recon_all(self, domains: list[str]) -> list[_DomainBucket]:
        tasks = [self._recon_domain(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[_DomainBucket] = []
        for domain, res in zip(domains, results):
            if isinstance(res, Exception):
                self._log.debug("[OST_001] recon failed for %s: %s", domain, res)
                continue
            out.append(res)
        return out

    async def _recon_domain(self, domain: str) -> _DomainBucket:
        bucket = _DomainBucket(domain=domain)
        loop = asyncio.get_event_loop()
        # Run blocking HTTP calls in executor to keep the event loop free.
        crt_task = loop.run_in_executor(None, self._fetch_crt, domain)
        cdx_task = loop.run_in_executor(None, self._fetch_cdx, domain)
        crt_result, cdx_result = await asyncio.gather(
            crt_task, cdx_task, return_exceptions=True,
        )
        if isinstance(crt_result, list):
            bucket.subdomains = crt_result
        if isinstance(cdx_result, list):
            bucket.wayback_urls = cdx_result
        return bucket

    @staticmethod
    def _fetch_crt(domain: str) -> list[str]:
        """Query crt.sh for subdomains via Certificate Transparency logs."""
        url = (
            f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}"
            f"&output=json"
        )
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "sentinel-osint/1.0"},
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                data: list[dict] = json.loads(resp.read().decode())
        except Exception as e:
            logger.debug("[OST_001] crt.sh error for %s: %s", domain, e)
            return []

        seen: set[str] = set()
        results: list[str] = []
        for entry in data[:_CRT_MAX]:
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                sub = sub.strip().lstrip("*.")
                if sub and sub not in seen and domain in sub:
                    seen.add(sub)
                    results.append(sub)
        return results

    @staticmethod
    def _fetch_cdx(domain: str) -> list[str]:
        """Query Wayback Machine CDX API for historical URLs."""
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{urllib.parse.quote(domain)}/*"
            "&output=json&fl=original&collapse=urlkey"
            f"&limit={_CDX_MAX}"
        )
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "sentinel-osint/1.0"},
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                rows: list[list[str]] = json.loads(resp.read().decode())
        except Exception as e:
            logger.debug("[OST_001] Wayback CDX error for %s: %s", domain, e)
            return []

        # First row is the header ["original"]; skip it.
        return [row[0] for row in rows[1:] if row]

    # ---------- Finding builders ----------

    def _bucket_to_finding(self, bucket: _DomainBucket) -> Finding:
        unique_subs = sorted(set(bucket.subdomains))
        unique_urls = sorted(set(bucket.wayback_urls))
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=1.0,
            evidence={
                "domain": bucket.domain,
                "subdomains": unique_subs[:50],
                "subdomain_count": len(unique_subs),
                "wayback_urls": unique_urls[:30],
                "wayback_url_count": len(unique_urls),
                "source": "crt.sh + wayback_cdx",
                "note": (
                    "Passive recon only — no requests were sent to the target. "
                    "Use discovered subdomains to prioritise network agent scope."
                ),
            },
            owasp="M8: Security Misconfiguration",
            masvs="MASVS-NETWORK-1",
            recommendation=(
                f"Review {len(unique_subs)} discovered subdomain(s) for "
                "forgotten assets, staging environments, and admin panels. "
                "Verify each against the bug bounty scope before testing."
            ),
        )

    def _oos_finding(self, domains: list[str]) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.INFO,
            confidence=1.0,
            evidence={
                "out_of_scope_domains": domains,
                "note": (
                    "These domains were extracted from the APK but are outside "
                    "the declared bounty scope — OSINT queries were skipped."
                ),
            },
            owasp="M8: Security Misconfiguration",
            masvs="MASVS-NETWORK-1",
            recommendation="Confirm scope with the programme owner before testing.",
        )


__all__ = ["ApkReconAgent"]
