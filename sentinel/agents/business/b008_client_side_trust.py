"""B_008 — Client-Side Trust Agent.

Detects business logic flaws where security-critical decisions are made
on the client side, making them trivially bypassable.

Targets:
1. Client-side price/financial calculations on price/total/discount vars.
2. Hardcoded role checks like if (user.role == "admin").
3. Client-side feature gates (isPremium, isSubscribed, etc.).
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_FILES = 3000
_FINANCIAL_VARS = (
    "price", "total", "discount", "amount", "cost", "fee",
    "balance", "quantity", "subtotal", "tax",
)
_FINANCIAL_RE = re.compile(
    r'\b(' + '|'.join(_FINANCIAL_VARS) + r')\s*'
    r'(?:[+\-*/]=|=\s*(?:.*[+\-*/]))',
    re.IGNORECASE,
)
_ROLE_RE = re.compile(
    r'(?:\.role\s*(?:==|\.equals)\s*["\'](\w+)["\']'
    r'|getRole\(\)\.equals(?:IgnoreCase)?\s*\(\s*["\'](\w+)["\']'
    r'|["\'](?:admin|moderator|superuser|manager|root|owner)["\']'
    r'\s*\.equals\s*\()',
    re.IGNORECASE,
)
_GATE_RE = re.compile(
    r'\b(?:is|has|can)(?:Premium|Subscribed|Paid|Pro|Licensed|'
    r'Unlocked|Admin|Verified|Activated|Authorized)\b',
    re.IGNORECASE,
)
_SKIP = ("log.", "Log.", "logger.", "toString()", "// ", "/*", "test", "mock")


class ClientSideTrustAgent(BaseAgent):
    """B_008: detects client-side trust violations."""

    AGENT_ID = "B_008"
    VULN_CLASS = "Client-Side Trust Violation"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        ctx = self._context
        fin_hits: list[dict] = []
        role_hits: list[dict] = []
        gate_hits: list[dict] = []
        scanned = 0

        for path in ctx.decompiled_dir.rglob("*.java"):
            if not path.is_file() or path.name in {"R.java", "BuildConfig.java"}:
                continue
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(ctx.decompiled_dir))
            for ln, line in enumerate(content.splitlines(), 1):
                s = line.strip()
                if not s or len(s) < 10 or any(ex in s for ex in _SKIP):
                    continue
                if _FINANCIAL_RE.search(s) and len(fin_hits) < 25:
                    fin_hits.append({"file": rel, "line": ln, "code": s[:200]})
                if _ROLE_RE.search(s) and len(role_hits) < 25:
                    role_hits.append({"file": rel, "line": ln, "code": s[:200]})
                if _GATE_RE.search(s) and len(gate_hits) < 25:
                    gate_hits.append({"file": rel, "line": ln, "code": s[:200]})

        if fin_hits:
            findings.append(self._make_finding(
                vuln_class="Client-Side Price Manipulation",
                severity=Severity.HIGH, confidence=0.75,
                recommendation=(
                    "Move all financial calculations to the server. The client "
                    "should only display server-provided prices. An attacker can "
                    "hook these with Frida and set arbitrary values."
                ),
                evidence={"title": f"Client-side financial calcs: {len(fin_hits)}",
                          "match_count": len(fin_hits), "hits": fin_hits[:10]},
                owasp="M7: Client Code Quality", masvs="MSTG-ARCH-2",
            ))
        if role_hits:
            findings.append(self._make_finding(
                vuln_class="Client-Side Role Check",
                severity=Severity.HIGH, confidence=0.80,
                recommendation=(
                    "Remove hardcoded role checks from client code. Authorization "
                    "must be enforced server-side. Checks like "
                    "if(user.role==\"admin\") can be patched or Frida-hooked."
                ),
                evidence={"title": f"Hardcoded role checks: {len(role_hits)}",
                          "match_count": len(role_hits), "hits": role_hits[:10]},
                owasp="M6: Insecure Authorization", masvs="MSTG-AUTH-1",
            ))
        if gate_hits:
            findings.append(self._make_finding(
                vuln_class="Client-Side Feature Gate",
                severity=Severity.MEDIUM, confidence=0.65,
                recommendation=(
                    "Client-side feature gates (isPremium, isSubscribed) are "
                    "trivially bypassed by hooking the getter with Frida. Gate "
                    "premium features server-side using your payment provider."
                ),
                evidence={"title": f"Feature gates: {len(gate_hits)}",
                          "match_count": len(gate_hits), "hits": gate_hits[:10]},
                owasp="M7: Client Code Quality", masvs="MSTG-ARCH-2",
            ))
        return findings


__all__ = ["ClientSideTrustAgent"]
