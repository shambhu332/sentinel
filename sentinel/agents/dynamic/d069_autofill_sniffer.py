"""D_069 — Autofill leak detector.

Pure SAST — no DAST trigger needed. Flags sensitive EditText fields
that don't set importantForAutofill="no" / autofillHints (so the
Android autofill framework caches them for any service).
"""
from __future__ import annotations

import logging
import re

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)
_SENSITIVE_INPUT_TYPES = (
    "textPassword", "numberPassword", "textWebPassword",
    "textVisiblePassword",
)
_SENSITIVE_HINT_RE = re.compile(
    r'\b(password|otp|pin|cvv|card_number|ssn|secret|seed_phrase)\b',
    re.IGNORECASE,
)


class AutofillSnifferAgent(BaseAgent):
    AGENT_ID = "D_069"
    VULN_CLASS = "Sensitive Field Leaked to Autofill"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.resources_dir
            and self._context.resources_dir.exists()
        )

    async def analyze(self) -> list[Finding]:
        res = self._context.resources_dir
        if res is None:
            return []
        layouts_dir = res / "res" / "layout"
        if not layouts_dir.is_dir():
            return []
        findings: list[Finding] = []
        scanned = 0
        for xml in layouts_dir.rglob("*.xml"):
            scanned += 1
            if scanned > 1500:
                break
            try:
                text = xml.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Find every EditText
            for m in re.finditer(
                r"<EditText\b([^>]*)/?>", text,
            ):
                attrs = m.group(1)
                is_password = any(
                    f'android:inputType="{t}"' in attrs
                    or f'android:inputType="{t}|' in attrs
                    or f'|{t}"' in attrs
                    for t in _SENSITIVE_INPUT_TYPES
                )
                has_sensitive_hint = bool(_SENSITIVE_HINT_RE.search(attrs))
                if not (is_password or has_sensitive_hint):
                    continue
                # Check for autofill protection
                protected = (
                    'android:importantForAutofill="no"' in attrs
                    or 'android:autofillHints=' in attrs
                )
                if protected:
                    continue
                rel = str(xml.relative_to(res))
                findings.append(self._make_finding(
                    vuln_class=self.VULN_CLASS,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    recommendation=(
                        "Sensitive EditText field with no "
                        "android:importantForAutofill=\"no\" or "
                        "android:autofillHints attribute. Android's "
                        "autofill framework caches the field's content "
                        "for any installed autofill service. Add "
                        "android:importantForAutofill=\"no\" for "
                        "passwords / PINs / OTPs / CVVs that should "
                        "never be cached."
                    ),
                    evidence={
                        "layout": rel,
                        "attrs_excerpt": attrs.strip()[:200],
                        "is_password_input_type": is_password,
                        "has_sensitive_hint": has_sensitive_hint,
                    },
                ))
        return findings


__all__ = ["AutofillSnifferAgent"]
