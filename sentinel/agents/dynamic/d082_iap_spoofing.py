"""D_082 — IAP Spoofing (active Frida target identifier).

Counterpart to D_008 (passive observer of billing events). D_008
detects when an unverified purchase actually unlocks a feature; D_082
*provokes* the bypass by emitting a Frida payload that synthesises a
PURCHASED Purchase object and replays the `onPurchasesUpdated`
callback with no real Google Play transaction.

SAST half walks decompiled Java for:

  1. **Billing surface** — `BillingClient.Builder`,
     `PurchasesUpdatedListener`, `Purchase.PurchaseState`,
     `queryPurchasesAsync`. Without these the agent has nothing to
     hook.

  2. **Server-side verification gap** — looks for the absence of
     network calls referencing the purchase token. The heuristic:
     in the same class (or one it directly references) we expect to
     see `purchase.getPurchaseToken()` followed within ~40 lines by
     `OkHttpClient.newCall` / `Retrofit` / `HttpURLConnection`. When
     the token never leaves the device, the entitlement is decided
     client-side and the spoof works.

  3. **Direct entitlement grant inside the callback** — patterns like
     `onPurchasesUpdated -> setPremium(true)` / `unlockFeature()` /
     `SharedPreferences.edit().putBoolean("premium", true)` without
     a token-validation hop in between. Highest severity.

Output finding carries `dynamic_target=True` and a `frida_payload`
describing the listener class + the SKUs to spoof. Per the brief's
safety guidance: SafetyBudget is tight (5 actions / 1 per sec / 15s)
and the Frida hook ONLY tampers with the local callback — never
constructs a real Google Play network exchange.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Billing-surface markers — at least one must appear or the agent skips.
_BILLING_MARKERS = (
    "BillingClient",
    "PurchasesUpdatedListener",
    "com.android.billingclient",
    "queryPurchasesAsync",
)

# Pattern for the callback declaration we'd hook.
_LISTENER_DECL_RE = re.compile(
    r"\b(?:class|new)\s+(\w+)\s+(?:extends|implements)\s+"
    r"PurchasesUpdatedListener\b"
    r"|onPurchasesUpdated\s*\("
    r"\s*(?:int|com\.android\.billingclient\.api\.BillingResult)\b"
)
# Network-call markers — presence implies token is leaving the device.
_NETWORK_MARKERS_RE = re.compile(
    r"\bOkHttpClient\b|\bRetrofit\b|\bHttpURLConnection\b"
    r"|\bHttpClient\b|\bVolley\b|\b\.execute\s*\("
)
# Token-flow signal — when the token is captured into a variable that
# is then handed to a network call.
_TOKEN_GETTER_RE = re.compile(r"\.\s*getPurchaseToken\s*\(\s*\)")
# Client-side entitlement-grant shapes inside the callback body.
_DIRECT_ENTITLEMENT_RE = re.compile(
    r"\b(setPremium|unlockFeature|grantEntitlement|setVip|"
    r"setSubscribed|markPaid|setPro)\s*\("
    r"|putBoolean\s*\(\s*\"(premium|pro|vip|paid|subscribed|unlocked)\""
)
# SKU literals — used as the spoof payload list at runtime.
_SKU_RE = re.compile(r'(?:"(?:premium|vip|pro|unlock|coins?|gems?|gold|monthly|yearly|sub_\w+|inapp_\w+)"|"sku_\w+")')

_MAX_FILES = 2500


class IapSpoofingAgent(BaseAgent):
    """D_082: identify client-side-trust IAP flows for Frida spoofing."""

    AGENT_ID = "D_082"
    VULN_CLASS = "IAP Spoofing (Dynamic Testing Target)"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(ctx.decompiled_dir and ctx.decompiled_dir.exists())

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        findings: list[Finding] = []
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not any(marker in text for marker in _BILLING_MARKERS):
                continue
            # Need the callback shape at least once
            if not _LISTENER_DECL_RE.search(text):
                continue
            rel = str(path.relative_to(root))
            class_name = path.stem.split("$")[0]

            has_network = bool(_NETWORK_MARKERS_RE.search(text))
            has_token_getter = bool(_TOKEN_GETTER_RE.search(text))
            direct_entitlement = bool(_DIRECT_ENTITLEMENT_RE.search(text))

            # Verification heuristic: token captured AND a network call
            # exists somewhere in the same class. The 40-line proximity
            # check is a stronger signal but we keep this loose pattern
            # so we don't FN on indirect-but-correct flows.
            looks_verified = has_token_getter and has_network

            if looks_verified and not direct_entitlement:
                continue  # plausible server-side validation, skip

            severity = (
                Severity.HIGH if direct_entitlement
                else Severity.MEDIUM
            )
            skus = sorted(set(_SKU_RE.findall(text)))[:10]

            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=severity,
                confidence=0.65,
                recommendation=(
                    f"`{class_name}` implements `PurchasesUpdatedListener` "
                    "but lacks the visible server-side token-validation "
                    "hop expected for a robust IAP flow"
                    + (", AND contains direct client-side entitlement "
                       "grants in the callback. " if direct_entitlement
                       else ". ")
                    + "The Frida DAST hook will replay "
                    "`onPurchasesUpdated(BillingResult.OK, [PURCHASED])` "
                    "with a synthetic Purchase carrying a fake token + "
                    "the SKUs found in this class, and observe whether "
                    "the app unlocks premium features. Fix by always "
                    "sending the purchase token to your backend and "
                    "calling Google Play's `purchases.products.get` for "
                    "cryptographic verification before granting any "
                    "entitlement."
                ),
                evidence={
                    "file": rel,
                    "class": class_name,
                    "has_network_call": has_network,
                    "captures_purchase_token": has_token_getter,
                    "direct_entitlement_in_callback": direct_entitlement,
                    "candidate_skus": skus,
                    "dynamic_target": True,
                    "frida_payload": self._build_payload(class_name, skus),
                },
            ))
        return findings

    @staticmethod
    def _build_payload(class_name: str, skus: list[str]) -> dict[str, Any]:
        # Strip the surrounding quotes that came from the SKU regex.
        clean_skus = [s.strip('"') for s in skus] or [
            "premium", "vip", "pro", "unlock_all",
        ]
        return {
            "listener_class": class_name,
            "spoof_skus": clean_skus,
            "fake_purchase_token":
                "fake_token_d082_" + "0" * 32,  # marker we can grep for
            "fake_order_id": "GPA.SPOOF-0000-0000-0000",
            "purchase_state": 1,  # PURCHASED
            # NEVER call Play backend; this hook only tampers with the
            # in-process callback.
            "safe_mode_local_only": True,
            "monitor_entitlement_methods": [
                "setPremium", "unlockFeature", "grantEntitlement",
                "setVip", "setSubscribed", "markPaid", "setPro",
            ],
            "monitor_shared_prefs_keys": [
                "premium", "pro", "vip", "paid", "subscribed", "unlocked",
            ],
            "safety_budget": {
                "max_actions_total": 5,
                "max_actions_per_sec": 1,
                "wall_clock_budget_s": 15,
                "max_consecutive_crashes": 2,
            },
            "frida_script_hint":
                "// D_082 — synthesise PURCHASED + replay "
                "onPurchasesUpdated locally\n"
                "// rpc.exports.iapspoofing(payload) is the entry\n",
        }


__all__ = ["IapSpoofingAgent"]
