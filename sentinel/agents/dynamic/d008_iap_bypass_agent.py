"""D_008 — In-App Purchase Bypass (runtime observation).

The Google Play Billing flow is:

    1. ``BillingClient.launchBillingFlow``        — user pays.
    2. The Play app delivers a ``Purchase`` with a signed JWS token.
    3. The app reads it via ``queryPurchasesAsync`` / ``onPurchasesUpdated``.
    4. The app sends the token to its backend.
    5. The backend calls Google Play Developer API
       ``purchases.products.get`` to *verify* the token cryptographically.
    6. Only after a positive server-side verdict does the backend mark
       the entitlement as granted.

The classic IAP-bypass bug is to skip step 5: the app trusts whatever
the client says about ``Purchase.purchaseState == PURCHASED`` and
unlocks the feature locally, with no server-side check. Frida-modded
``queryPurchasesAsync`` returning a synthesised purchase then grants
the user every premium feature for free, which is the exact pattern
used by "Lucky Patcher" and friends.

Detection
---------

We consume Frida events of kind:

* ``billing.purchase_observed`` — emitted when the app receives any
  ``Purchase`` instance (via the hooked callback or
  ``queryPurchasesAsync`` continuation). Payload:
  ``{sku, purchase_state, order_id, token_prefix, acknowledged}``.
* ``billing.feature_unlock`` — emitted by an optional companion hook
  on the app's own "entitlement set" routine. Payload:
  ``{entitlement, source}``.
* ``network.purchase_verification`` — emitted by the mitmproxy
  capture when an outbound request matches the Play Developer API
  verification pattern (``/androidpublisher/.../purchases/`` or any
  outbound POST whose body carries the captured ``purchase_token``).

Logic:

1. For every ``billing.feature_unlock`` event, look back at the
   ``billing.purchase_observed`` events that fired before it.
2. If we have ≥1 purchase observed AND zero
   ``network.purchase_verification`` events whose payload contains
   the matching ``purchase_token`` prefix, raise HIGH.
3. If a purchase is ``acknowledged=false`` after a feature unlock,
   raise MEDIUM — even if the backend was contacted, the app failed
   the mandatory acknowledgement which voids the purchase after 3
   days.

The agent has no way to confirm the *contents* of the server's
response; the absence of any verification request is the strong
signal.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


class IapBypassAgent(BaseAgent):
    """D_008: detect IAP unlocks with no server-side verification."""

    AGENT_ID = "D_008"
    VULN_CLASS = "In-App Purchase Verification Bypass"
    PHASE = "dynamic"

    async def is_applicable(self) -> bool:
        capture = self._context.sources.get("frida")
        if not capture:
            logger.info("[D_008] No Frida capture — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        capture = self._context.sources.get("frida")
        if capture is None or not capture.events:
            return []

        purchases: list[dict[str, Any]] = []
        unlocks: list[dict[str, Any]] = []
        for ev in capture.events:
            payload = ev.payload or {}
            if ev.kind == "billing.purchase_observed":
                purchases.append({
                    "sku": payload.get("sku"),
                    "purchase_state": payload.get("purchase_state"),
                    "order_id": payload.get("order_id"),
                    "token_prefix": str(payload.get("token_prefix") or ""),
                    "acknowledged": bool(payload.get("acknowledged")),
                    "timestamp": ev.timestamp,
                })
            elif ev.kind == "billing.feature_unlock":
                unlocks.append({
                    "entitlement": payload.get("entitlement"),
                    "source": payload.get("source"),
                    "timestamp": ev.timestamp,
                })

        # mitmproxy verifications, if any
        verification_tokens: set[str] = set()
        mitm = self._context.sources.get("mitmproxy")
        if mitm and getattr(mitm, "flows", None):
            for flow in mitm.flows:
                body = (getattr(flow, "request_body", "") or "")[:20000]
                # The Play purchase token is a long opaque string; we
                # only need the prefix because the Frida hook only
                # emits a prefix in the purchase event.
                for p in purchases:
                    pref = p["token_prefix"]
                    if pref and len(pref) >= 8 and pref in body:
                        verification_tokens.add(pref)

        if not purchases and not unlocks:
            return []

        findings: list[Finding] = []
        unverified_purchases = [
            p for p in purchases
            if p["token_prefix"] not in verification_tokens
        ]

        # ---- HIGH: feature unlock without any verification flow ----
        if unlocks and unverified_purchases:
            findings.append(self._unverified_finding(
                unlocks, unverified_purchases,
            ))

        # ---- MEDIUM: unacknowledged purchases after unlock ----
        unacked = [p for p in purchases if not p["acknowledged"]]
        if unlocks and unacked and not findings:
            findings.append(self._unacked_finding(unlocks, unacked))

        return findings

    def _unverified_finding(
        self,
        unlocks: list[dict[str, Any]],
        unverified: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=Severity.HIGH,
            confidence=0.85,
            evidence={
                "issue": (
                    "The application granted a premium feature unlock "
                    "after receiving a Purchase token, but no outbound "
                    "HTTP flow contained that token's prefix during "
                    "the session. The server-side verification step "
                    "of the Play Billing flow appears to be missing. "
                    "A Frida-modded queryPurchasesAsync that returns "
                    "a fabricated Purchase will unlock the feature."
                ),
                "unlocked_entitlements": [u.get("entitlement") for u in unlocks],
                "unverified_purchase_tokens": [
                    p["token_prefix"] for p in unverified
                ],
                "purchase_count": len(unverified),
                "unlock_count": len(unlocks),
                "vector": (
                    "Frida hooks on BillingClient.queryPurchasesAsync "
                    "and the app's PurchasesUpdatedListener observed a "
                    "Purchase delivery. mitmproxy flow inspection found "
                    "no outbound request body carrying the matching "
                    "purchase token prefix."
                ),
                "sources": ["frida", "mitmproxy"],
            },
            recommendation=(
                "Every Purchase must be sent to your backend with the "
                "raw token, signature, and orderId. The backend must "
                "call the Play Developer API "
                "purchases.products.get / subscriptions.get to verify "
                "the token before unlocking any entitlement. Cache the "
                "verdict server-side keyed by orderId. Never grant a "
                "feature solely on a client-side purchaseState read; "
                "never call acknowledgePurchase from the client without "
                "first writing the entitlement record server-side."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        )

    def _unacked_finding(
        self,
        unlocks: list[dict[str, Any]],
        unacked: list[dict[str, Any]],
    ) -> Finding:
        return self._make_finding(
            vuln_class="Unacknowledged IAP After Feature Unlock",
            severity=Severity.MEDIUM,
            confidence=0.75,
            evidence={
                "issue": (
                    "A feature unlock fired after a Purchase but the "
                    "Purchase was never acknowledged. Google Play "
                    "automatically refunds any purchase that is not "
                    "acknowledged within three days, after which the "
                    "user retains the unlocked feature for free."
                ),
                "unlocked_entitlements": [u.get("entitlement") for u in unlocks],
                "unacked_skus": [p.get("sku") for p in unacked],
                "vector": (
                    "Frida hook on BillingClient.acknowledgePurchase "
                    "and Purchase.isAcknowledged observed the unacked "
                    "state at unlock time."
                ),
                "sources": ["frida"],
            },
            recommendation=(
                "Call BillingClient.acknowledgePurchase (or "
                "consumeAsync for consumable products) from your "
                "backend immediately after the server-side "
                "verification succeeds. Do not perform "
                "acknowledgePurchase from the client — it lets a user "
                "who tampered with the client skip both verification "
                "and acknowledgement."
            ),
            owasp="M3: Insecure Communication",
            masvs="MSTG-AUTH-3",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        )
