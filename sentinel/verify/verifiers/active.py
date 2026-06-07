"""Active-replay verifiers (D_007 / D_009 / D_013).

These promote *candidate* findings to ``VERIFIED`` by issuing live
HTTP traffic against the application's backend. They are gated on
``VerifierContext.active_replay`` — without that opt-in they return
``UNSUPPORTED`` rather than touch a live system.

See :mod:`sentinel.verify.replayers` for the budget / allow-list /
timeout enforcement shared across all three.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.core.finding import Finding
from sentinel.verify.models import VerificationResult, VerifierContext
from sentinel.verify.replayers import (
    IdorReplayer,
    ParallelReplayer,
    ReplayBudget,
    ReplayClient,
    TokenRedactionReplayer,
)

logger = logging.getLogger(__name__)


# ---------- D_007 race-condition ----------


class RaceConditionVerifier:
    """Promote D_007 candidates to VERIFIED by parallel-firing."""

    AGENT_IDS = ("D_007",)

    PARALLELISM = 5

    async def verify(
        self,
        finding: Finding,
        ctx: VerifierContext,
    ) -> VerificationResult:
        if not ctx.active_replay:
            return VerificationResult.unsupported(
                method="race-parallel-fire",
                reason=(
                    "active replay disabled; rerun with "
                    "ScanContext.active_replay=True to allow live "
                    "race-condition replay"
                ),
            )
        evidence = finding.evidence or {}
        host = evidence.get("host")
        method = evidence.get("method")
        path = evidence.get("path")
        if not (host and method and path):
            return VerificationResult.inconclusive(
                method="race-parallel-fire",
                reason="finding evidence missing host/method/path",
            )
        url = f"https://{host}{path}"
        budget = ReplayBudget(max_total_requests=self.PARALLELISM * 2)
        try:
            async with ReplayClient({host}, budget=budget) as client:
                replayer = ParallelReplayer(client=client)
                result = await replayer.fire(
                    method, url, n=self.PARALLELISM,
                )
        except Exception as exc:  # noqa: BLE001
            return VerificationResult.inconclusive(
                method="race-parallel-fire",
                reason=f"replayer error: {exc}",
            )

        replay_evidence: dict[str, Any] = {
            "url": url, "method": method,
            "fired": result.fired,
            "succeeded": result.succeeded,
            "statuses": result.statuses,
        }
        if result.race_confirmed:
            return VerificationResult.verified(
                method="race-parallel-fire",
                evidence=replay_evidence,
                confidence=0.85,
                notes=(
                    f"{result.succeeded} of {result.fired} parallel "
                    "requests returned a success indicator — "
                    "endpoint commits the side-effect more than once."
                ),
            )
        if result.succeeded == 0:
            return VerificationResult.refuted(
                method="race-parallel-fire",
                evidence=replay_evidence,
                notes="no parallel request reached the success path",
            )
        return VerificationResult.inconclusive(
            method="race-parallel-fire",
            reason=(
                f"one of {result.fired} requests succeeded — server "
                "may be enforcing idempotency; replay did not "
                "trigger a TOCTOU window in this run"
            ),
        )


# ---------- D_009 IDOR ----------


class IdorVerifier:
    """Promote D_009 IDOR candidates by re-firing with a perturbed ID."""

    AGENT_IDS = ("D_009",)

    async def verify(
        self,
        finding: Finding,
        ctx: VerifierContext,
    ) -> VerificationResult:
        if not ctx.active_replay:
            return VerificationResult.unsupported(
                method="idor-perturb",
                reason="active replay disabled",
            )
        evidence = finding.evidence or {}
        host = evidence.get("host")
        method = evidence.get("method") or "GET"
        path = evidence.get("path")
        original_id = str(evidence.get("id_segment_observed") or "")
        if not (host and path and original_id):
            return VerificationResult.inconclusive(
                method="idor-perturb",
                reason="finding evidence missing host/path/id_segment",
            )
        perturbed_id = self._perturb(original_id)
        if perturbed_id == original_id:
            return VerificationResult.inconclusive(
                method="idor-perturb",
                reason="could not perturb owner id",
            )
        url = f"https://{host}{path}"
        budget = ReplayBudget(max_total_requests=4)
        # We need the original session token to be set by the caller
        # before this verifier runs; mitmproxy capture flow headers
        # carry it.
        headers = self._auth_headers_from_finding(finding, ctx)
        try:
            async with ReplayClient({host}, budget=budget) as client:
                replayer = IdorReplayer(client=client)
                result = await replayer.perturb_path(
                    method, url,
                    original_id=original_id,
                    perturbed_id=perturbed_id,
                    headers=headers,
                )
        except Exception as exc:  # noqa: BLE001
            return VerificationResult.inconclusive(
                method="idor-perturb",
                reason=f"replayer error: {exc}",
            )
        replay_evidence: dict[str, Any] = {
            "url": url,
            "original_id": original_id,
            "perturbed_id": perturbed_id,
            "original_status": result.original.status,
            "perturbed_status": result.perturbed.status,
        }
        if result.idor_confirmed:
            return VerificationResult.verified(
                method="idor-perturb",
                evidence=replay_evidence,
                confidence=0.85,
                notes=(
                    "Perturbed-ID request returned 2xx with a "
                    "different body than the original — owner check "
                    "is not enforced server-side."
                ),
            )
        if (result.original.succeeded
                and not result.perturbed.succeeded):
            return VerificationResult.refuted(
                method="idor-perturb",
                evidence=replay_evidence,
                notes=(
                    "Perturbed-ID request returned a non-2xx — "
                    "owner check is enforced."
                ),
            )
        return VerificationResult.inconclusive(
            method="idor-perturb",
            reason=(
                f"original={result.original.status}, "
                f"perturbed={result.perturbed.status} — could not "
                "distinguish enforcement from request error"
            ),
        )

    @staticmethod
    def _perturb(original: str) -> str:
        """Produce an adjacent ID we don't own.

        Integer IDs: ±1. UUID: flip the last hex character. Opaque:
        increment the last alphanumeric character.
        """
        if original.isdigit():
            try:
                v = int(original)
                return str(v + 1)
            except ValueError:
                return original
        if "-" in original and len(original) == 36:
            # UUID — flip last char between 0..f cycle.
            last = original[-1]
            replacement = {"0": "1", "f": "e"}.get(last)
            if replacement is None:
                replacement = "0" if last != "0" else "1"
            return original[:-1] + replacement
        if original:
            last = original[-1]
            if last.isalnum():
                shifted = chr(ord(last) + 1) if last < "z" else "a"
                return original[:-1] + shifted
        return original

    @staticmethod
    def _auth_headers_from_finding(
        finding: Finding, ctx: VerifierContext,
    ) -> dict[str, str]:
        """Find the original request's auth headers from the mitm capture."""
        capture = ctx.mitm_capture
        if capture is None:
            return {}
        flows = getattr(capture, "flows", None) or []
        target_host = (finding.evidence or {}).get("host")
        for flow in flows:
            if getattr(flow, "host", "") != target_host:
                continue
            req_headers = getattr(flow, "request_headers", {}) or {}
            picked = {}
            for k, v in req_headers.items():
                if k.lower() in ("authorization", "cookie", "x-api-key"):
                    picked[k] = str(v)
            if picked:
                return picked
        return {}


# ---------- D_013 third-party PII / token leak ----------


class ThirdPartyTokenRedactionVerifier:
    """Promote D_013 token-leak candidates."""

    AGENT_IDS = ("D_013",)

    async def verify(
        self,
        finding: Finding,
        ctx: VerifierContext,
    ) -> VerificationResult:
        if not ctx.active_replay:
            return VerificationResult.unsupported(
                method="thirdparty-token-redact",
                reason="active replay disabled",
            )
        if "Bearer Token" not in finding.vuln_class:
            return VerificationResult.unsupported(
                method="thirdparty-token-redact",
                reason="only Bearer-token leak findings are replayed",
            )
        evidence = finding.evidence or {}
        samples = evidence.get("samples") or []
        if not samples:
            return VerificationResult.inconclusive(
                method="thirdparty-token-redact",
                reason="no sample flow to replay",
            )
        sample = samples[0]
        host = sample.get("host")
        path = sample.get("path")
        method = sample.get("method") or "POST"
        if not (host and path):
            return VerificationResult.inconclusive(
                method="thirdparty-token-redact",
                reason="sample missing host/path",
            )
        original_headers, original_body = self._lookup_flow(
            ctx, host, path, method,
        )
        if "authorization" not in {k.lower() for k in original_headers}:
            return VerificationResult.inconclusive(
                method="thirdparty-token-redact",
                reason="no Authorization header on the original flow",
            )
        url = f"https://{host}{path}"
        budget = ReplayBudget(max_total_requests=4)
        try:
            async with ReplayClient({host}, budget=budget) as client:
                replayer = TokenRedactionReplayer(client=client)
                result = await replayer.strip_token(
                    method, url,
                    headers=original_headers,
                    content=original_body or None,
                )
        except Exception as exc:  # noqa: BLE001
            return VerificationResult.inconclusive(
                method="thirdparty-token-redact",
                reason=f"replayer error: {exc}",
            )
        replay_evidence = {
            "url": url,
            "with_token_status": result.with_token.status,
            "no_token_status": result.no_token.status,
        }
        if result.token_unnecessary:
            return VerificationResult.verified(
                method="thirdparty-token-redact",
                evidence=replay_evidence,
                confidence=0.90,
                notes=(
                    "Third-party endpoint accepted the request with "
                    "the Authorization header removed — the bearer "
                    "token was a pure leak from the app's own session "
                    "into telemetry."
                ),
            )
        return VerificationResult.refuted(
            method="thirdparty-token-redact",
            evidence=replay_evidence,
            notes=(
                "Stripping Authorization changed the response — the "
                "third party does authenticate against the token, so "
                "the leak is real but the token's also functional. "
                "Treat the finding as a HIGH irrespective."
            ),
        )

    @staticmethod
    def _lookup_flow(
        ctx: VerifierContext, host: str, path: str, method: str,
    ) -> tuple[dict[str, str], str]:
        capture = ctx.mitm_capture
        if capture is None:
            return {}, ""
        flows = getattr(capture, "flows", None) or []
        for flow in flows:
            if (getattr(flow, "host", "") == host
                    and getattr(flow, "path", "") == path
                    and getattr(flow, "method", "") == method):
                headers = dict(getattr(flow, "request_headers", {}) or {})
                body = getattr(flow, "request_body", "") or ""
                return {str(k): str(v) for k, v in headers.items()}, body
        return {}, ""
