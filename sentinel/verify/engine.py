"""Orchestrator for the verify engine.

The engine owns a registry of verifiers keyed by ``agent_id``. Each
verifier implements one method — ``verify(finding, ctx)`` — and
returns a ``VerificationResult``. The engine calls them one at a
time, persists the result back into the finding's evidence under
``_verify``, and never raises into the caller.
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable, Iterable, Protocol, runtime_checkable

from sentinel.core.finding import Finding
from sentinel.core.scan_context import ScanContext
from sentinel.verify.models import (
    VerificationOutcome,
    VerificationResult,
    VerifierContext,
)

logger = logging.getLogger(__name__)


@runtime_checkable
class Verifier(Protocol):
    """Contract every verifier must satisfy."""

    AGENT_IDS: tuple[str, ...]

    async def verify(
        self,
        finding: Finding,
        ctx: VerifierContext,
    ) -> VerificationResult:
        ...


VerifierFactory = Callable[[], Verifier]


class VerifyEngine:
    """Route findings to per-class verifiers."""

    def __init__(self) -> None:
        self._registry: dict[str, Verifier] = {}

    # ---------- registry ----------

    def register(self, verifier: Verifier) -> None:
        """Bind ``verifier`` to every agent_id it claims to handle."""
        for aid in verifier.AGENT_IDS:
            if aid in self._registry:
                logger.warning(
                    "[verify] %s already bound to %s — overriding with %s",
                    aid,
                    type(self._registry[aid]).__name__,
                    type(verifier).__name__,
                )
            self._registry[aid] = verifier

    def register_default_verifiers(self) -> None:
        """Wire in every shipped verifier.

        Kept as a separate call so unit tests can run with an empty
        engine and add only what they need.
        """
        # Local imports keep the module's top-level cheap.
        from sentinel.verify.verifiers.frida import (
            RuntimeCryptoVerifier,
            TlsPinningBypassVerifier,
        )
        from sentinel.verify.verifiers.manifest import (
            BackupRulesVerifier,
            DebuggableManifestVerifier,
            ExcessivePermissionsVerifier,
            InsecureFileProviderVerifier,
        )
        from sentinel.verify.verifiers.mitm import CleartextTrafficVerifier

        for cls in (
            DebuggableManifestVerifier,
            ExcessivePermissionsVerifier,
            InsecureFileProviderVerifier,
            BackupRulesVerifier,
            CleartextTrafficVerifier,
            RuntimeCryptoVerifier,
            TlsPinningBypassVerifier,
        ):
            self.register(cls())

    @property
    def supported_agents(self) -> tuple[str, ...]:
        return tuple(sorted(self._registry.keys()))

    # ---------- orchestration ----------

    async def verify(
        self,
        finding: Finding,
        scan: ScanContext,
    ) -> VerificationResult:
        verifier = self._registry.get(finding.agent_id)
        if verifier is None:
            return VerificationResult.unsupported(
                method="no-verifier-registered",
                reason=(
                    f"no verifier bound for agent_id {finding.agent_id}; "
                    f"engine supports {len(self._registry)} agent class(es)"
                ),
            )
        try:
            return await verifier.verify(finding, VerifierContext(scan=scan))
        except Exception as exc:  # noqa: BLE001 - never block the pipeline
            logger.warning(
                "[verify] %s verifier raised: %s",
                finding.agent_id, exc,
            )
            return VerificationResult.unsupported(
                method="verifier-error",
                reason=f"{type(exc).__name__}: {exc}",
            )

    async def verify_all(
        self,
        findings: Iterable[Finding],
        scan: ScanContext,
    ) -> list[tuple[Finding, VerificationResult]]:
        """Verify every finding in turn; persist results into evidence."""
        out: list[tuple[Finding, VerificationResult]] = []
        for f in findings:
            result = await self.verify(f, scan)
            self._persist(f, result)
            out.append((f, result))
        return out

    # ---------- evidence persistence ----------

    @staticmethod
    def _persist(finding: Finding, result: VerificationResult) -> None:
        if finding.evidence is None:
            finding.evidence = {}
        finding.evidence["_verify"] = {
            "outcome": result.outcome.value,
            "method": result.method,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "notes": result.notes,
        }
