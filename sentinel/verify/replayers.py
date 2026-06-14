"""Active HTTP replayers for verifier classes.

These replay primitives let a verifier promote a "candidate" finding
to ``VERIFIED`` by sending live traffic against the application's
backend. They are **opt-in** — ``ScanContext.active_replay`` must be
True before any of them dial out.

Three categories:

* :class:`ParallelReplayer` — fires N copies of a single request in
  parallel. Used by the D_007 race-condition verifier to test
  whether the endpoint commits the same side-effect more than once.

* :class:`IdorReplayer` — re-fires a request with a perturbed owner
  identifier in the path. Used by the D_009 IDOR verifier to test
  whether the bearer-token check binds the resource to the caller.

* :class:`TokenRedactionReplayer` — re-fires a third-party telemetry
  request with the ``Authorization`` header stripped. Used by the
  D_013 verifier to confirm the third-party endpoint does NOT
  require the token (i.e., the token leaked from the app's own
  session into the analytics SDK).

All replayers share a single :class:`ReplayClient` that enforces:

* a hard per-session request budget (default 50) so a runaway
  verifier cannot DoS the target,
* a hard per-request timeout (default 10s),
* a strict host allow-list derived from the original capture,
* never follows redirects (we want to observe the first response).

The replayers never persist responses to disk; they return only the
short verdict the verifier needs.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass
from typing import Any

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a real dep
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class ReplayBudget:
    """Hard caps the replayer cannot exceed in one verification run."""

    max_total_requests: int = 50
    per_request_timeout_s: float = 10.0
    parallel_window_s: float = 5.0


@dataclass
class ReplayResponse:
    """Minimal view of a replayed response."""

    status: int
    body_prefix: str            # first 512 chars of the body
    elapsed_s: float
    exception: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.exception is None and 200 <= self.status < 300


class ReplayClient:
    """Single-use HTTP client with a budget and host allow-list."""

    def __init__(
        self,
        allowed_hosts: set[str],
        budget: ReplayBudget | None = None,
    ) -> None:
        self._allowed_hosts = {h.lower() for h in allowed_hosts if h}
        self._budget = budget or ReplayBudget()
        self._issued = 0
        self._client: Any | None = None

    async def __aenter__(self) -> "ReplayClient":
        if httpx is None:
            raise RuntimeError(
                "httpx is required for active replay verifiers",
            )
        self._client = httpx.AsyncClient(
            timeout=self._budget.per_request_timeout_s,
            follow_redirects=False,
        )
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.aclose()
        self._client = None

    @property
    def issued(self) -> int:
        return self._issued

    @property
    def remaining(self) -> int:
        return max(0, self._budget.max_total_requests - self._issued)

    def _check_allowed(self, url: str) -> bool:
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
        except (ValueError, AttributeError):
            return False
        return host in self._allowed_hosts

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | str | None = None,
    ) -> ReplayResponse:
        if self._client is None:
            raise RuntimeError("ReplayClient used outside its context manager")
        if not self._check_allowed(url):
            return ReplayResponse(
                status=0, body_prefix="",
                elapsed_s=0.0,
                exception="host not in allow-list",
            )
        if self.remaining <= 0:
            return ReplayResponse(
                status=0, body_prefix="",
                elapsed_s=0.0,
                exception="replay budget exhausted",
            )
        self._issued += 1
        loop = asyncio.get_event_loop()
        t0 = loop.time()
        try:
            resp = await self._client.request(
                method, url,
                headers=headers or {},
                content=content,
            )
            body = resp.text[:512] if hasattr(resp, "text") else ""
            return ReplayResponse(
                status=resp.status_code,
                body_prefix=body,
                elapsed_s=loop.time() - t0,
            )
        except Exception as exc:  # noqa: BLE001
            return ReplayResponse(
                status=0, body_prefix="",
                elapsed_s=loop.time() - t0,
                exception=f"{type(exc).__name__}: {exc}",
            )


# ---------- specialised replayers ----------


_SUCCESS_TOKENS = re.compile(
    r"\b(?:success|ok|true|accepted|created|approved)\b",
    re.IGNORECASE,
)


@dataclass
class ParallelReplayer:
    """D_007 — parallel-fire a single state-affecting request."""

    client: ReplayClient

    async def fire(
        self,
        method: str,
        url: str,
        *,
        n: int = 5,
        headers: dict[str, str] | None = None,
        content: bytes | str | None = None,
    ) -> "ParallelReplayResult":
        n = max(1, min(n, self.client.remaining))
        tasks = [
            asyncio.create_task(self.client.request(
                method, url, headers=headers, content=content,
            ))
            for _ in range(n)
        ]
        responses = await asyncio.gather(*tasks)
        succeeded = [r for r in responses if r.succeeded
                     and _looks_success(r)]
        return ParallelReplayResult(
            method=method, url=url,
            fired=n, succeeded=len(succeeded),
            statuses=[r.status for r in responses],
        )


@dataclass
class ParallelReplayResult:
    method: str
    url: str
    fired: int
    succeeded: int
    statuses: list[int]

    @property
    def race_confirmed(self) -> bool:
        """≥ 2 simultaneous successes = TOCTOU window is open."""
        return self.succeeded >= 2


def _looks_success(r: ReplayResponse) -> bool:
    if not r.succeeded:
        return False
    if r.status in (201, 202, 204):
        return True
    return bool(_SUCCESS_TOKENS.search(r.body_prefix))


@dataclass
class IdorReplayer:
    """D_009 — re-fire a request with a perturbed owner ID."""

    client: ReplayClient

    async def perturb_path(
        self,
        method: str,
        url: str,
        *,
        original_id: str,
        perturbed_id: str,
        headers: dict[str, str] | None = None,
        content: bytes | str | None = None,
    ) -> "IdorReplayResult":
        if original_id not in url:
            return IdorReplayResult(
                method=method, url=url,
                original_id=original_id, perturbed_id=perturbed_id,
                original=ReplayResponse(0, "", 0.0, "id not in url"),
                perturbed=ReplayResponse(0, "", 0.0, "id not in url"),
            )
        perturbed_url = url.replace(original_id, perturbed_id, 1)
        original_resp = await self.client.request(
            method, url, headers=headers, content=content,
        )
        perturbed_resp = await self.client.request(
            method, perturbed_url, headers=headers, content=content,
        )
        return IdorReplayResult(
            method=method, url=url,
            original_id=original_id, perturbed_id=perturbed_id,
            original=original_resp, perturbed=perturbed_resp,
        )


@dataclass
class IdorReplayResult:
    method: str
    url: str
    original_id: str
    perturbed_id: str
    original: ReplayResponse
    perturbed: ReplayResponse

    @property
    def idor_confirmed(self) -> bool:
        """Both calls returned 2xx and the bodies were not byte-identical.

        The exact-equality check filters cached / canonicalised
        responses; a real IDOR shows different user PII per ID.
        """
        if not (self.original.succeeded and self.perturbed.succeeded):
            return False
        return self.original.body_prefix != self.perturbed.body_prefix


@dataclass
class TokenRedactionReplayer:
    """D_013 — re-fire a third-party request with Authorization stripped."""

    client: ReplayClient

    async def strip_token(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes | str | None = None,
    ) -> "TokenRedactionResult":
        stripped = {
            k: v for k, v in headers.items()
            if k.lower() != "authorization"
        }
        with_token = await self.client.request(
            method, url, headers=headers, content=content,
        )
        no_token = await self.client.request(
            method, url, headers=stripped, content=content,
        )
        return TokenRedactionResult(
            method=method, url=url,
            with_token=with_token, no_token=no_token,
        )


@dataclass
class TokenRedactionResult:
    method: str
    url: str
    with_token: ReplayResponse
    no_token: ReplayResponse

    @property
    def token_unnecessary(self) -> bool:
        """The third-party accepted the request without the bearer token.

        If the third-party endpoint returns the same success without
        Authorization, the token in the original request was a *leak*
        — the third-party never needed it.
        """
        if self.with_token.exception or self.no_token.exception:
            return False
        # Both succeeded → third party doesn't actually authenticate.
        return self.no_token.succeeded and self.with_token.succeeded
