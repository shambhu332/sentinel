"""Unit tests for the active-replay verifiers (D_007 / D_009 / D_013).

We monkey-patch the verifier-local ReplayClient to avoid touching the
network. The replayer's behaviour is asserted directly by
test_replayers.py; here we exercise verifier logic only.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.finding import BountyScope, Finding, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.tools.mitmproxy_runner import CapturedFlow, MitmproxyCapture
from sentinel.verify.models import VerificationOutcome, VerifierContext
from sentinel.verify.replayers import (
    IdorReplayResult,
    ParallelReplayResult,
    ReplayResponse,
    TokenRedactionResult,
)
from sentinel.verify.verifiers.active import (
    IdorVerifier,
    RaceConditionVerifier,
    ThirdPartyTokenRedactionVerifier,
)

# ---------- fixtures ----------


@pytest.fixture
def scan(tmp_path):
    apk = tmp_path / "dummy.apk"
    apk.write_bytes(b"")
    return ScanContext(
        session_id=generate_session_id(),
        apk_path=apk, workspace=tmp_path, scope=BountyScope(),
    )


@pytest.fixture
def ctx_no_replay(scan):
    scan.active_replay = False
    return VerifierContext(scan=scan)


@pytest.fixture
def ctx_with_replay(scan):
    scan.active_replay = True
    return VerifierContext(scan=scan)


def _finding(agent_id: str, **evidence) -> Finding:
    return Finding(
        session_id="test1234",
        agent_id=agent_id,
        vuln_class=evidence.pop("vuln_class", "Test vuln class"),
        severity=Severity.HIGH,
        confidence=0.7,
        evidence=evidence,
        recommendation="test recommendation text",
    )


# ---------- helpers to fake replayers ----------


@asynccontextmanager
async def _noop_cm():
    yield None


class _FakeReplayClient:
    def __init__(self, *args, **kwargs):
        self._issued = 0
    async def __aenter__(self):
        return self
    async def __aexit__(self, *exc_info):
        return False
    @property
    def remaining(self) -> int:
        return 100


# ---------- D_007 race ----------


@pytest.mark.asyncio
async def test_race_unsupported_without_active_replay(ctx_no_replay):
    f = _finding("D_007", host="api.x.com", method="POST", path="/redeem")
    r = await RaceConditionVerifier().verify(f, ctx_no_replay)
    assert r.outcome is VerificationOutcome.UNSUPPORTED


@pytest.mark.asyncio
async def test_race_inconclusive_when_evidence_missing(ctx_with_replay):
    f = _finding("D_007")
    r = await RaceConditionVerifier().verify(f, ctx_with_replay)
    assert r.outcome is VerificationOutcome.INCONCLUSIVE


@pytest.mark.asyncio
async def test_race_verified_when_two_parallel_succeed(monkeypatch, ctx_with_replay):
    f = _finding("D_007", host="api.x.com", method="POST", path="/redeem")

    async def fake_fire(self, method, url, *, n, headers=None, content=None):
        return ParallelReplayResult(
            method=method, url=url, fired=n, succeeded=3,
            statuses=[200, 200, 200, 200, 200],
        )

    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ReplayClient",
        _FakeReplayClient,
    )
    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ParallelReplayer.fire",
        fake_fire,
    )
    r = await RaceConditionVerifier().verify(f, ctx_with_replay)
    assert r.outcome is VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_race_refuted_when_zero_succeed(monkeypatch, ctx_with_replay):
    f = _finding("D_007", host="api.x.com", method="POST", path="/redeem")

    async def fake_fire(self, method, url, *, n, headers=None, content=None):
        return ParallelReplayResult(
            method=method, url=url, fired=n, succeeded=0,
            statuses=[409, 409, 409, 409, 409],
        )

    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ReplayClient",
        _FakeReplayClient,
    )
    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ParallelReplayer.fire",
        fake_fire,
    )
    r = await RaceConditionVerifier().verify(f, ctx_with_replay)
    assert r.outcome is VerificationOutcome.REFUTED


# ---------- D_009 IDOR ----------


@pytest.mark.asyncio
async def test_idor_unsupported_without_active(ctx_no_replay):
    f = _finding("D_009", host="api.x.com", method="GET",
                 path="/api/v1/users/123", id_segment_observed="123")
    r = await IdorVerifier().verify(f, ctx_no_replay)
    assert r.outcome is VerificationOutcome.UNSUPPORTED


@pytest.mark.asyncio
async def test_idor_verified_when_perturbed_succeeds(monkeypatch, ctx_with_replay):
    f = _finding(
        "D_009",
        host="api.x.com", method="GET",
        path="/api/v1/users/123",
        id_segment_observed="123",
    )

    async def fake_perturb(self, method, url, *, original_id,
                            perturbed_id, headers=None, content=None):
        return IdorReplayResult(
            method=method, url=url,
            original_id=original_id, perturbed_id=perturbed_id,
            original=ReplayResponse(200, '{"email":"a@x.com"}', 0.1),
            perturbed=ReplayResponse(200, '{"email":"b@y.com"}', 0.1),
        )

    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ReplayClient",
        _FakeReplayClient,
    )
    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.IdorReplayer.perturb_path",
        fake_perturb,
    )
    r = await IdorVerifier().verify(f, ctx_with_replay)
    assert r.outcome is VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_idor_refuted_when_perturbed_403(monkeypatch, ctx_with_replay):
    f = _finding(
        "D_009",
        host="api.x.com", method="GET",
        path="/api/v1/users/123",
        id_segment_observed="123",
    )

    async def fake_perturb(self, method, url, *, original_id,
                            perturbed_id, headers=None, content=None):
        return IdorReplayResult(
            method=method, url=url,
            original_id=original_id, perturbed_id=perturbed_id,
            original=ReplayResponse(200, '{"ok":true}', 0.1),
            perturbed=ReplayResponse(403, "forbidden", 0.1),
        )

    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ReplayClient",
        _FakeReplayClient,
    )
    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.IdorReplayer.perturb_path",
        fake_perturb,
    )
    r = await IdorVerifier().verify(f, ctx_with_replay)
    assert r.outcome is VerificationOutcome.REFUTED


def test_idor_perturb_integer():
    assert IdorVerifier._perturb("123") == "124"


def test_idor_perturb_uuid_flips_last():
    u = "550e8400-e29b-41d4-a716-446655440000"
    assert IdorVerifier._perturb(u) != u
    assert IdorVerifier._perturb(u).endswith("1")


def test_idor_perturb_opaque_increments():
    assert IdorVerifier._perturb("abc") == "abd"


# ---------- D_013 third-party token ----------


@pytest.mark.asyncio
async def test_third_party_unsupported_without_active(ctx_no_replay):
    f = _finding(
        "D_013",
        vuln_class="Bearer Token Leaked to Third-Party Endpoint",
        samples=[{"host": "api.amplitude.com", "method": "POST", "path": "/2/track"}],
    )
    r = await ThirdPartyTokenRedactionVerifier().verify(f, ctx_no_replay)
    assert r.outcome is VerificationOutcome.UNSUPPORTED


@pytest.mark.asyncio
async def test_third_party_skips_non_bearer_finding(ctx_with_replay):
    f = _finding(
        "D_013",
        vuln_class="PII Sent to Third-Party Endpoint",
        samples=[{"host": "api.amplitude.com", "method": "POST",
                  "path": "/2/track"}],
    )
    r = await ThirdPartyTokenRedactionVerifier().verify(f, ctx_with_replay)
    assert r.outcome is VerificationOutcome.UNSUPPORTED


@pytest.mark.asyncio
async def test_third_party_verified_when_token_unnecessary(monkeypatch, ctx_with_replay, scan):
    # Plant the original flow with an Authorization header so the
    # verifier can find it.
    scan.sources["mitmproxy"] = MitmproxyCapture(
        flows=[CapturedFlow(
            method="POST",
            url="https://api.amplitude.com/2/track",
            scheme="https", host="api.amplitude.com", path="/2/track",
            request_headers={"Authorization": "Bearer abc"},
            request_body='{"event":"x"}',
            response_status=200, response_body="{}",
        )],
        capture_file=Path("/tmp/dummy.jsonl"),
        duration_seconds=1.0, flow_count=1,
    )
    f = _finding(
        "D_013",
        vuln_class="Bearer Token Leaked to Third-Party Endpoint",
        samples=[{"host": "api.amplitude.com", "method": "POST",
                  "path": "/2/track"}],
    )

    async def fake_strip(self, method, url, *, headers, content=None):
        return TokenRedactionResult(
            method=method, url=url,
            with_token=ReplayResponse(200, "{}", 0.1),
            no_token=ReplayResponse(200, "{}", 0.1),
        )

    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ReplayClient",
        _FakeReplayClient,
    )
    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.TokenRedactionReplayer.strip_token",
        fake_strip,
    )
    ctx = VerifierContext(scan=scan)
    r = await ThirdPartyTokenRedactionVerifier().verify(f, ctx)
    assert r.outcome is VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_third_party_refuted_when_token_required(monkeypatch, ctx_with_replay, scan):
    scan.sources["mitmproxy"] = MitmproxyCapture(
        flows=[CapturedFlow(
            method="POST",
            url="https://api.amplitude.com/2/track",
            scheme="https", host="api.amplitude.com", path="/2/track",
            request_headers={"Authorization": "Bearer abc"},
            request_body='{"event":"x"}',
            response_status=200, response_body="{}",
        )],
        capture_file=Path("/tmp/dummy.jsonl"),
        duration_seconds=1.0, flow_count=1,
    )
    f = _finding(
        "D_013",
        vuln_class="Bearer Token Leaked to Third-Party Endpoint",
        samples=[{"host": "api.amplitude.com", "method": "POST",
                  "path": "/2/track"}],
    )

    async def fake_strip(self, method, url, *, headers, content=None):
        return TokenRedactionResult(
            method=method, url=url,
            with_token=ReplayResponse(200, "{}", 0.1),
            no_token=ReplayResponse(401, "unauthorized", 0.1),
        )

    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.ReplayClient",
        _FakeReplayClient,
    )
    monkeypatch.setattr(
        "sentinel.verify.verifiers.active.TokenRedactionReplayer.strip_token",
        fake_strip,
    )
    ctx = VerifierContext(scan=scan)
    r = await ThirdPartyTokenRedactionVerifier().verify(f, ctx)
    assert r.outcome is VerificationOutcome.REFUTED
