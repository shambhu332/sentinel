"""Tests for the replayer primitives (no real HTTP)."""
from __future__ import annotations

import pytest

from sentinel.verify.replayers import (
    IdorReplayResult,
    ParallelReplayResult,
    ReplayResponse,
    TokenRedactionResult,
)


def test_replay_response_success_predicate():
    assert ReplayResponse(200, "", 0.0).succeeded is True
    assert ReplayResponse(404, "", 0.0).succeeded is False
    assert ReplayResponse(500, "", 0.0).succeeded is False
    assert ReplayResponse(0, "", 0.0, exception="boom").succeeded is False


def test_parallel_race_confirmed_at_two_successes():
    r = ParallelReplayResult(
        method="POST", url="https://x", fired=5,
        succeeded=2, statuses=[200, 200, 409, 409, 409],
    )
    assert r.race_confirmed is True


def test_parallel_race_not_confirmed_at_one():
    r = ParallelReplayResult(
        method="POST", url="https://x", fired=5,
        succeeded=1, statuses=[200, 409, 409, 409, 409],
    )
    assert r.race_confirmed is False


def test_idor_confirmed_on_different_body():
    r = IdorReplayResult(
        method="GET", url="https://x/users/1",
        original_id="1", perturbed_id="2",
        original=ReplayResponse(200, '{"email":"a@x"}', 0.1),
        perturbed=ReplayResponse(200, '{"email":"b@y"}', 0.1),
    )
    assert r.idor_confirmed is True


def test_idor_not_confirmed_on_403():
    r = IdorReplayResult(
        method="GET", url="https://x/users/1",
        original_id="1", perturbed_id="2",
        original=ReplayResponse(200, '{"x":1}', 0.1),
        perturbed=ReplayResponse(403, "forbidden", 0.1),
    )
    assert r.idor_confirmed is False


def test_idor_not_confirmed_on_identical_body():
    r = IdorReplayResult(
        method="GET", url="https://x/users/1",
        original_id="1", perturbed_id="2",
        original=ReplayResponse(200, '{"x":1}', 0.1),
        perturbed=ReplayResponse(200, '{"x":1}', 0.1),
    )
    assert r.idor_confirmed is False


def test_token_redaction_verified_when_both_succeed():
    r = TokenRedactionResult(
        method="POST", url="https://x",
        with_token=ReplayResponse(200, "{}", 0.1),
        no_token=ReplayResponse(200, "{}", 0.1),
    )
    assert r.token_unnecessary is True


def test_token_redaction_not_verified_when_no_token_fails():
    r = TokenRedactionResult(
        method="POST", url="https://x",
        with_token=ReplayResponse(200, "{}", 0.1),
        no_token=ReplayResponse(401, "unauthorized", 0.1),
    )
    assert r.token_unnecessary is False
