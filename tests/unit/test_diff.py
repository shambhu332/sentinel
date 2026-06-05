"""Unit tests for sentinel diff — fingerprinting, deltas, baseline, renderers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.baseline_store import BaselineStore
from sentinel.core.diff import (
    DiffSummary,
    compute_delta,
    finding_fingerprint,
    gate_exit_code,
    parse_severity_list,
    render_json,
    render_markdown,
)
from sentinel.core.finding import Finding, Severity

# ---------- Helpers ----------

def _f(
    *,
    agent_id: str = "A_004",
    vuln_class: str = "HARDCODED_SECRET",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    file: str = "com/example/Foo.java",
    code: str = 'String key = "AKIA...";',
    session_id: str = "sess_abc12345",
    extra_evidence: dict[str, Any] | None = None,
) -> Finding:
    """Build a Finding with sensible defaults; tests override what they vary."""
    ev: dict[str, Any] = {"source_file": file, "code": code}
    if extra_evidence:
        ev.update(extra_evidence)
    return Finding(
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=confidence,
        evidence=ev,
        recommendation="Rotate the secret and move it to the Android Keystore.",
        session_id=session_id,
    )


# ---------- Fingerprint stability ----------

def test_fingerprint_stable_across_sessions_and_workspaces() -> None:
    """Same logical finding emitted by two scans must hash identically.

    The fingerprint normaliser strips workspace prefixes, leading line
    numbers, whitespace differences, and trailing comments — so the
    'same bug' is preserved across versions even when the decompiler
    formats it slightly differently or writes to a different per-scan
    workspace directory.
    """
    a = _f(
        file="/abs/workspace/sessA/decompiled/sources/com/foo/Bar.java",
        code='  127:  String key = "AKIA123";',
        session_id="sess_aaaaaaaa",
    )
    b = _f(
        file="/different/workspace/sessB/decompiled/sources/com/foo/Bar.java",
        code='String key = "AKIA123"; // TODO rotate',
        session_id="sess_bbbbbbbb",
    )
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_changes_with_vuln_class() -> None:
    """Different vuln_class on otherwise identical evidence must hash differently."""
    a = _f(vuln_class="HARDCODED_SECRET")
    b = _f(vuln_class="WEAK_CRYPTO")
    assert finding_fingerprint(a) != finding_fingerprint(b)


def test_fingerprint_changes_with_agent_id() -> None:
    a = _f(agent_id="A_004")
    b = _f(agent_id="C_007")
    assert finding_fingerprint(a) != finding_fingerprint(b)


def test_fingerprint_changes_with_file_path() -> None:
    a = _f(file="com/foo/Bar.java")
    b = _f(file="com/foo/Baz.java")
    assert finding_fingerprint(a) != finding_fingerprint(b)


def test_fingerprint_handles_missing_evidence_fields() -> None:
    """A finding with no file/snippet still produces a deterministic hash —
    no exceptions."""
    f = Finding(
        agent_id="META_001", vuln_class="OBFUSCATION_DETECTED",
        severity=Severity.INFO, confidence=0.9,
        evidence={"package": "com.foo"},
        recommendation="Note for triage.",
        session_id="sess_aaaaaaaa",
    )
    fp = finding_fingerprint(f)
    assert isinstance(fp, str) and len(fp) == 16


def test_fingerprint_reads_taint_trace_evidence() -> None:
    """TAINT_001 finds store sink details under evidence.trace[-1].file/code.
    The fingerprint helper falls back to this when the top-level
    source_file/code keys are absent."""
    f = Finding(
        agent_id="TAINT_001", vuln_class="SQL_INJECTION",
        severity=Severity.HIGH, confidence=0.9,
        evidence={
            "sink_file": "/abs/workspace/sess_aaaa1111/decompiled/sources/com/foo/Bar.java",
            "sink_line": 42,
            "trace": [
                {"file": "com/foo/Bar.java", "line": 10, "code": "src", "kind": "source", "label": "x"},
                {"file": "com/foo/Bar.java", "line": 42, "code": "db.rawQuery(q)", "kind": "sink", "label": "rawQuery"},
            ],
        },
        recommendation="Use parameterised queries.",
        session_id="sess_aaaaaaaa",
    )
    fp1 = finding_fingerprint(f)
    f.evidence["sink_file"] = "/different/host/workspace/sess_zzzz9999/decompiled/sources/com/foo/Bar.java"
    fp2 = finding_fingerprint(f)
    assert fp1 == fp2


# ---------- Delta computation ----------

def test_compute_delta_basic_three_sets() -> None:
    """Two findings carry over, one disappears, two appear."""
    shared_a = _f(file="com/foo/A.java")
    shared_b = _f(file="com/foo/B.java")
    removed  = _f(file="com/foo/Removed.java")
    added_1  = _f(file="com/foo/Added1.java")
    added_2  = _f(agent_id="C_007", vuln_class="WEAK_CRYPTO",
                  file="com/foo/Added2.java",
                  code='MessageDigest.getInstance("MD5");')

    base = [shared_a, shared_b, removed]
    head = [shared_a, shared_b, added_1, added_2]

    d = compute_delta(base, head)
    assert len(d.unchanged) == 2
    assert len(d.fixed)     == 1
    assert len(d.new)       == 2
    assert finding_fingerprint(d.fixed[0]) == finding_fingerprint(removed)


def test_compute_delta_empty_base_everything_new() -> None:
    """First scan against an empty base — every finding is 'new'."""
    head = [_f(file=f"com/foo/F{i}.java") for i in range(3)]
    d = compute_delta([], head)
    assert len(d.new) == 3
    assert d.fixed == []
    assert d.unchanged == []


def test_compute_delta_empty_head_everything_fixed() -> None:
    """If head has zero findings, base findings count as 'fixed'."""
    base = [_f(file=f"com/foo/F{i}.java") for i in range(2)]
    d = compute_delta(base, [])
    assert d.new == []
    assert len(d.fixed) == 2


def test_compute_delta_preserves_emission_order() -> None:
    """New / unchanged in head order; fixed in base order."""
    base = [
        _f(file=f"com/foo/B{i}.java")
        for i in range(3)
    ]
    head = [
        _f(file="com/foo/B1.java"),  # shared (was index 1 in base)
        _f(file="com/foo/B2.java"),  # shared
        _f(file="com/foo/new_a.java"),
        _f(file="com/foo/new_b.java"),
    ]
    d = compute_delta(base, head)
    # head order — shared before new, in head order.
    assert d.unchanged[0].evidence["source_file"] == "com/foo/B1.java"
    assert d.new[0].evidence["source_file"] == "com/foo/new_a.java"
    assert d.new[1].evidence["source_file"] == "com/foo/new_b.java"
    # fixed in base order.
    assert d.fixed[0].evidence["source_file"] == "com/foo/B0.java"


# ---------- Severity gate ----------

def test_gate_blocks_on_new_high_severity() -> None:
    """A new HIGH finding flips the exit code when --fail-on covers HIGH."""
    new_high = _f(severity=Severity.HIGH)
    summary = DiffSummary(new=[new_high], fixed=[], unchanged=[])
    assert gate_exit_code(summary, {Severity.CRITICAL, Severity.HIGH}) == 1


def test_gate_passes_when_only_fixed_or_unchanged() -> None:
    """No 'new' findings → exit code 0 regardless of severity set."""
    fixed_critical = _f(severity=Severity.CRITICAL)
    summary = DiffSummary(new=[], fixed=[fixed_critical], unchanged=[])
    assert gate_exit_code(summary, {Severity.CRITICAL}) == 0


def test_gate_passes_for_new_below_threshold() -> None:
    """A new LOW finding with --fail-on=critical,high must NOT trip."""
    new_low = _f(severity=Severity.LOW)
    summary = DiffSummary(new=[new_low], fixed=[], unchanged=[])
    assert gate_exit_code(
        summary, {Severity.CRITICAL, Severity.HIGH},
    ) == 0


def test_parse_severity_list_round_trips_canonical_names() -> None:
    parsed = parse_severity_list("Critical, high, MEDIUM")
    assert parsed == {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


def test_parse_severity_list_rejects_unknown_token() -> None:
    with pytest.raises(ValueError):
        parse_severity_list("critical,extreme")


# ---------- Renderers ----------

def test_render_markdown_has_pr_comment_shape() -> None:
    """The markdown output must lead with a "🔴 N new" headline so a
    GitHub Action can paste it straight into a PR comment, then list
    each new finding in a severity-sorted table."""
    summary = compute_delta(
        base=[_f(file="com/foo/Old.java")],
        head=[
            _f(severity=Severity.CRITICAL,
               vuln_class="COMMAND_INJECTION",
               file="com/foo/New.java",
               code="Runtime.getRuntime().exec(cmd);"),
            _f(severity=Severity.MEDIUM,
               vuln_class="INSECURE_LOGGING",
               file="com/foo/Log.java",
               code="Log.d(\"tag\", token);"),
        ],
    )
    md = render_markdown(summary, base_label="v1.apk", head_label="v2.apk")
    assert md.startswith("### SENTINEL diff")
    assert "🔴 **2 new findings introduced**" in md
    assert "🟢 **1 fixed**" in md
    # Sorted: CRITICAL before MEDIUM in the table.
    crit_idx = md.find("COMMAND_INJECTION")
    med_idx  = md.find("INSECURE_LOGGING")
    assert 0 <= crit_idx < med_idx
    # Sections are separated headers we can pin on.
    assert "#### New findings" in md
    assert "#### Fixed findings" in md


def test_render_markdown_empty_diff_shows_success() -> None:
    f = _f(file="com/foo/A.java")
    summary = compute_delta([f], [f])
    md = render_markdown(summary, base_label="v1", head_label="v2")
    assert md.startswith("### SENTINEL diff")
    assert "✅" in md
    assert "0 new" in md and "0 fixed" in md


def test_render_markdown_escapes_pipe_characters() -> None:
    """Vuln-class strings sometimes contain ``|`` chars — they must be
    backslash-escaped so the markdown table doesn't break."""
    summary = compute_delta(
        base=[],
        head=[_f(vuln_class="X | Y", code="foo")],
    )
    md = render_markdown(summary, base_label="b", head_label="h")
    assert r"X \| Y" in md


def test_render_json_schema_keys() -> None:
    """The JSON renderer must produce the exact top-level keys the
    spec mandates — schema is part of the public contract."""
    summary = compute_delta(
        base=[_f(file="com/foo/A.java")],
        head=[_f(file="com/foo/B.java")],
    )
    payload = render_json(summary, base_label="b.apk", head_label="h.apk")
    assert set(payload.keys()) == {
        "base", "head", "summary", "new_findings", "fixed_findings",
    }
    assert payload["summary"] == {"new": 1, "fixed": 1, "unchanged": 0}
    # JSON-serializable round-trip.
    s = json.dumps(payload)
    assert "new_findings" in s


# ---------- Baseline store ----------

def test_baseline_store_round_trip(tmp_path: Path) -> None:
    """Findings written for a given APK hash must read back identically,
    and re-recording bumps last_seen without losing first_seen."""
    db = tmp_path / "baselines.sqlite"
    findings = [
        _f(file="com/foo/A.java", code='secret = "abc";'),
        _f(file="com/foo/B.java", agent_id="C_007",
           vuln_class="WEAK_CRYPTO", code='"MD5"'),
    ]
    with BaselineStore(db) as store:
        n = store.record("apk_hash_demo", findings)
        assert n == 2
        rows = store.rows_for("apk_hash_demo")
        assert len(rows) == 2
        # first_seen == last_seen on first observation.
        assert rows[0]["first_seen"] == rows[0]["last_seen"]
        first_seen_original = rows[0]["first_seen"]

    # Re-record same findings: should update last_seen, preserve first_seen.
    import time as _time
    _time.sleep(0.01)  # ISO-format precision is microseconds; tiny pause suffices.
    with BaselineStore(db) as store:
        store.record("apk_hash_demo", findings)
        rows = store.rows_for("apk_hash_demo")
        assert len(rows) == 2  # still 2, not 4 — upsert worked
        assert rows[0]["first_seen"] == first_seen_original


def test_baseline_store_empty_apk_returns_empty_set(tmp_path: Path) -> None:
    db = tmp_path / "baselines.sqlite"
    with BaselineStore(db) as store:
        assert store.fingerprints_for("never_recorded_hash") == set()


# ---------- DiffSummary.counts helper ----------

def test_summary_counts_matches_lengths() -> None:
    summary = DiffSummary(
        new=[_f(file="A.java")],
        fixed=[_f(file="B.java"), _f(file="C.java")],
        unchanged=[_f(file="D.java"), _f(file="E.java"), _f(file="F.java")],
    )
    assert summary.counts == {"new": 1, "fixed": 2, "unchanged": 3}


# ---------- Optional real-corpus integration test ----------

@pytest.mark.integration
def test_real_corpus_diff_if_present() -> None:
    """If two real corpus APKs are present, run a diff end-to-end.

    Skipped automatically when the files aren't available. Gated by the
    'integration' marker so the default unit-test run stays sub-minute.
    """
    base = Path("corpus/InsecureBankv2.apk")
    head = Path("corpus/InsecureBankv2.apk")  # diff with self → no changes
    if not (base.exists() and head.exists()):
        pytest.skip("real corpus APKs not present")

    import asyncio

    from sentinel.cli import _run_static_scan

    base_findings, _ = asyncio.run(_run_static_scan(
        base, Path("./data"), Path("./workspace"), label="integration-base",
    ))
    head_findings, _ = asyncio.run(_run_static_scan(
        head, Path("./data"), Path("./workspace"), label="integration-head",
    ))
    diff = compute_delta(base_findings, head_findings)
    # Diffing an APK against itself should show zero new, zero fixed.
    assert diff.new == []
    assert diff.fixed == []
