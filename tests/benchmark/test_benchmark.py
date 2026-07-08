"""Benchmark tests — opt-in via `pytest -m benchmark`.

Requires APKs in tests/benchmark/corpus/ or SENTINEL_BENCHMARK_CORPUS_DIR.
Skipped automatically in normal CI runs.
"""
from __future__ import annotations

import pytest

from tests.benchmark.mstg_runner import RECALL_THRESHOLD, PRECISION_THRESHOLD, run_benchmark


@pytest.mark.benchmark
def test_benchmark_recall_and_precision():
    results = run_benchmark(download=True)

    if "error" in results:
        pytest.skip(results["error"])

    overall_recall = results["overall_recall"]
    overall_precision = results["overall_precision"]

    assert overall_recall >= RECALL_THRESHOLD, (
        f"Recall {overall_recall:.3f} below threshold {RECALL_THRESHOLD}. "
        f"Per-app: {results['per_app']}"
    )
    assert overall_precision >= PRECISION_THRESHOLD, (
        f"Precision {overall_precision:.3f} below threshold {PRECISION_THRESHOLD}."
    )


@pytest.mark.benchmark
@pytest.mark.parametrize("app", ["DIVA", "InsecureBankv2", "OVAA"])
def test_per_app_has_findings(app: str):
    """Each app must produce at least one finding when scanned."""
    from pathlib import Path
    from tests.benchmark.mstg_runner import CORPUS, _corpus_dir, _run_scan

    spec = next((s for s in CORPUS if s.name == app), None)
    if spec is None:
        pytest.skip(f"No spec for {app}")

    apk_path = _corpus_dir() / spec.apk_filename
    if not apk_path.exists():
        pytest.skip(f"{apk_path} not found — place APK in corpus dir")

    findings = _run_scan(apk_path)
    assert len(findings) > 0, f"No findings produced for {app}"
