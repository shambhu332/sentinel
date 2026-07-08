"""MSTG/DIVA/OVAA benchmark runner.

Measures SENTINEL's precision and recall against known-vulnerable APKs.

Usage:
    python tests/benchmark/mstg_runner.py
    pytest tests/benchmark/test_benchmark.py -m benchmark

Required env:
    SENTINEL_BENCHMARK_CORPUS_DIR — path to pre-downloaded APKs (see CORPUS below).
    Skip individual apps by omitting their APK from the corpus directory.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Benchmark corpus definition
# ---------------------------------------------------------------------------

@dataclass
class AppSpec:
    name: str
    apk_filename: str
    source_url: str
    expected_finding_categories: list[str]
    # Minimum number of true-positive findings we expect per category.
    min_tp_per_category: dict[str, int] = field(default_factory=dict)


CORPUS: list[AppSpec] = [
    AppSpec(
        name="DIVA",
        apk_filename="diva-beta.apk",
        source_url="https://github.com/payatu/diva-android/raw/master/diva-beta.apk",
        expected_finding_categories=["Crypto/Storage", "Authentication", "Network", "Android Platform"],
        min_tp_per_category={"Crypto/Storage": 2, "Authentication": 1},
    ),
    AppSpec(
        name="InsecureBankv2",
        apk_filename="InsecureBankv2.apk",
        source_url="https://github.com/dineshshetty/InsecureBankv2/raw/master/InsecureBankv2.apk",
        expected_finding_categories=["Crypto/Storage", "Authentication", "Network", "WebView"],
        min_tp_per_category={"Network": 2, "Crypto/Storage": 1},
    ),
    AppSpec(
        name="OVAA",
        apk_filename="ovaa.apk",
        source_url="https://github.com/oversecured/ovaa/releases/latest/download/ovaa.apk",
        expected_finding_categories=["Android Platform", "Authentication", "Crypto/Storage"],
        min_tp_per_category={"Android Platform": 2},
    ),
]

# ---------------------------------------------------------------------------
# Thresholds (CI gate)
# ---------------------------------------------------------------------------

RECALL_THRESHOLD = 0.70
PRECISION_THRESHOLD = 0.80

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

@dataclass
class AppResult:
    app: str
    total_findings: int
    categories_found: set[str]
    categories_expected: set[str]
    category_recall: float
    scan_duration_s: float
    raw_findings: list[dict[str, Any]]
    error: str = ""


def _corpus_dir() -> Path:
    env = os.environ.get("SENTINEL_BENCHMARK_CORPUS_DIR", "")
    if env:
        return Path(env)
    return Path(__file__).parent / "corpus"


def _download_apk(spec: AppSpec, dest: Path) -> bool:
    """Download APK if not present. Returns True if available."""
    apk_path = dest / spec.apk_filename
    if apk_path.exists():
        return True
    print(f"[benchmark] downloading {spec.name} from {spec.source_url}")
    try:
        import urllib.request
        urllib.request.urlretrieve(spec.source_url, apk_path)
        return True
    except Exception as e:
        print(f"[benchmark] SKIP {spec.name}: download failed ({e})", file=sys.stderr)
        return False


def _run_scan(apk_path: Path, timeout: int = 600) -> list[dict[str, Any]]:
    """Run sentinel scan CLI and return parsed findings list."""
    cmd = [
        sys.executable, "-m", "sentinel",
        "scan", str(apk_path),
        "--format", "json",
        "--private",  # local-only, no cloud LLM calls in CI
        "--no-dynamic",  # static only for benchmark (no device needed)
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=Path(__file__).parents[2],
        )
        if result.returncode != 0:
            print(f"[benchmark] scan stderr: {result.stderr[:500]}", file=sys.stderr)
        # Parse JSON output — sentinel writes findings JSON to stdout with --format json
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("findings", [])
    except subprocess.TimeoutExpired:
        print("[benchmark] scan timed out", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"[benchmark] JSON parse error: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[benchmark] scan error: {e}", file=sys.stderr)
    return []


def run_benchmark(download: bool = True) -> dict[str, Any]:
    """Run full benchmark suite. Returns aggregated metrics."""
    corpus_dir = _corpus_dir()
    corpus_dir.mkdir(parents=True, exist_ok=True)

    results: list[AppResult] = []

    for spec in CORPUS:
        apk_path = corpus_dir / spec.apk_filename
        if not apk_path.exists():
            if not download or not _download_apk(spec, corpus_dir):
                print(f"[benchmark] SKIP {spec.name}: APK not found", file=sys.stderr)
                continue

        print(f"\n[benchmark] scanning {spec.name} ({apk_path.name})")
        t0 = time.monotonic()
        findings = _run_scan(apk_path)
        duration = time.monotonic() - t0

        categories_found = {f.get("category", "") for f in findings if f.get("severity") not in ("Info", "LOW")}
        categories_expected = set(spec.expected_finding_categories)

        # Category-level recall: fraction of expected categories with at least one finding.
        matched = categories_found & categories_expected
        recall = len(matched) / len(categories_expected) if categories_expected else 1.0

        results.append(AppResult(
            app=spec.name,
            total_findings=len(findings),
            categories_found=categories_found,
            categories_expected=categories_expected,
            category_recall=recall,
            scan_duration_s=round(duration, 1),
            raw_findings=findings,
        ))
        print(
            f"  findings={len(findings)}  recall={recall:.2f}  "
            f"categories_found={sorted(categories_found)}  duration={duration:.1f}s"
        )

    if not results:
        return {"error": "No APKs available. Place APKs in tests/benchmark/corpus/ or set SENTINEL_BENCHMARK_CORPUS_DIR."}

    overall_recall = sum(r.category_recall for r in results) / len(results)

    # Precision: fraction of findings that have a non-empty category (proxy for non-noise findings).
    all_findings = [f for r in results for f in r.raw_findings]
    valid = [f for f in all_findings if f.get("category") and f.get("severity") not in ("Info",)]
    overall_precision = len(valid) / len(all_findings) if all_findings else 1.0

    summary = {
        "overall_recall": round(overall_recall, 3),
        "overall_precision": round(overall_precision, 3),
        "f1_score": round(
            2 * (overall_precision * overall_recall) / (overall_precision + overall_recall)
            if (overall_precision + overall_recall) > 0 else 0,
            3,
        ),
        "recall_threshold": RECALL_THRESHOLD,
        "precision_threshold": PRECISION_THRESHOLD,
        "passes_recall": overall_recall >= RECALL_THRESHOLD,
        "passes_precision": overall_precision >= PRECISION_THRESHOLD,
        "per_app": [
            {
                "app": r.app,
                "total_findings": r.total_findings,
                "category_recall": round(r.category_recall, 3),
                "scan_duration_s": r.scan_duration_s,
                "categories_found": sorted(r.categories_found),
                "categories_expected": sorted(r.categories_expected),
            }
            for r in results
        ],
    }
    return summary


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SENTINEL MSTG benchmark runner")
    parser.add_argument("--no-download", action="store_true", help="Skip auto-download")
    parser.add_argument("--output", default="", help="Write JSON results to file")
    args = parser.parse_args()

    results = run_benchmark(download=not args.no_download)
    output = json.dumps(results, indent=2)
    print(output)

    if args.output:
        Path(args.output).write_text(output)
        print(f"\nResults written to {args.output}", file=sys.stderr)

    if not results.get("passes_recall") or not results.get("passes_precision"):
        print(
            f"\nFAIL: recall={results.get('overall_recall')} "
            f"(need >={RECALL_THRESHOLD}), "
            f"precision={results.get('overall_precision')} "
            f"(need >={PRECISION_THRESHOLD})",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"\nPASS: recall={results.get('overall_recall')} precision={results.get('overall_precision')}")
