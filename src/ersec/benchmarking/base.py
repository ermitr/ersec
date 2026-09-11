"""
Base classes for ERSEC security benchmarks.
Provides the structure for implementing target-specific assurance suites.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import time
import json

from ersec.benchmarking.metrics import calculate_metrics, calculate_runtime_stats

@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    family: str
    identity: str
    path: str
    expected_verdict: str  # "pass" or "violation"
    truth_class: str = "deterministic" # "deterministic" or "ambiguous"
    metadata: Dict[str, Any] = None

class BaseBenchmarkSuite(ABC):
    """
    Abstract base for all ERSEC benchmarks.
    Enforces a consistent reporting format for industry-leading transparency.
    """

    def __init__(self, benchmark_id: str):
        self.benchmark_id = benchmark_id

    @abstractmethod
    def get_cases(self) -> Sequence[BenchmarkCase]:
        """Return the set of cases to be tested."""
        pass

    @abstractmethod
    def run_case(self, case: BenchmarkCase, variant: str) -> Dict[str, Any]:
        """
        Execute a single test case against a specific variant (e.g., 'fixed' vs 'vulnerable').
        Returns a result containing the observed verdict and request count.
        """
        pass

    def run_suite(self, variants: List[str] = ["fixed", "vulnerable"]) -> Dict[str, Any]:
        """
        Run the complete suite across multiple variants and compute metrics.
        """
        cases = self.get_cases()
        results = {}
        all_runtime = []
        all_requests = []

        for variant in variants:
            variant_results = []
            variant_start = time.perf_counter()

            for case in cases:
                res = self.run_case(case, variant)
                variant_results.append(res)
                all_requests.append(res.get("request_count", 0))

            variant_runtime = time.perf_counter() - variant_start
            all_runtime.append(variant_runtime)
            results[variant] = {
                "cases": variant_results,
                "runtime": variant_runtime,
                "request_count": sum(r.get("request_count", 0) for r in variant_results)
            }

        # Metric calculation
        scorable_ids = {c.case_id for c in cases if c.truth_class == "deterministic"}

        # We compare 'vulnerable' vs 'fixed' if both exist
        if "vulnerable" in results and "fixed" in results:
            v_pos = {r["case_id"] for r in results["vulnerable"]["cases"] if r["verdict"] == "violation"}
            f_pos = {r["case_id"] for r in results["fixed"]["cases"] if r["verdict"] == "violation"}
            expected_pos = {c.case_id for c in cases if c.expected_verdict == "violation"}

            metrics = calculate_metrics(expected_pos, v_pos, scorable_ids)
            # Check for regressions in 'fixed' variant
            fixed_violations = f_pos - set() # Simplified for base

            quality = {
                **metrics,
                "fixed_variant_safe": len(f_pos) == 0,
                "scorable_coverage": len(scorable_ids) / len(cases) if cases else 1.0
            }
        else:
            quality = {"note": "Comparison metrics require both fixed and vulnerable variants."}

        return {
            "benchmark_id": self.benchmark_id,
            "status": "completed",
            "cases_count": len(cases),
            "quality": quality,
            "runtime": calculate_runtime_stats(all_runtime),
            "variants": results
        }

    def write_report(self, path: str):
        """Write the benchmark results to a JSON file."""
        result = self.run_suite()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
        return result
