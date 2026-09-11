"""
ERSEC Authorization Benchmark Engine.
Implements the "Real Authorization Benchmark" with independent ground truth.
"""
from __future__ import annotations
from typing import Any, Dict, List, Set, Tuple
from dataclasses import dataclass
import json
from pathlib import Path

from ersec.benchmarking.base import BaseBenchmarkSuite, BenchmarkCase
from ersec.benchmarking.metrics import calculate_metrics
from ersec.benchmarking.ground_truth import get_ground_truth, AuthTestCase
from ersec.adapters.base import TargetAdapter
from ersec.ersec_differential_auth import DifferentialOracle
from ersec.types import RequestEvidence

@dataclass
class BenchmarkReport:
    benchmark_id: str
    metrics: Dict[str, Any]
    case_results: Dict[str, Any]
    runtime_stats: Dict[str, Any]

class RealAuthorizationBenchmark(BaseBenchmarkSuite):
    """
    Executes the ERSEC Authorization Benchmark against a real target
    using independently stored ground truth.
    """

    def __init__(self, benchmark_id: str, adapter: TargetAdapter, admin_token: str, user_token: str, anon_token: str = ""):
        super().__init__(benchmark_id)
        self.adapter = adapter
        self.tokens = {
            "admin": admin_token,
            "user": user_token,
            "anonymous": anon_token
        }
        self.oracle = DifferentialOracle()
        self.ground_truth = get_ground_truth()

    def get_cases(self) -> List[BenchmarkCase]:
        """
        Convert ground truth manifest into BenchmarkCases.
        """
        cases = []
        for case_id, gt in self.ground_truth.items():
            # We create a case for the 'user' identity to see if they can do what's forbidden
            cases.append(BenchmarkCase(
                case_id=case_id,
                family=gt.family,
                identity="user",
                path=gt.path,
                expected_verdict="violation" if gt.expectations.get("user") == "violation" else "pass"
            ))
        return cases

    def _perform_request(self, token: str, path: str, method: str = "GET") -> RequestEvidence:
        """Helper to perform a request via the adapter."""
        url = self.adapter.get_full_url(path)
        headers = self.adapter.get_session_headers(token) if token else {}

        import requests
        try:
            resp = requests.request(method, url, headers=headers, timeout=5)
            try:
                json_body = resp.json()
            except:
                json_body = None

            return RequestEvidence(
                method=method,
                url=url,
                status_code=resp.status_code,
                response_json=json_body,
                response_headers=dict(resp.headers),
                request_headers_sent=headers
            )
        except Exception:
            return RequestEvidence(method=method, url=url, status_code=500)

    def run_case(self, case: BenchmarkCase, variant: str = "vulnerable") -> Dict[str, Any]:
        """
        Run a single case and compare against ground truth.
        """
        gt = self.ground_truth.get(case.case_id)
        if not gt:
            return {"case_id": case.case_id, "verdict": "error", "reason": "No ground truth found"}

        # 1. Get Golden (Privileged) Evidence
        golden_ev = self._perform_request(self.tokens["admin"], gt.path, gt.method)

        # 2. Get Twin (Unprivileged) Evidence
        twin_ev = self._perform_request(self.tokens["user"], gt.path, gt.method)

        # 3. Evaluate via Differential Oracle
        result = self.oracle.evaluate(golden_ev, twin_ev)
        observed_verdict = "violation" if result.is_violation else "pass"

        # 4. Compare against independent ground truth
        expected_verdict = gt.expectations.get("user", "blocked")
        # Convert "blocked" to "pass" for the sake of the oracle's binary result (not a violation)
        normalized_expected = "violation" if expected_verdict == "violation" else "pass"

        is_correct = (observed_verdict == normalized_expected)

        return {
            "case_id": case.case_id,
            "expected": normalized_expected,
            "observed": observed_verdict,
            "is_correct": is_correct,
            "verdict": observed_verdict,
            "distance": result.distance,
            "confidence": result.confidence,
            "request_count": 2
        }

    def run_benchmark(self) -> BenchmarkReport:
        """
        Run the entire corpus and calculate la-v-f metrics.
        """
        cases = self.get_cases()
        results = []

        for case in cases:
            res = self.run_case(case)
            results.append(res)

        # Metrics calculation
        expected_pos = {c.case_id for c in cases if c.expected_verdict == "violation"}
        observed_pos = {r["case_id"] for r in results if r["verdict"] == "violation"}
        scorable_ids = {c.case_id for c in cases}

        metrics = calculate_metrics(expected_pos, observed_pos, scorable_ids)

        return BenchmarkReport(
            benchmark_id=self.benchmark_id,
            metrics=metrics,
            case_results={r["case_id"]: r for r in results},
            runtime_stats={} # Simplified for now
        )
