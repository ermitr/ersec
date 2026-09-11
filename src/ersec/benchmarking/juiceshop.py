"""
Juice Shop Implementation of the ERSEC Benchmark Suite.
Provides deterministic cases for proving BOLA/IDOR and Admin Exposure on OWASP Juice Shop.
"""
from __future__ import annotations
from typing import Any, Dict, List, Sequence
from ersec.benchmarking.base import BaseBenchmarkSuite, BenchmarkCase
from ersec.adapters.juiceshop import JuiceShopAdapter
from ersec.ersec_differential_auth import DifferentialOracle
from ersec.types import RequestEvidence, ScanConfig, ScopeConfig
import requests

class JuiceShopBenchmarkSuite(BaseBenchmarkSuite):
    """
    Concrete benchmark suite for OWASP Juice Shop.
    """

    def __init__(self, base_url: str, admin_token: str, user_token: str):
        super().__init__(benchmark_id="juiceshop-authz-v1")
        self.adapter = JuiceShopAdapter(base_url)
        self.admin_token = admin_token
        self.user_token = user_token
        self.oracle = DifferentialOracle()

    def get_cases(self) -> Sequence[BenchmarkCase]:
        """
        Define the ground-truth cases for Juice Shop authorization.
        """
        return [
            # Case 1: Admin User List (Vertical Privilege Escalation)
            BenchmarkCase(
                case_id="JS-ADMIN-01",
                family="admin_exposure",
                identity="user",
                path="/rest/admin/users",
                expected_verdict="violation"
            ),
            # Case 2: Another User's Profile (Horizontal Privilege Escalation / BOLA)
            BenchmarkCase(
                case_id="JS-BOLA-01",
                family="bola",
                identity="user",
                path="/rest/user/1", # Assuming user 1 is a different user
                expected_verdict="violation"
            ),
            # Case 3: Another User's Orders (BOLA)
            BenchmarkCase(
                case_id="JS-BOLA-02",
                family="bola",
                identity="user",
                path="/rest/order/1",
                expected_verdict="violation"
            ),
            # Case 4: Public Asset (Baseline - should NOT be a violation)
            BenchmarkCase(
                case_id="JS-PUBLIC-01",
                family="baseline",
                identity="user",
                path="/api/products",
                expected_verdict="pass"
            ),
        ]

    def _perform_request(self, token: str, path: str) -> RequestEvidence:
        """Helper to perform a request and return RequestEvidence."""
        url = self.adapter.get_full_url(path)
        headers = self.adapter.get_session_headers(token)

        try:
            resp = requests.get(url, headers=headers, timeout=5)
            try:
                json_body = resp.json()
            except:
                json_body = None

            return RequestEvidence(
                method="GET",
                url=url,
                status_code=resp.status_code,
                response_json=json_body,
                response_headers=dict(resp.headers),
                request_headers_sent=headers
            )
        except Exception as e:
            # In a real benchmark, we'd track errors separately.
            return RequestEvidence(method="GET", url=url, status_code=500)

    def run_case(self, case: BenchmarkCase, variant: str) -> Dict[str, Any]:
        """
        Execute a single case using Differential Behavioral Assurance.
        """
        # 1. Get Golden (Privileged) Evidence
        # For simplicity, we use the admin_token as the privileged identity
        golden_ev = self._perform_request(self.admin_token, case.path)

        # 2. Get Twin (Unprivileged) Evidence
        # We use the user_token as the twin identity
        twin_ev = self._perform_request(self.user_token, case.path)

        # 3. Evaluate via Differential Oracle
        result = self.oracle.evaluate(golden_ev, twin_ev)

        verdict = "violation" if result.is_violation else "pass"

        return {
            "case_id": case.case_id,
            "verdict": verdict,
            "distance": result.distance,
            "confidence": result.confidence,
            "request_count": 2
        }
