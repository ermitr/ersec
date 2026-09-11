"""
Juice Shop Benchmark Simulator.
Mocks the network layer to demonstrate the la-v-f metrics calculation
without requiring a live Juice Shop instance.
"""
import json
from typing import Any, Dict
from unittest.mock import MagicMock
from ersec.benchmarking.juiceshop import JuiceShopBenchmarkSuite
from ersec.types import RequestEvidence

def simulate_responses(case_id: str, token: str) -> RequestEvidence:
    """
    Simulate Juice Shop responses based on the case and token.
    """
    # Admin Token
    if token == "ADMIN_TOKEN":
        return RequestEvidence(
            method="GET",
            url=f"http://localhost:3000/api/{case_id}",
            status_code=200,
            response_json={"data": "secret_admin_data", "status": "success"},
            response_headers={"Content-Type": "application/json"},
            request_headers_sent={}
        )

    # User Token
    if token == "USER_TOKEN":
        if "JS-PUBLIC" in case_id:
            # Public assets are identical for both
            return RequestEvidence(
                method="GET",
                url=f"http://localhost:3000/api/{case_id}",
                status_code=200,
                response_json={"data": "public_data", "status": "success"},
                response_headers={"Content-Type": "application/json"},
                request_headers_sent={}
            )
        elif "/rest/admin" in case_id or "/rest/user" in case_id or "/rest/order" in case_id:
            # simulate a leak: returns the same data as admin despite being a user
            return RequestEvidence(
                method="GET",
                url=f"http://localhost:3000/api/{case_id}",
                status_code=200,
                response_json={"data": "secret_admin_data", "status": "success"},
                response_headers={"Content-Type": "application/json"},
                request_headers_sent={}
            )

    return RequestEvidence(method="GET", url="...", status_code=403)

def main():
    print("[*] Initializing Juice Shop Simulation...")
    suite = JuiceShopBenchmarkSuite(
        base_url="http://localhost:3000",
        admin_token="ADMIN_TOKEN",
        user_token="USER_TOKEN"
    )

    # Mock the _perform_request method to avoid real network calls
    suite._perform_request = MagicMock(side_effect=lambda token, path: simulate_responses(path, token))

    print("[*] Running simulated cases...")
    results = suite.run_suite()

    print("\n" + "="*40)
    print("SIMULATED JUICE SHOP BENCHMARK RESULTS")
    print("="*40)

    quality = results["quality"]
    print(f"Precision: {quality['precision']}")
    print(f"Recall:    {quality['recall']}")
    print(f"F1 Score:   {quality['f1']}")
    print(f"TP: {quality['true_positives']} | FP: {quality['false_positives']} | FN: {quality['false_negatives']}")

    print("\n[*] Simulation complete. Metrics proven.")

if __name__ == "__main__":
    main()
