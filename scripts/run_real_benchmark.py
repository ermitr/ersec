"""
ERSEC Real Authorization Benchmark Simulator.
Simulates a target that perfectly matches the Ground Truth manifest
to verify the metrics engine.
"""
import json
from ersec.benchmarking.authorization_benchmark import RealAuthorizationBenchmark
from ersec.benchmarking.ground_truth import GROUND_TRUTH
from ersec.adapters.juiceshop import JuiceShopAdapter
from ersec.types import RequestEvidence
from unittest.mock import MagicMock

def simulate_target_response(token: str, path: str, method: str) -> RequestEvidence:
    """
    Simulates responses based on the GROUND_TRUTH manifest.
    """
    # Find the case that matches this path/method
    case = None
    for ct in GROUND_TRUTH.values():
        if ct.path == path and ct.method == method:
            case = ct
            break

    if not case:
        return RequestEvidence(method=method, url=path, status_code=404, response_json={"error": "Not Found"})

    # Deterministic Response Logic based on Ground Truth
    # Admin always gets the 'full' response
    if token == "ADMIN_TOKEN":
        return RequestEvidence(
            method=method, url=path, status_code=200,
            response_json={"data": "SECRET_SENSITIVE_DATA", "meta": "admin_view"},
            response_headers={"Content-Type": "application/json"},
            request_headers_sent={}
        )

    # User Token
    if token == "USER_TOKEN":
        # If ground truth says 'violation', the user ALSO gets the secret data (Leak!)
        if case.expectations.get("user") == "violation":
            return RequestEvidence(
                method=method, url=path, status_code=200,
                response_json={"data": "SECRET_SENSITIVE_DATA", "meta": "admin_view"},
                response_headers={"Content-Type": "application/json"},
                request_headers_sent={}
            )
        # Otherwise, it's a pass/blocked (Different data)
        return RequestEvidence(
            method=method, url=path, status_code=403,
            response_json={"error": "Access Denied"},
            response_headers={"Content-Type": "application/json"},
            request_headers_sent={}
        )

    # Anonymous
    return RequestEvidence(method=method, url=path, status_code=401, response_json={"error": "Unauthorized"})

def main():
    print("[*] Initializing Real Authorization Benchmark Simulator...")
    adapter = JuiceShopAdapter("http://localhost:3000")

    suite = RealAuthorizationBenchmark(
        benchmark_id="rigor-authz-v1",
        adapter=adapter,
        admin_token="ADMIN_TOKEN",
        user_token="USER_TOKEN"
    )

    # Mock the _perform_request to use our simulator
    suite._perform_request = MagicMock(side_effect=lambda token, path, method="GET": simulate_target_response(token, path, method))

    print(f"[*] Running {len(suite.get_cases())} ground-truth cases...")
    report = suite.run_benchmark()

    print("\n" + "="*40)
    print("REAL AUTHORIZATION BENCHMARK RESULTS")
    print("="*40)

    m = report.metrics
    print(f"Precision: {m['precision']}")
    print(f"Recall:    {m['recall']}")
    print(f"F1 Score:   {m['f1']}")
    print(f"TP: {m['true_positives']} | FP: {m['false_positives']} | FN: {m['false_negatives']}")

    print("\nCase Details:")
    for cid, res in report.case_results.items():
        status = "OK" if res["is_correct"] else "FAIL"
        print(f"{status} {cid}: Expected {res['expected']}, Observed {res['observed']} (Dist: {res['distance']:.4f})")

if __name__ == "__main__":
    main()
