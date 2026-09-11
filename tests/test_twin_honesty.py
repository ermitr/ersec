"""
Rigor Tests for the Behavioral Twin Honesty mechanisms.
Ensures that confidence degrades when data is nondeterministic or observations are sparse.
"""
import pytest
from unittest.mock import MagicMock
from ersec.ersec_behavioral_twin import GoldenPathObserver, BehavioralTwinEngine, BehavioralProof
from ersec.ersec_differential_auth import DifferentialOracle
from ersec.types import RequestEvidence

def create_ev(status=200, body=None):
    return RequestEvidence(
        method="GET",
        url="http://target/api/resource",
        status_code=status,
        response_json=body,
        response_headers={},
        request_headers_sent={}
    )

def test_confidence_degradation_on_sparse_observations():
    """
    PROOF: Confidence degrades when only one observation exists.
    """
    observer = GoldenPathObserver()
    oracle = DifferentialOracle()
    engine = BehavioralTwinEngine(observer, oracle)

    # Only record once (Sparse)
    observer.record("/api/data", "GET", "admin", create_ev(body={"secret": "val"}))

    # Twin also gets the secret (Violation)
    def mock_request(identity, method, path):
        return create_ev(body={"secret": "val"})

    proofs = engine.prove_violation("user", mock_request)

    assert proofs[0].is_violation is True
    assert proofs[0].confidence == "Low" # Degraded from High/Medium due to obs_count < 3
    assert any("Low observation count" in factor for factor in proofs[0].uncertainty_factors)

def test_confidence_increase_on_stable_observations():
    """
    PROOF: Confidence increases when baseline is observed multiple times.
    """
    observer = GoldenPathObserver()
    oracle = DifferentialOracle()
    engine = BehavioralTwinEngine(observer, oracle)

    # Record multiple times (Stable)
    for _ in range(3):
        observer.record("/api/data", "GET", "admin", create_ev(body={"secret": "val"}))

    def mock_request(identity, method, path):
        return create_ev(body={"secret": "val"})

    proofs = engine.prove_violation("user", mock_request)

    assert proofs[0].is_violation is True
    assert proofs[0].confidence != "Low" # Should be High/Medium now
    assert not any("Low observation count" in factor for factor in proofs[0].uncertainty_factors)

def test_uncertainty_on_empty_responses():
    """
    PROOF: Warns when the twin cannot distinguish authorization from normal personalization (empty responses).
    """
    observer = GoldenPathObserver()
    oracle = DifferentialOracle()
    engine = BehavioralTwinEngine(observer, oracle)

    for _ in range(3):
        observer.record("/api/data", "GET", "admin", create_ev(body={"secret": "val"}))

    # Twin gets an empty response (possibly blocked, possibly just empty)
    def mock_request(identity, method, path):
        return create_ev(body=None)

    proofs = engine.prove_violation("user", mock_request)

    # it's not a violation (distance is high), but it should be flagged as uncertain
    assert proofs[0].is_violation is False
    assert any("Twin received empty response" in factor for factor in proofs[0].uncertainty_factors)
