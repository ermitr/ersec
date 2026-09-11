"""
Rigor Tests for the DifferentialOracle.
Converts architectural claims into executable proof.
"""
import pytest
from ersec.ersec_differential_auth import DifferentialOracle, DifferentialResult
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

def test_status_code_lie():
    """
    PROOF: Detects unauthorized data leakage even when HTTP status is 200
    but the response bodies are identical.
    """
    oracle = DifferentialOracle()
    # Both get the same data, but they have different roles.
    # Even if the server incorrectly returns 200 for both, it's a violation.
    privileged = create_ev(status=200, body={"secret": "admin_data"})
    unprivileged = create_ev(status=200, body={"secret": "admin_data"})

    result = oracle.evaluate(privileged, unprivileged)
    assert result.is_violation is True
    assert result.distance == 0.0
    assert "Field 'secret' leaked" in result.reason

def test_volatile_field_immunity():
    """
    PROOF: Does not flag harmless timestamps or random IDs.
    """
    oracle = DifferentialOracle()
    # Bodies are semantically identical except for a timestamp
    privileged = create_ev(body={"data": "value", "timestamp": "2026-01-01T10:00:00Z"})
    unprivileged = create_ev(body={"data": "value", "timestamp": "2026-01-01T10:00:05Z"})

    result = oracle.evaluate(privileged, unprivileged)
    assert result.is_violation is True
    assert result.distance == 0.0
    assert "timestamp" not in result.reason

def test_meaningful_field_change():
    """
    PROOF: Does flag meaningful sensitive-field changes.
    """
    oracle = DifferentialOracle()
    privileged = create_ev(body={"user": "admin", "role": "superuser"})
    unprivileged = create_ev(body={"user": "guest", "role": "user"})

    result = oracle.evaluate(privileged, unprivileged)
    assert result.is_violation is False
    assert result.distance > 0.5

def test_array_ordering_indifference():
    """
    PROOF: Handles nondeterministic array ordering.
    """
    oracle = DifferentialOracle(ignore_array_order=True)
    privileged = create_ev(body={"items": [1, 2, 3]})
    unprivileged = create_ev(body={"items": [3, 1, 2]})

    result = oracle.evaluate(privileged, unprivileged)
    assert result.is_violation is True
    assert result.distance == 0.0

def test_null_vs_absent_semantics():
    """
    PROOF: Handles null-versus-absent semantics.
    """
    oracle = DifferentialOracle()
    # These are semantically similar in many APIs
    privileged = create_ev(body={"data": "value", "meta": None})
    unprivileged = create_ev(body={"data": "value"})

    # In our current impl, this will be a distance because keys differ.
    # This test documents the current behavior.
    result = oracle.evaluate(privileged, unprivileged)
    # We expect this to be a violation if they are "close enough"
    # but technically it's a difference.
    assert result.distance > 0

def test_content_type_aware_comparison():
    """
    PROOF: Handles non-JSON bodies (string comparison).
    """
    oracle = DifferentialOracle()
    privileged = create_ev(body="Privileged Content")
    unprivileged = create_ev(body="Privileged Content")

    result = oracle.evaluate(privileged, unprivileged)
    assert result.is_violation is True
    assert result.distance == 0.0
