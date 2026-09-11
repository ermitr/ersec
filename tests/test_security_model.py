"""29.1.0 runtime security-model regression coverage used by the roadmap audit."""
from ersec_behavior import SecurityBehaviorModel

def test_security_model_rejects_state_changing_methods():
    data = {"identities": [{"name": "u", "role": "user", "tenant": "t"}],
            "resources": [{"resource_id": "r", "url": "https://example.test/r", "methods": ["GET", "POST"], "expected": {"u": {"status": [200]}}}],
            "invariants": [], "workflows": []}
    try:
        SecurityBehaviorModel(data)
    except ValueError as exc:
        assert "only GET/HEAD/OPTIONS" in str(exc)
    else:
        assert False, "state-changing methods must be rejected"

def test_security_model_graph_is_deterministic():
    spec={"identities":[{"name":"u","role":"user","tenant":"t"}],"resources":[{"resource_id":"r","url":"https://example.test/r","methods":["GET"],"expected":{"u":{"status":[200]}}}],"invariants":[],"workflows":[]}
    a=SecurityBehaviorModel(spec).validate()["fingerprint"]
    b=SecurityBehaviorModel(spec).validate()["fingerprint"]
    assert a == b
