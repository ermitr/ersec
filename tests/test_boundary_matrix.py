from ersec_security_boundary_lab import compile_differential_matrix


def test_differential_matrix_pairs_security_boundaries_only():
    spec = {
        "identities": {
            "alice": {"role": "user", "tenant": "A", "credential_ref": "vault://a"},
            "bob": {"role": "user", "tenant": "B", "credential_ref": "vault://b"},
            "admin": {"role": "admin", "tenant": "A", "credential_ref": "vault://admin"},
            "same": {"role": "user", "tenant": "A", "credential_ref": "vault://same"},
        },
        "resources": [{"id": "order", "methods": ["GET", "POST"]}],
        "properties": [{"id": "isolation", "resource": "order", "expected_status": [403, 404], "forbidden": ["amount"]}],
    }
    p = compile_differential_matrix(spec)
    assert p["mode"] == "differential_identity_matrix"
    assert p["statistics"]["identity_pairs"] == 5
    assert p["statistics"]["cases"] == 5
    assert all(c["safety"]["network"] is False for c in p["cases"])
    assert "credential_ref" not in str(p)
