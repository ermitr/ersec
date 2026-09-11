from ersec.ersec_proof_engine import build_finding, verify

def test_build_and_verify():
    b=build_finding({"case_id":"c1","property_id":"p1","subject":"b","resource":"order","method":"GET"},{"verdict":"pass","status":200},{"case_id":"c1","verdict":"violation","status":200,"reason":"boundary"},["ev1"])
    assert b["classification"] == "confirmed"; assert verify(b)["valid"]

def test_tamper_detected():
    b=build_finding({"case_id":"c1"},{"verdict":"pass"},{"case_id":"c1","verdict":"violation"}); b["mutation"]["status"]=200
    assert not verify(b)["valid"]

def test_mismatched_case_is_rejected():
    try:
        build_finding({"case_id":"c1"},{"verdict":"pass"},{"case_id":"c2","verdict":"violation"})
    except ValueError as exc:
        assert "case_id" in str(exc)
    else:
        assert False

def test_verify_rejects_credential_policy_tampering():
    b=build_finding({"case_id":"c1"},{"verdict":"pass"},{"case_id":"c1","verdict":"violation"})
    b["replay"]["credential_values_included"] = True
    # Integrity is intentionally now stale; both integrity and policy violations must be visible.
    result=verify(b)
    assert not result["valid"]
    assert any("digest" in e for e in result["errors"])
