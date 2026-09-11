import json
from ersec.ersec_remediation_verify import verify_contracts


def contracts():
    return {"contracts": [{"contract_id":"RGC-1","property_id":"PROP-1","verification":{"required_verdict":"PASS"}}]}


def test_missing_evidence_not_resolved():
    r = verify_contracts(contracts(), {"observations": []})
    assert r["status"] == "FAIL"
    assert r["unresolved_count"] == 1
    assert r["results"][0]["status"] == "NOT_RESOLVED"


def test_missing_digest_blocked():
    r = verify_contracts(contracts(), {"observations":[{"property_id":"PROP-1","verdict":"PASS"}]})
    assert r["status"] == "BLOCKED"


def test_fresh_positive_evidence_verifies():
    r = verify_contracts(contracts(), {"observations":[{"property_id":"PROP-1","verdict":"PASS","evidence_digest":"abc"}]}, baseline={"observations":[{"property_id":"PROP-1","verdict":"VIOLATION","evidence_digest":"old"}]})
    assert r["status"] == "PASS"
    assert r["verified_count"] == 1


def test_already_passing_is_not_claimed_as_remediation():
    r = verify_contracts(contracts(), {"observations":[{"property_id":"PROP-1","verdict":"PASS","evidence_digest":"new"}]}, baseline={"observations":[{"property_id":"PROP-1","verdict":"PASS","evidence_digest":"old"}]})
    assert r["status"] == "PASS"
    assert r["already_pass_count"] == 1


def test_violation_remains_unresolved():
    r = verify_contracts(contracts(), {"observations":[{"property_id":"PROP-1","verdict":"VIOLATION","evidence_digest":"bad"}]})
    assert r["status"] == "FAIL"
    assert r["results"][0]["status"] == "NOT_RESOLVED"


def test_digest_is_deterministic():
    a = verify_contracts(contracts(), {"observations":[{"property_id":"PROP-1","verdict":"PASS","evidence_digest":"abc"}]})
    b = verify_contracts(contracts(), {"observations":[{"property_id":"PROP-1","verdict":"PASS","evidence_digest":"abc"}]})
    assert a["verification_digest"] == b["verification_digest"]
