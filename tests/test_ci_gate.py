import sys
sys.path.insert(0, ".")
from ersec_ci_gate import evaluate

def base():
    return {"status":"PASS","valid":True,"statement_digest":"abc","decision":"PASS"}

def test_all_evidence_passes():
    r=evaluate(release_audit={"status":"PASS"}, continuous={"decision":"PASS"}, release_evidence={"valid":True}, provenance={"statement_digest":"x","signed":False})
    assert r["status"] == "PASS"

def test_missing_evidence_blocks():
    r=evaluate(release_audit={"status":"PASS"}, continuous={"decision":"PASS"})
    assert r["status"] == "BLOCKED"
    assert r["blocked_count"] >= 2

def test_regression_fails():
    r=evaluate(release_audit={"status":"PASS"}, continuous={"decision":"FAIL"}, release_evidence={"valid":True}, provenance={"statement_digest":"x"})
    assert r["status"] == "FAIL"

def test_signed_provenance_requirement_blocks():
    r=evaluate(release_audit={"status":"PASS"}, continuous={"decision":"PASS"}, release_evidence={"valid":True}, provenance={"statement_digest":"x","signed":False}, require_signed_provenance=True)
    assert r["status"] == "BLOCKED"

def test_no_false_pass_from_absence():
    r=evaluate()
    assert r["status"] == "BLOCKED"
    assert all(x["status"] != "PASS" for x in r["checks"])
