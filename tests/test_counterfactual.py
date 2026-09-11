from ersec.ersec_counterfactual import build_counterfactual

def test_mutation_sensitive_pass():
    r=build_counterfactual({"verdict":"pass"},{"verdict":"violation","mutation":{"id":"m1"}},[{"trace_id":"t1","policy_decision_id":"p1"}])
    assert r["status"]=="pass" and r["relation"]=="security_property_sensitive_to_mutation"
    assert r["trace_ids"]==["t1"]

def test_same_verdict_is_inconclusive():
    r=build_counterfactual({"verdict":"pass"},{"verdict":"pass","mutation":{"id":"m1"}})
    assert r["status"]=="inconclusive"

def test_missing_verdict_not_tested():
    r=build_counterfactual({}, {"verdict":"violation"})
    assert r["status"]=="not_tested"

def test_unexpected_improvement_not_pass():
    r=build_counterfactual({"verdict":"violation"},{"verdict":"pass"})
    assert r["status"]=="inconclusive"
