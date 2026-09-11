from ersec.ersec_security_boundary_lab import compile_lab, evaluate

def spec():
    return {"identities":{"a":{"role":"user","tenant":"a","credential_ref":"vault://a"},"b":{"role":"user","tenant":"b","credential_ref":"vault://b"}},"resources":[{"id":"order","methods":["GET"]}],"properties":[{"id":"cross-tenant","subject":"b","resource":"order","expected_status":[403,404],"forbidden":["amount"]}]}

def test_compile_safe_matrix():
    p=compile_lab(spec()); assert p["statistics"]["cases"] == 1; assert p["governance"]["offline"]

def test_missing_is_not_pass_and_violation_is_confirmable():
    p=compile_lab(spec()); assert evaluate(p,{})["status"] == "inconclusive"
    c=p["cases"][0]; r=evaluate(p,{"observations":[{"case_id":c["case_id"],"verdict":"observed","status":200,"observed_fields":["amount"],"evidence_ref":"ev1"}]})
    assert r["status"] == "fail" and r["counts"]["violation"] == 1

def test_credential_values_rejected():
    try: compile_lab({"identities":{"x":{"bearer_token":"secret"}}})
    except ValueError: return
    assert False
