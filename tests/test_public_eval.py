from ersec_public_eval import new_scorecard, validate_scorecard, build_public_evaluation

def test_external_scorecards_start_unexecuted():
    c=new_scorecard("owasp-benchmark-python")
    assert c["status"] == "not_executed"
    assert validate_scorecard(c)["valid"]

def test_pass_requires_reproducibility_evidence():
    c=new_scorecard("juice-shop"); c["status"]="pass"
    assert not validate_scorecard(c)["valid"]

def test_public_eval_does_not_fabricate_external_results():
    r=build_public_evaluation({"status":"PASS","metrics":{"precision":1,"recall":1,"f1":1,"false_positive_rate":0},"reproducibility_digest":"x"})
    assert r["status"] == "INCOMPLETE"
    assert all(c["status"]=="not_executed" for c in r["cards"][1:])
