import sys
sys.path.insert(0,'.')
from ersec_concurrent_assurance import compile_plan,evaluate

def test_compile_supported_race_families():
    r=compile_plan({"properties":[{"id":"p1","kind":"toctou","operation":"approve"},{"id":"p2","kind":"double-submit","operation":"charge"}]})
    assert r["version"]=="29.1.0" and r["scenario_count"]==2
    assert r["governance"]["network_contact"] is False

def test_missing_evidence_not_pass():
    p=compile_plan({"properties":[{"id":"p1","kind":"quota-race","operation":"reserve"}]})
    r=evaluate(p,{"observations":[]})
    assert r["status"]=="not_tested"
    assert r["counts"]["not_tested"]==1

def test_explicit_violation():
    p=compile_plan({"properties":[{"id":"p1","kind":"idempotency-race","operation":"create"}]})
    r=evaluate(p,{"observations":[{"scenario_id":"p1","observed_events":["a","b"],"observed_outcome":"duplicate","verdict":"violation"}]})
    assert r["status"]=="violation"

def test_credential_rejection():
    try: compile_plan({"properties":[{"id":"p","kind":"toctou","operation":"x","token":"secret"}]})
    except ValueError: return
    assert False
