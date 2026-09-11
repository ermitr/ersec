import json
from ersec_hybrid_oracle import evaluate_hybrid, correlate_runtime_controls

def test_conflict_is_inconclusive():
    r=evaluate_hybrid({"verdict":"pass"}, [{"source":"opa","verdict":"violation"}])
    assert r["verdict"]=="inconclusive" and r["observer_conflict"]

def test_authoritative_violation_dominates():
    r=evaluate_hybrid({"verdict":"pass"}, [{"source":"db","verdict":"violation"}, {"source":"audit","verdict":"violation"}])
    assert r["verdict"]=="violation"

def test_agreement_passes():
    r=evaluate_hybrid({"verdict":"pass"}, [{"source":"db","verdict":"pass"}])
    assert r["verdict"]=="pass"

def test_runtime_states():
    m={"controls":[{"id":"c1","decision":"deny","service":"api","service_revision":"r1"},{"id":"c2","decision":"allow","service":"api"},{"id":"c3","decision":"deny","service":"api"}]}
    t=[{"control_id":"c1","decision":"deny","service":"api","service_revision":"r1","authoritative":True,"enforced":True},{"control_id":"c2","decision":"allow","service":"api","configured":True}]
    r=correlate_runtime_controls(m,t)
    assert r["counts"]["observed_enforced"]==1
    assert r["counts"]["configured_only"]==1
    assert r["counts"]["insufficient_telemetry"]==1
