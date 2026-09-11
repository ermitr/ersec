import json
from ersec.ersec_observer_adapters import adapt_otel, adapt_opa, adapt_gateway, merge_observers, correlate_trace
from ersec.ersec_provenance import build, verify

def test_observer_normalization_and_trace_binding():
    o=adapt_otel([{"traceId":"t1","spanId":"s1","serviceVersion":"r1","attributes":{"http.route":"/orders","http.response.status_code":403,"decision":"deny"}}])
    p=adapt_opa([{"trace_id":"t1","service_revision":"r1","decision":"deny","decision_id":"d1"}])
    g=adapt_gateway([{"trace_id":"t1","service_revision":"r1","decision":"deny","decision_id":"g1"}])
    m=merge_observers(o,p,g)
    assert m["count"]==3
    r=correlate_trace(m["observations"], expected_revision="r1")
    assert r["status"]=="violation"
    bad=correlate_trace(m["observations"], expected_revision="r2")
    assert bad["status"]=="inconclusive"
    assert len(bad["rejected"])==3

def test_observer_conflict_is_inconclusive():
    m=merge_observers(adapt_opa([{"trace_id":"t2","service_revision":"r1","decision":"allow"}]), adapt_gateway([{"trace_id":"t2","service_revision":"r1","decision":"deny"}]))
    r=correlate_trace(m["observations"], expected_revision="r1")
    assert r["status"]=="inconclusive"
    assert r["traces"][0]["verdict"]=="inconclusive"

def test_provenance_digest_integrity_and_unsigned_boundary():
    evidence={"release_id":"r29","certificate_digest":"abc","artifact_refs":[{"artifact":"bundle","digest":"123"}],"certificate":{}}
    a=build(evidence)
    assert a["version"]=="29.1.1" and a["signed"] is False
    assert verify(a)["valid"] is True
    a["statement"]["predicate"]["commit"]="tampered"
    assert verify(a)["valid"] is False
