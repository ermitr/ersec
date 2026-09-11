import json
from ersec_stateful_links import learn, evaluate


def test_openapi_link_and_location_learning():
    inv = {"operations": [
        {"operation_id": "createOrder", "links": [{"operationId": "getOrder", "parameters": {"id": "$response.body#/id"}}], "location": "/orders/{id}"},
        {"operation_id": "getOrder"},
    ]}
    plan = learn(inv)
    assert plan["version"] == "29.1.0"
    assert plan["counts"]["relationships"] >= 2
    assert any(x["kind"] == "openapi_link" for x in plan["relationships"])


def test_missing_evidence_is_not_pass():
    plan = learn({"operations": [{"operation_id": "create"}, {"operation_id": "get"}]})
    assert plan["obligations"] == []

    inv = {"operations": [{"operation_id": "create", "links": [{"operationId": "get"}]}, {"operation_id": "get"}]}
    plan = learn(inv)
    result = evaluate(plan, {"relationships": {}})
    assert result["status"] == "inconclusive"
    assert result["counts"]["not_tested"] == len(plan["obligations"])


def test_violation_and_revision_evidence():
    inv = {"operations": [{"operation_id": "create", "links": [{"operationId": "get"}]}, {"operation_id": "get"}]}
    plan = learn(inv)
    oid = plan["obligations"][0]["id"]
    result = evaluate(plan, {"relationships": {oid: {"verdict": "violation", "trace_id": "t1", "service_revision": "r1"}}})
    assert result["status"] == "violation"
    assert result["counts"]["violation"] == 1
