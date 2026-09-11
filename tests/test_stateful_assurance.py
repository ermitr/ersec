import json
from pathlib import Path
from ersec_stateful_assurance import compile_plan, evaluate

def test_compile_and_digest():
    doc={"version":"29.1.0","workflows":[{"id":"w","states":["a","b"],"transitions":[{"from":"a","to":"b","action":"go"}],"invariants":[{"id":"i","statement":"must hold"}]}]}
    a=compile_plan(doc); b=compile_plan(doc)
    assert a["version"] == "29.1.0" and a["digest"] == b["digest"]
    assert len(a["workflows"][0]["scenarios"]) == 7

def test_missing_evidence_is_not_tested():
    plan=compile_plan({"workflows":[{"id":"w","states":["a"],"transitions":[],"invariants":[{"id":"i","statement":"x"}]}]})
    result=evaluate(plan,{"scenarios":{}})
    assert result["counts"]["not_tested"] == 7
    assert result["status"] == "inconclusive"

def test_explicit_violation():
    plan=compile_plan({"workflows":[{"id":"w","states":["a"],"transitions":[],"invariants":[]}]})
    result=evaluate(plan,{"scenarios":{"w:baseline":{"verdict":"violation","oracle_available":True}}})
    assert result["status"] == "violation"

def test_credentials_rejected():
    try:
        compile_plan({"workflows":[],"token":"secret"})
    except ValueError as e:
        assert "credential" in str(e)
    else:
        raise AssertionError("credential material accepted")
